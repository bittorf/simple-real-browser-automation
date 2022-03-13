#!/bin/sh
{

INPUT="$1" && ACTION="$INPUT"
ARG="$2"
OPTION="$3"

case "$ACTION" in
	include)
	;;
	action=*)
		ACTION="${ACTION#*=}"	# action=foo => foo
	;;
	*'='*)
		ARG="${ACTION#*=}"	# foo=bar => bar
		ACTION="${ACTION%%=*}"	# foo=bar => foo
	;;
esac

export HOME=/root
export DISPLAY=:1
export FALLTROUGH=222

read -r RESOLUTION 2>/dev/null </tmp/RESOLUTION || RESOLUTION=1280x720
X=${RESOLUTION%x*}	# e.g. 800x600 => 800
Y=${RESOLUTION#*x}	#              => 600

isnumber()
{
	test 2>/dev/null "${1:-a}" -eq "${1##*[!0-9-]*}"
}

json_emit()
{
	local key="$1"
	local value="$2"
	local message="$3"

	case "$message" in
		'') addbytes=9 ;;
		 *) addbytes=34 ;;
	esac

	# RFC2616 | https://stackoverflow.com/questions/5757290/http-header-line-break-style
	printf '%s\r\n'   "Content-Length: $(( ${#key} + ${#value} + ${#message} + addbytes ))"
	printf '%s\r\n\n' "Content-Type: application/json"

	# https://github.com/omniti-labs/jsend
	case "$message" in
		'') printf '%s\n' "{\"$key\": \"$value\"}" ;;
		 *) printf '%s\n' "{\"$key\": \"$value\", \"data\": {\"message\": \"$message\"}}" ;;
	esac
}

browser_stop()
{
	while pidof firefox >/dev/null; do
		xdotool key ctrl+w
		xdotool key ctrl+w
		sleep 1
		killall firefox
		sleep 1
	done
}

pid_exists()
{
	kill -0 "${1:-foo}" 2>/dev/null
}

userjs_replace_or_add()		# make sure browser does not run!
{
	local key="$1"
	local value="$2"
	local file dir line quote='"'

	file="$( find "$HOME/.mozilla/firefox" -type f -name 'prefs.js' )"
	dir="$( dirname "$file" )"
	file="$dir/user.js"

	# e.g. user_pref("browser.sessionstore.resume_from_crash", false);
	# filter out our line:
	grep -v "(\"$key\"," "$file" >"$file.tmp"

	if [ "$value" = default ]; then
		# this is needed e.g. for 'general.useragent.override'
		grep -v "$key" "$dir/prefs.js" >"$dir/prefs.js.tmp"
		mv "$dir/prefs.js.tmp" "$dir/prefs.js"
	else
		# add out changed line:
		case "$value" in 'true'|'false'|'null'|[0-9]|'') quote= ;; esac
		printf '%s\n' "user_pref(\"$key\", ${quote}${value:-null}${quote});" >>"$file.tmp"
	fi

	mv "$file.tmp" "$file"
}

useragent_set()
{
	printf '%s\n' "$1" >/tmp/UA_USERWISH
}

start_framebuffer()
{
	pidof Xvfb >/dev/null || {
		nohup Xvfb $DISPLAY -screen 0 ${RESOLUTION}x24+32 +extension GLX +render -noreset &

		sleep 1
		while ! pidof Xvfb >/dev/null; do sleep 1; done
		true 
	}
}

resetbrowser()		# TODO: clear cache + set lang + set UA
{
	local useragent pid=

	true >/tmp/BROWSER

        sysctl -qw vm.panic_on_oom=2
        sysctl -qw kernel.panic_on_oops=1
        sysctl -qw kernel.panic=10
        sysctl -qw vm.min_free_kbytes=4096

	browser_stop
	start_framebuffer
        firefox --version >/tmp/BROWSER || return 1

	read -r useragent 2>/dev/null </tmp/UA_USERWISH && \
	userjs_replace_or_add 'general.useragent.override' "$useragent"

	userjs_replace_or_add browser.urlbar.autoFill 'false'
	userjs_replace_or_add services.sync.prefs.sync.browser.urlbar.maxRichResults 'false'
	userjs_replace_or_add browser.urlbar.maxRichResults '0'
	userjs_replace_or_add browser.newtabpage.activity-stream.feeds.topsites 'false'
	userjs_replace_or_add browser.newtabpage.activity-stream.feeds.section.highlights 'false'
	userjs_replace_or_add browser.newtabpage.activity-stream.showSearch 'false'
	userjs_replace_or_add browser.newtabpage.activity-stream.feeds.snippets 'false'
	userjs_replace_or_add webgl.force-enabled 'false'

        nohup firefox >>/tmp/debug-firefox.1 2>>/tmp/debug-firefox.2 &

	# wait till really ready:
        while ! ID="$( xdotool search --classname Navigator )"; do sleep 1; done
	sleep 1

	true >/tmp/UA			# is written from 'detect_headers'
	true >/tmp/ACCEPT_LANG
	while ! test -s /tmp/UA; do {
		if pid_exists "$pid"; then
			sleep 1
		else
			nc -l -p 8080 -e "$0" detect_headers &
			pid=$!
		fi

								# TODO: sometimes firefox says "Unable to connect", but file /tmp/UA was written
		type_url_into_bar 'http://127.0.0.1:8080'	# TODO: no search-suggestions, empty background
		xdotool key Return

		sleep 1
	} done

	pid_exists "$pid" && kill "$pid"
	true
}

url_decode() {
	local url="$1"
	local hex_encoded

	tohex() { sed -E -e 's/\+/ /g' -e 's/%([0-9a-fA-F]{2})/\\x\1/g'; }
	hex_encoded="$( printf '%s\n' "$url" | tohex )"

	printf '%b\n' "$hex_encoded"
}

press_enter_and_measure_time_till_traffic_relaxes()
{
        local dev line old=
        local bytes_dn bytes_dn_old diff_dn sum_dn
        local bytes_up bytes_up_old diff_up sum_up
        local up rest t0 t1 time time_ready i j list=

	# TODO:
	# tcpdump -i eth0 -w foo.pcap
	# tcpdump -vnr foo.pcap | sed -n 's/^.*length \([0-9]*\).*/\1/p' | awk '{s+=$1} END {print s}'

	true >/tmp/NETWORK_ACTION
	true >/tmp/DOWNLOAD_TIME_MS
	true >/tmp/DOWNLOAD_BYTES
	true >/tmp/UPLOAD_BYTES

        # e.g. default via 10.63.22.97 dev eth0 proto static metric 100
        #                                  ^^^^
        for dev in $( ip route list exact '0.0.0.0/0' ); do test "$old" = dev && break; old="$dev"; done

        byte_counter()
        {
                while read -r line; do {
                        case "$line" in
                                *"$1:"*)
                                        # shellcheck disable=SC2086
                                        set -- ${line#*:}

                                        bytes_dn="$1"	# rx column = download
                                        bytes_up="$9"	# tx column = upload
                                        return
                                ;;
                        esac
                } done </proc/net/dev
        }

        # initial values for uptime:
        read -r up rest </proc/uptime
        t0="${up%.*}${up#*.}0"

        # initial values for network:
        byte_counter "$dev"
        bytes_dn_old="$bytes_dn"       # our baseline
        bytes_up_old="$bytes_up"
        sum_dn="$bytes_dn"
        sum_up="$bytes_up"

        date +%s >/tmp/URL_START
        xdotool key Return

	j=-1		# make sure we wait for traffic
        i=250		# 250 x 0.1 sec = 25 sec max runtime

        while case "$i" in 0) false ;; esac
        do
                i=$(( i - 1 ))

                read -r up rest </proc/uptime
                t1="${up%.*}${up#*.}0"

                byte_counter "$dev"
                diff_dn=$(( bytes_dn - bytes_dn_old ))
                diff_up=$(( bytes_up - bytes_up_old ))
                bytes_dn_old="$bytes_dn"
                bytes_up_old="$bytes_up"

                time="$(( t1 - t0 ))"
                list="$list $time,$diff_dn,$diff_up"

		# wait till 'j' and up/down-traffic is 0:
                case "$j-$diff_dn-$diff_up" in
                        0-0-0) break ;;
                        *-0-0) j=$(( j - 1 )) ;;
                            *) time_ready="$time" && j=20 ;; # consecutive measurepoints without traffic = 2 sec
                esac

                sleep 0.1
        done

        echo "$list"                    >/tmp/NETWORK_ACTION
	echo "$time_ready"              >/tmp/DOWNLOAD_TIME_MS
        echo "$(( bytes_dn - sum_dn ))" >/tmp/DOWNLOAD_BYTES
        echo "$(( bytes_up - sum_up ))" >/tmp/UPLOAD_BYTES
}

get_url()
{
	local clipboard=

	xdotool key ctrl+l sleep 0.1		# jump to url-bar

	printf '%s' '' | xclip -in  -selection 'clipboard'	# clear
	xdotool key ctrl+c sleep 0.1
	clipboard="$(    xclip -out -selection 'clipboard' )"

	xdotool key Escape sleep 0.1
	xdotool key Tab				# park selection on next element

	printf '%s\n' "$clipboard"
	test -n "$clipboard"
}

type_url_into_bar()
{
	local url="$1"

	xdotool key ctrl+t			# new tab
	xdotool key ctrl+Page_Up		# go back to old tab
	xdotool key ctrl+w sleep 0.1		# close (old) tab

	xdotool key ctrl+l sleep 0.1		# jump to url-bar
	xdotool key BackSpace			# make sure we start empty

	printf '%s' "$url " | xclip -in -selection 'clipboard'	# URL+space into clipboard

	xdotool key ctrl+v sleep 0.1		# paste clipboard
	xdotool key Right			# force unselect text
}

script_safe_replace()
{
	local dest="$1"
	local url="$2"

	wget -qO /tmp/new.sh "$url"	|| return 1
	test -s  /tmp/new.sh		|| return 1
	sh -n    /tmp/new.sh		|| return 1
	cp       /tmp/new.sh "$dest"	|| return 1
	chmod +x             "$dest"	|| return 1
	rm -f    /tmp/new.sh
}

mouse_set_defaultpos()
{
	xdotool mousemove 30 30
}

clearcache()
{
	xdotool key ctrl+shift+Delete	# open GUI for cache
	xdotool key shift+e		# select 'Everything'

	xdotool mousemove "$(( X / 2 ))" '345'

	xdotool key Tab
	xdotool key Tab
	xdotool key Tab
	xdotool key Tab
	xdotool key Tab
	xdotool key Tab
	xdotool key Tab
	xdotool key Tab
	xdotool key Tab
	sleep 5
	xdotool key Return

	mouse_set_defaultpos
}
					# TODO: avoid search-box resizing content (performance issue)
check_valid_certificate()		# FIXME: detect no-connect, e.g. nonexisting page: https://bittorf.jp
{
	local pattern1=' Potential Security '	# e.g.: Potential Security Risk Ahead
	local pattern2=' potential security '	#   or: Potential Security Issue | potential security
	local clipboard

	case "$( cat /tmp/URL_EFFECTIVE )" in
		https://*) ;;
		*) echo 'null' && return ;;
	esac

	xdotool key ctrl+f						# open search-field
	printf '%s' "$pattern1" | xclip -in -selection 'clipboard'	# fill clipboard
	xdotool key ctrl+v sleep 1					# paste clipboard
	xdotool key Return						# ...and search! (if found, text is highlighted)
	xdotool key Escape sleep 1					# remove search-field
	xdotool key Escape sleep 1					# remove search-field (2nd try)

	printf '%s' '' | xclip -in  -selection 'clipboard'		# clear clipboard
	xdotool key ctrl+c sleep 1					# copy (maybe) highlighted text

	clipboard="$( xclip -out -selection 'clipboard' )"

	case "$clipboard" in
		"$pattern1") echo 'false' ;;
		"$pattern2") echo 'false' ;;
		*) echo 'true' ;;
	esac
}

is_ip4()
{
	local ip="$1"
	local oldifs="$IFS"; IFS='.'

	set -f
	# shellcheck disable=SC2086
	set +f -- $ip
	IFS="$oldifs"

	isnumber "$1${2:-x}${3:-x}${4:-x}" || return 1

	test "$1" -eq 0 -o "$1" -gt 254 \
			-o "$2" -gt 255 \
			-o "$3" -gt 255 \
			-o "$4" -lt 0   \
			-o "$4" -gt 254 \
			-o -n "$5" && \
				return 2
	true
}

check_command()
{
	local list="$*"
	local app uptodate=

	for app in $list; do {
		command -v "$app" >/dev/null || {
			case "$app" in
				mesa-dri-gallium)
					test -f /usr/lib/xorg/modules/dri/swrast_dri.so && continue
				;;
				openssh-client)
					ssh -V 2>&1 | grep -q ^'OpenSSH' && continue
				;;
				py-pip)
					command -v 'pip3' >/dev/null && continue
				;;
			esac

			apk add "$app" && {
				test -z "$uptodate" && apk update && uptodate='true'

				case "$app" in
					openssh-client)
						{
							echo "HostkeyAlgorithms +ssh-rsa"
							echo "HostkeyAlgorithms +ssh-dss"
							echo "StrictHostKeyChecking=accept-new"
							echo "UserKnownHostsFile=/dev/null"
							echo "PubkeyAcceptedKeyTypes +ssh-rsa"
							echo "ServerAliveInterval 60"
						} >>/root/.ssh/config
					;;
				esac
			}
		}
	} done
}

case "$ACTION" in
	include)
	;;
	json_emit)
		case "$ARG" in
			"$FALLTROUGH")
				exit 0
			;;
			0)
				INPUT='status'
				ARG='success'
			;;
			[1-9]|[1-9][0-9]|1[0-9][0-9])	# a returncode/number > 0
				INPUT='status'
				ARG='error'
			;;
		esac

		json_emit "$INPUT" "$ARG" "$OPTION"
	;;
	dnsserver)
		is_ip4 "$ARG" && {
			sed -i "s/^nameserver.*/nameserver $ARG/" /etc/resolv.conf
		}
	;;
	sshprivkey)
		echo "$ARG" | base64 -d >/tmp/SSHPRIVKEY && {
			cp /tmp/SSHPRIVKEY /root/.ssh/id_rsa && chmod 0600 /root/.ssh/id_rsa
			rm -f /tmp/SSHPRIVKEY
		}
	;;
	sshuttle)
		case "$ARG" in
			stop)
				killall sshuttle
			;;
			*)
				check_command 'iptables' 'openssh-client' 'py-pip' 'sshuttle' || pip install sshuttle

				# ARG = e.g. user@any.remote.box:222
				#                 ^^^^^^^^^^^^^^
				HOST="$( echo "$ARG" | cut -d'@' -f2 | cut -d':' -f1 )"
				for SERVERIP in $( getent hosts "$HOST" ); do break; done

				sshuttle --exclude="$SERVERIP/32" --dns --remote="$ARG" '0.0.0.0/0' --disable-ipv6 --daemon
			;;
		esac
	;;
	startwebgl)
		test -f /usr/lib/xorg/modules/dri/swrast_dri.so || apk add mesa-dri-gallium
	;;
	startvnc)
		if pidof x11vnc >/dev/null; then
			json_emit 'status' 'success' 'x11vnc already running'
		else
			start_framebuffer
			check_command 'x11vnc'

			if x11vnc -display :1 -cursor most -bg -nopw -xkb 2>/dev/null >/dev/null; then
				json_emit 'status' 'success' 'x11vnc started'
			else
				json_emit 'status' 'error' "x11vnc did not started RC:$?"
			fi
		fi
	;;
	clearcache)
		clearcache
	;;
	update)
		# fix missing apk cache once:
		mkdir /run/apkcache 2>/dev/null && rm -fR /var/cache/apk && ln -s /run/apkcache /var/cache/apk

		BASE="${ARG:-https://raw.githubusercontent.com/bittorf/simple-real-browser-automation/main}"

		RC=0
		script_safe_replace '/etc/local.d/api.sh' "$BASE/api.sh"    || RC=1
		script_safe_replace '/root/worker.sh'     "$BASE/worker.sh" || RC=2
		exit $RC
	;;
	useragent)
		PLAIN="$( url_decode "$ARG" )"
		useragent_set "$PLAIN"
	;;
	detect_headers)
		printf '%s\r\n'   'HTTP/1.1 200 OK'
		printf '%s\r\n'   'Connection: close'
		printf '%s\r\n'   'Content-Length: 3'
		printf '%s\r\n\n' 'Content-Type: text/plain'
		printf '%s\n' 'OK'

		I=2
		while read -r LINE; do {
			case "$LINE" in
				'User-Agent:'*)
					# shellcheck disable=SC2086
					set -- $LINE
					shift

					printf '%s\n' "$*" | tr -d '\r' >/tmp/UA
					I=$(( I - 1 ))
					test $I -eq 0 && exit
				;;
				'Accept-Language:'*)
					# shellcheck disable=SC2086
					set -- $LINE
					shift

					printf '%s\n' "$*" | tr -d '\r' >/tmp/ACCEPT_LANG
					I=$(( I - 1 ))
					test $I -eq 0 && exit
				;;
			esac
		} done
	;;
        screenshot)
                # GTmetrix.com
                # call main with args + TODO: count bytes + streams + time + w3c validator? + effective URL + compression?

		true >/tmp/screen.png
		true >/tmp/screen.jpg
		true >/tmp/screen.base64
		true >/tmp/screen.size
		true >/tmp/screen.format

		test -s /tmp/NETWORK_ACTION || exit 1

                case "$ARG" in
                        png)
				if scrot --silent --overwrite /tmp/screen.png; then
					echo 'png'                 >/tmp/screen.format
					wc -c </tmp/screen.png     >/tmp/screen.size
					base64 -w0 /tmp/screen.png >/tmp/screen.base64 && echo >>/tmp/screen.base64
				else
					exit $?
				fi
			;;
                        jpg|jpgthumb|*)
				case "$ARG" in
					jpgthumb) SCROT_OPTS='--quality 10 --thumb 25' ;;
					       *) SCROT_OPTS='--quality 30' ;;
				esac

				# shellcheck disable=SC2086
				if scrot --silent --overwrite $SCROT_OPTS '/tmp/%%.jpg'; then
					if mv '/tmp/%-thumb.jpg' /tmp/screen.jpg; then
						rm -f '/tmp/%.jpg'
					else
						mv '/tmp/%.jpg' /tmp/screen.jpg
					fi

					echo 'jpg'                 >/tmp/screen.format
					wc -c </tmp/screen.jpg     >/tmp/screen.size
					base64 -w0 /tmp/screen.jpg >/tmp/screen.base64 && echo >>/tmp/screen.base64
				else
					exit $?
				fi
			;;
                esac
        ;;
        report)
		DATE="$( read -r UNIX </tmp/URL_START && LC_ALL=C date "-d@$UNIX" )"

		read -r SIZE    </tmp/screen.size   || SIZE=
		read -r BASE64  </tmp/screen.base64 || BASE64=
		read -r FORMAT  </tmp/screen.format || FORMAT=
		read -r PUBIP   </tmp/PUBIP         || PUBIP=
		read -r COUNTRY </tmp/COUNTRY       || COUNTRY=
		read -r TIME_MS </tmp/DOWNLOAD_TIME_MS

		case "$FORMAT" in
			png) MIME='image/png' ;;
			jpg) MIME='image/jpeg' ;;
			*) MIME= ;;
		esac

		if test -s /tmp/NETWORK_ACTION; then
			cat >/tmp/REPORT <<EOF
{
  "status": "success",
  "time_unix": $( cat /tmp/URL_START ),
  "time_date": "$DATE $( tail -n1 /etc/localtime )",
  "url_userinput": "$( cat /tmp/URL )",
  "url_effective": "$( cat /tmp/URL_EFFECTIVE )",
  "https_valid_certificate": $( cat /tmp/CERT ),
  "http_accept_language": "$( cat /tmp/ACCEPT_LANG )",
  "user_agent": "$( cat /tmp/UA )",
  "browser_version": "$( cat /tmp/BROWSER )",
  "download_time_ms": $TIME_MS,
  "download_size_bytes": $( cat /tmp/DOWNLOAD_BYTES ),
  "network_public_ip": ${PUBIP:+\"}${PUBIP:-null}${PUBIP:+\"},
  "network_country": ${COUNTRY:+\"}${COUNTRY:-null}${COUNTRY:+\"},
  "network_action": [
$(
  read -r DATA </tmp/NETWORK_ACTION
  APPEND=','
  for TRIPLE in $DATA; do
    case "$TRIPLE" in "$TIME_MS,"*) APPEND='],' ;; esac
    # e.g.: 20,234,567
    D1=${TRIPLE%%,*}
    D2=${TRIPLE%,*} && D2=${D2##*,}
    D3=${TRIPLE##*,}
    printf '    {"tims_ms": %4i, "bytes_down": %6i, "bytes_up": %6i}%s\n' "$D1" "$D2" "$D3" "$APPEND"
    case "$TRIPLE" in "$TIME_MS,"*) break ;; esac
  done
 )
  "resolution": "$RESOLUTION",
  "screenshot_filesize": ${SIZE:-null},
  "screenshot_mime": ${MIME:+\"}${MIME:-null}${MIME:+\"},
  "screenshot_format": ${FORMAT:+\"}${FORMAT:-null}${FORMAT:+\"},
  "screenshot_base64": ${BASE64:+\"}${BASE64:-null}${BASE64:+\"},
  "script": "https://github.com/bittorf/simple-real-browser-automation"
}
EOF
			printf '%s\r\n'   "Content-Length: $( wc -c </tmp/REPORT )"
			printf '%s\r\n\n' "Content-Type: application/json"
			cat /tmp/REPORT
		else
			json_emit 'status' 'error' 'no URL loaded yet?'
		fi
        ;;
        reboot)
                sync && reboot -f
        ;;
        poweroff)
		browser_stop
                poweroff
        ;;
        resetbrowser)
                resetbrowser
        ;;
        language)
                # about:config => intl.accept_languages
        ;;
        screensize)
                printf '%s\n' "$ARG" >/tmp/RESOLUTION
		browser_stop
		killall Xvfb
        ;;
        geturl)
                geturl
        ;;
        loadurl)
		true >/tmp/screen.png
		true >/tmp/screen.jpg
		true >/tmp/screen.base64
		true >/tmp/screen.size
		true >/tmp/screen.format

                ID="$( xdotool search --classname Navigator )" || resetbrowser
                URL="$( url_decode "$ARG" )"
                echo "$URL" >/tmp/URL

		PUBIP="$( wget -qO - 'http://ifconfig.me' )"		# TODO: use same proxy like browser
		COUNTRY="$( wget -qO - "http://ip-api.com/line/$PUBIP" | head -n2 | tail -n1 )"
		echo "$PUBIP"   >/tmp/PUBIP
		echo "$COUNTRY" >/tmp/COUNTRY

		# resize max to fit screen:
		while ! test "$GEOMETRY" = "$RESOLUTION"; do {
			for GEOMETRY in $( xdotool getwindowgeometry "$ID" ); do :; done
			xdotool windowsize "$ID" "$X" "$Y"
		} done

		mouse_set_defaultpos
		type_url_into_bar "$URL"

		press_enter_and_measure_time_till_traffic_relaxes

		# try up to 2 times:
		get_url >/tmp/URL_EFFECTIVE || \
		get_url >/tmp/URL_EFFECTIVE

		check_valid_certificate >/tmp/CERT
        ;;
        *)
		cat <<EOF

{
  "status": "fail",
  "data": {
    "input         ": "${INPUT:-<empty>}",
    "detected_key  ": "${ACTION:-<empty>}",
    "detected_value": "${ARG:-<empty>}",

    "usage   ":       "curl http://server/key=value",

    "example1":       "               .../loadurl=google.de",
    "example2":       "               .../screenshot=jpg",
    "example3":       "               .../action=report",

    "example4":       "               .../language=zh-CN",
    "example5":       "               .../useragent=Mozilla/5.0+(linux)",
    "example6":       "               .../screensize=800x3000",
    "example7":       "               .../action=resetbrowser",

    "example8":       "               .../action=update",
    "example9":       "               .../action=poweroff",
    "exampleA":       "               .../action=reboot",
    "exampleB":       "               .../action=startssh",
    "exampleC":       "               .../action=startvnc",
    "exampleD":       "               .../action=sysinfo",
    "exampleE":       "               .../dnsserver=1.2.3.4",
    "exampleF":       "               .../sshuttle=user@host.foo",
    "exampleG":       "               .../sshuttle=stop",
    "exampleH":       "               .../sshprivkey=base64-encoded-key",
    "exampleI":       "               .../action=startwebgl",

    "see": "https://github.com/bittorf/simple-real-browser-automation"
  }
}
EOF
		exit "$FALLTROUGH"
	;;
esac

}
