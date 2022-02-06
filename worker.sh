#!/bin/sh
{

INPUT="$1" && ACTION="$INPUT"
ARG="$2"
OPTION="$3"

case "$ACTION" in
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
read -r RESOLUTION 2>/dev/null </tmp/RESOLUTION || RESOLUTION=1280x720

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
	printf '%s\r\n'   "Connection: close"
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

	[ "$value" = default ] || {
		# add out changed line:
		case "$value" in 'true'|'false'|'null'|[0-9]|'') quote= ;; esac
		printf '%s\n' "user_pref(\"$key\", ${quote}${value:-null}${quote});" >>"$file.tmp"
	}

	mv "$file.tmp" "$file"
}

useragent_set()
{
	printf '%s\n' "$1" >/tmp/UA_USERWISH
}

start_framebuffer()
{
	pidof Xvfb >/dev/null || {
		nohup Xvfb $DISPLAY -screen 0 ${RESOLUTION}x24+32 &

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
        local j=20		# consecutive measurepoints without traffic = 2 sec
        local i=150		# 150 x 0.1 sec = 10 sec max runtime
        local dev line old=
        local bytes_dn bytes_dn_old diff_dn sum_dn
        local bytes_up bytes_up_old diff_up sum_up
        local up rest t0 t1 time time_ready list=

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

                case "$j-$diff_dn-$diff_up" in
                        0-0-0) break ;;
                        *-0-0) j=$(( j - 1 )) ;;
                            *) time_ready="$time" ;;
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

	xdotool key ctrl+l              # jump to url-bar

	printf '%s' ''   | xclip -selection 'clipboard'		# clear
	xdotool key ctrl+c
	clipboard="$( xclip -out -selection 'clipboard' )"

	xdotool key Escape
	xdotool key Tab

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

	printf '%s' "$url " | xclip -selection 'clipboard'	# append a space

	xdotool key ctrl+v sleep 0.1		# paste clipboard
}

replace()
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

case "$ACTION" in
	json_emit)
		case "$ARG" in
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
	startvnc)
		if pidof x11vnc >/dev/null; then
			json_emit 'status' 'success' 'x11vnc already running'
		else
			start_framebuffer

			if x11vnc -display :1 -cursor most -bg -nopw -xkb 2>/dev/null >/dev/null; then
				json_emit 'status' 'success' 'x11vnc started'
			else
				json_emit 'status' 'error' "x11vnc did not started RC:$?"
			fi
		fi
	;;
	update)
		BASE="${ARG:-https://raw.githubusercontent.com/bittorf/simple-real-browser-automation/main}"

		RC=0
		replace '/etc/local.d/api.sh' "$BASE/api.sh"    || RC=1
		replace '/root/worker.sh'     "$BASE/worker.sh" || RC=2
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
                        *)
				if scrot --silent --overwrite /tmp/screen.jpg --quality 25; then
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

		# TODO: mimeheader and filename
		# jq -r .screenshot | base64 -d

		if test -s /tmp/NETWORK_ACTION; then
			cat >/tmp/REPORT <<EOF
{
  "status": "success",
  "time_unix": $( cat /tmp/URL_START ),
  "time_date": "$DATE $( tail -n1 /etc/localtime )",
  "url_userinput": "$( cat /tmp/URL )",
  "url_effective": "$( cat /tmp/URL_EFFECTIVE )",
  "http_accept_language": "$( cat /tmp/ACCEPT_LANG )",
  "user_agent": "$( cat /tmp/UA )",
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
  "browser_version": "$( cat /tmp/BROWSER )",
  "resolution": "$RESOLUTION",
  "screenshot_size": ${SIZE:-null},
  "screenshot_format": ${FORMAT:+\"}${FORMAT:-null}${FORMAT:+\"},
  "screenshot_base64": ${BASE64:+\"}${BASE64:-null}${BASE64:+\"},
  "script": "https://github.com/bittorf/simple-real-browser-automation"
}
EOF
			printf '%s\r\n'   "Connection: close"
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

		X=${RESOLUTION%x*}	# e.g. 800x600 => 800
		Y=${RESOLUTION#*x}	#              => 600
                ID="$( xdotool search --classname Navigator )" || resetbrowser
                URL="$( url_decode "$ARG" )"
                echo "$URL" >/tmp/URL

		PUBIP="$( curl --silent ifconfig.me )"		# TODO: use same proxy like browser
		COUNTRY="$( curl "http://ip-api.com/line/$PUBIP" | head -n2 | tail -n1 )"
		echo "$PUBIP"   >/tmp/PUBIP
		echo "$COUNTRY" >/tmp/COUNTRY

		# resize max to fit screen:
		while ! test "$GEOMETRY" = "$RESOLUTION"; do {
			for GEOMETRY in $( xdotool getwindowgeometry "$ID" ); do :; done
			xdotool windowsize "$ID" "$X" "$Y"
		} done

		type_url_into_bar "$URL"

		press_enter_and_measure_time_till_traffic_relaxes

		# try up to 2 times:
		get_url >/tmp/URL_EFFECTIVE || \
		get_url >/tmp/URL_EFFECTIVE
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

    "see": "https://github.com/bittorf/simple-real-browser-automation"
  }
}
EOF
	;;
esac

}
