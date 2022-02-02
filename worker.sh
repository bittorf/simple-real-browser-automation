#!/bin/sh

ACTION="$1"
ARG="$2"

export DISPLAY=:1
read -r RESOLUTION 2>/dev/null </tmp/RESOLUTION || RESOLUTION=1280x720

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

resetbrowser()
{
	local pid=

        sysctl -qw vm.panic_on_oom=2
        sysctl -qw kernel.panic_on_oops=1
        sysctl -qw kernel.panic=10
        sysctl -qw vm.min_free_kbytes=4096

	browser_stop

        pidof Xvfb >/dev/null || nohup Xvfb $DISPLAY -screen 0 ${RESOLUTION}x24+32 &

        firefox --version >/tmp/BROWSER || return 1

        nohup firefox >>/tmp/debug-firefox.1 2>>/tmp/debug-firefox.2 &

	# wait till really ready:
        while ! ID="$( xdotool search --classname Navigator )"; do sleep 1; done
	sleep 1

	true >/tmp/UA
	true >/tmp/ACCEPT_LANG
	while ! test -s /tmp/UA; do {
		pid_exists "$pid" || {
			nc -l -p 8080 -e $0 detect_headers &
			pid=$!
		}

		type_url_into_bar 'http://127.0.0.1:8080'
		xdotool key Return
	} done

	pid_exists "$pid" && kill "$pid"
}

press_enter_and_measure_time_till_network_relax_max10sec()
{
        local i j dev line old=
        local bytes_dn bytes_dn_old diff_dn sum_dn
        local bytes_up bytes_up_old diff_up sum_up
        local up rest t0 t1 time time_ready list=

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

        j=8     # consecutive measurepoints without traffic
        i=100   # 100 x 0.1 sec = 10 sec maxtime

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
        xdotool key ctrl+l              # jump to url-bar
        xdotool key ctrl+c
        OUT="$( xclip -out -selection 'clipboard' )"
        xdotool key Escape
        xdotool key Tab

        printf '%s\n' "$OUT"
}

type_url_into_bar()
{
	local url="$1"

	xdotool key ctrl+t			# new tab
	xdotool key ctrl+Page_Up		# go back to old tab
	xdotool key ctrl+w			# close (old) tab
	xdotool key ctrl+l			# jump to url-bar
	xdotool key BackSpace sleep 0.6		# make sure we start empty
	xdotool type --delay 300 "$url "	# append a space
}

case "$ACTION" in
	detect_headers)
		printf '%s\n\n' 'HTTP/1.1 200 OK'
		printf '%s' 'OK'

		I=2
		while read -r LINE; do {
			case "$LINE" in
				'User-Agent:'*)
					set -- $LINE
					shift

					printf '%s\n' "$*" >/tmp/UA
					I=$(( I - 1 ))
					test $I -eq 0 && exit
				;;
				'Accept-Language:'*)
					set -- $LINE
					shift

					printf '%s\n' "$*" >/tmp/ACCEPT_LANG
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

                case "$ARG" in
                        png)
				if scrot --silent --overwrite /tmp/screen.png; then
					echo 'png'                 >/tmp/screen.format
					wc -c </tmp/screen.png     >/tmp/screen.size
					base64 -w0 /tmp/screen.png >/tmp/screen.base64 && echo >>/tmp/screen.base64
				else
					echo "scrot-RC:$?"
				fi
			;;
                        *)
				if scrot --silent --overwrite /tmp/screen.jpg --quality 25; then
					echo 'jpg'                 >/tmp/screen.format
					wc -c </tmp/screen.jpg     >/tmp/screen.size
					base64 -w0 /tmp/screen.jpg >/tmp/screen.base64 && echo >>/tmp/screen.base64
				else
					echo "scrot-RC:$?"
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

		cat <<EOF
{
  "time_unix": $( cat /tmp/URL_START ),
  "time_date": "$DATE timezone $( tail -n1 /etc/localtime )",
  "url_userinput": "$( cat /tmp/URL )",
  "url_effective": "$( get_url )",
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
  "screenshot": ${BASE64:+\"}${BASE64:-null}${BASE64:+\"}
}
EOF
        ;;
        reboot)
                sync && reboot -f
        ;;
        safe_poweroff)
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

                url_decode() {
                        local url="$1"
                        local hex_encoded

                        tohex() { sed -E -e 's/\+/ /g' -e 's/%([0-9a-fA-F]{2})/\\x\1/g'; }
                        hex_encoded="$( printf '%s\n' "$url" | tohex )"

                        printf '%b\n' "$hex_encoded"
                }

		X=${RESOLUTION%.*}
		Y=${RESOLUTION#*.}
                ID="$( xdotool search --classname Navigator )" || resetbrowser
                URL="$( url_decode "$ARG" )"
                echo "$URL" >/tmp/URL

		PUBIP="$( curl --silent ifconfig.me )"		# TODO: use same proxy like browser
		COUNTRY="$( curl "http://ip-api.com/line/$PUBIP" | head -n2 | tail -n1 )"
		echo "$PUBIP"   >/tmp/PUBIP
		echo "$COUNTRY" >/tmp/COUNTRY

                xdotool windowsize "$ID" "$X" "$Y"	# resize to fit screen
		type_url_into_bar "$URL"

                press_enter_and_measure_time_till_network_relax_max10sec
        ;;
        *)
                printf '%s\n' "ERROR - detected: ${ARG:-<empty>} | KEY=$ACTION VALUE=$ARG"
                printf '%s\n' ''
                printf '%s\n' 'Usage: curl http://server/key=value'
                printf '%s\n' ' e.g.: action=poweroff|reboot|startssh|startvnc|sysinfo|resetbrowser'
                printf '%s\n' ''
                printf '%s\n' '       language=zh-CN'
                printf '%s\n' '       screensize=800x3000'
                printf '%s\n' '       loadurl=https://amiunique.org/fp'
                printf '%s\n' '       screenshot=png'
                printf '%s\n' '       action=report'
        ;;
esac
