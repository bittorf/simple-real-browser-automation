#!/bin/sh

read _ QUERY _ && QUERY="${QUERY#?}"
printf '%s\n\n' 'HTTP/1.1 200 OK'

case "$QUERY" in
        action=poweroff)
                /root/worker.sh safe_poweroff
        ;;
        action=reboot)
                /root/worker.sh reboot >/dev/null 2>&1 & disown
        ;;
        action=startssh)
                /etc/init.d/dropbear restart
        ;;
        action=startvnc)
                pidof x11vnc >/dev/null || {
			x11vnc -display :1 -cursor most -bg -nopw -xkb 2>/dev/null >/dev/null || echo ERR:$?
		}
        ;;
        action=sysinfo)
                uname -a && uptime && free
                ps | while read -r LINE; do case "$LINE" in *']') ;; *) printf '%s\n' "$LINE" ;; esac; done
        ;;
        action=report)
                /root/worker.sh "${QUERY#*=}"
        ;;
        action=resetbrowser)
                /root/worker.sh resetbrowser >/dev/null 2>&1 & disown
        ;;
        language=*|screensize=*|screenshot*)
                /root/worker.sh "${QUERY%%=*}" "${QUERY#*=}"
        ;;
        loadurl=*)
                pidof firefox >/dev/null || /root/worker.sh resetbrowser >/dev/null 2>&1 & disown
                /root/worker.sh "${QUERY%%=*}" "${QUERY#*=}"
        ;;
        *)
                /root/worker.sh showusage "$QUERY"
        ;;
esac
