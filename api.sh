#!/bin/sh
{

read _ QUERY _ && QUERY="${QUERY#?}"
printf '%s\n\n' 'HTTP/1.1 200 OK'

case "$QUERY" in
        action=startssh)
		/etc/init.d/dropbear restart >/dev/null
		/root/worker.sh json_emit "$?" "$QUERY"
        ;;
        action=sysinfo)
                uname -a && uptime && free	# TODO: json
                ps | while read -r LINE; do case "$LINE" in *']') ;; *) printf '%s\n' "$LINE" ;; esac; done
        ;;
        action=resetbrowser|action=reboot)
                /root/worker.sh "$QUERY" >/dev/null 2>&1 & disown
		/root/worker.sh json_emit "$?" "$QUERY"
        ;;
        language=*|screensize=*|screenshot*|update|action=update|useragent=*|action=poweroff|action=startvnc|action=report)
                /root/worker.sh "$QUERY"
		case "$QUERY" in action=report|action=startvnc) ;; *) /root/worker.sh json_emit "$?" "$QUERY" ;; esac
        ;;
        loadurl=*)
                pidof firefox >/dev/null || /root/worker.sh 'resetbrowser' >/dev/null 2>&1 & disown
                /root/worker.sh "$QUERY"
		/root/worker.sh json_emit "$?" "$QUERY"
        ;;
        *)
                /root/worker.sh 'showusage' "$QUERY"
        ;;
esac

}
