#!/bin/sh
{

read -r _ QUERY _ && QUERY="${QUERY#?}"				# /foo => foo
case "$QUERY" in '?'*) QUERY="${QUERY#?}" ;; esac		# ?foo => foo
printf '%s\r\n%s\r\n' 'HTTP/1.1 200 OK' 'Connection: close'

case "$QUERY" in
	action=startssh)
		/etc/init.d/dropbear restart >/dev/null
		/root/worker.sh json_emit "$?" "$QUERY"
	;;
	action=sysinfo)
		printf '\n%s\n' '{"status": "success", "data": [' && { uname -a && uptime && free && firefox -v && echo; } | sed 's/.*/"&",/'
		ps | while read -r LINE; do case "$LINE" in *']') ;; *) printf '%s\n' "\"$LINE\"," ;; esac; done
		printf '%s\n' '0]}'
	;;
	action=resetbrowser|action=reboot)
		/root/worker.sh "$QUERY" >/dev/null 2>&1 & disown
		/root/worker.sh json_emit "$?" "$QUERY"
	;;
	loadurl=*)
		pidof firefox >/dev/null || /root/worker.sh 'resetbrowser' >/dev/null 2>&1 & disown
		/root/worker.sh "$QUERY"
		/root/worker.sh json_emit "$?" "$QUERY"
	;;
	*)
		/root/worker.sh "$QUERY"
		case "$QUERY" in action=report|action=startvnc) ;; *) /root/worker.sh json_emit "$?" "$QUERY" "$MESSAGE" ;; esac
	;;
esac

}
