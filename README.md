### Setup

```
URL='https://dl-cdn.alpinelinux.org/alpine/v3.15/releases/x86_64/alpine-virt-3.15.0-x86_64.iso'		# ..
URL='https://dl-cdn.alpinelinux.org/alpine/v3.15/releases/x86_64/alpine-extended-3.15.0-x86_64.iso'	# initial install: 948M
URL='https://dl-cdn.alpinelinux.org/alpine/v3.15/releases/x86_64/alpine-standard-3.15.0-x86_64.iso'	# initial install: 948M
ISO="$( basename "$URL" )"
HDD='image.bin'

wget -O "$ISO" "$URL"

qemu-img create -f qcow2 "$HDD" 2G || \
echo 'H4sICJln+mEAA2Zvby5iaW4A7c7NasJAFAbQifYBfIR5mkKXXXU9asRA/GE60uqTF7ppFKW6Mdllc87AhYH7Xb7317ffEMI0PJqdx/L//3KZt63qbvY7Z9fr6c9HF4nd1SaXY5w3ZVi6WuxyPuzL0MSk/i513qY2LlNJcdW09dPzoU2nY8z1arE7bMtn7/nQ9dikfe/ibb/K6Ss+dBqYBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGMFk7AIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACMrro+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeOIPewYwSSAAAwA=' | base64 -d >"$HDD.gz" && gzip -d "$HDD.gz"
oemu-system-x86_64 -m 256 -nic user -boot d -cdrom "$ISO" -hda "$HDD"

# TODO: automate using 'expect'
# login as root, execute 'SWAP_SIZE=0 setup-alpine', answer these questions:
# q1: keyboard1           => de
# q2: keyboard2           => de-nodeadkeys
# q3: hostname            => foo
# q4: network             => eth0 (enter)
# q5: network             => dhcp (enter)
# q6: network             => manual? (enter)
# q7: password            => secret
# q8: timezoneA           => Europe
# q9: timezoneB           => Berlin
# q10: proxy              => none (enter)
# q11: use package mirror => default (enter)
# q12: which sshserver    => dropbear
# q13: use which hdd?     => sda
# q14: hdd-usecase?       => sys
# q15: really format hdd? => yes
#
# ... and execute 'poweroff'
# resulting image = 125 megabytes

OPTS="-nic user,hostfwd=tcp::10022-:22 -hda"
qemu-system-x86_64 -cpu host -enable-kvm -display none -nodefaults -m 512 $OPTS $HDD
ssh root@127.0.0.1 -p 10022

# install some packages:
sed -i 's|^#\(.*/community$\)|\1|' /etc/apk/repositories
apk update
# apk add dropbear-scp
# apk add ffmpeg
# apk add x11vnc
# apk add dnsmasq               # really?
apk add zram-init && rc-update add zram-init default
apk add xvfb
apk add firefox-esr
apk add scrot
apk add perl
apk add imagemagick
apk add file            # only for png_resolution_get()
apk add xdotool
apk add xclip
apk add coreutils	# base64 -w0 file.bin
# visgrep:
wget -qO /usr/local/bin/visgrep http://intercity-vpn.de/alpine-usr-local-bin-visgrep
chmod +x /usr/local/bin/visgrep
# bezier:
mkdir -p /usr/local/lib/perl5/site_perl/Math
wget -qO /usr/local/lib/perl5/site_perl/Math/Bezier.pm http://intercity-vpn.de/Bezier.pm
wget -qO bezier.pl http://intercity-vpn.de/bezier.pl
chmod +x bezier.pl
rm -f /var/cache/apk/*

# mini-webservice:
printf '%s\n%s\n' '#!/bin/sh' 'cat /proc/uptime >/tmp/BOOTED; nohup /etc/local.d/api &' >/etc/local.d/api.start
printf '%s\n%s\n' '#!/bin/sh' 'while true; do nc -l -p 80 -e /etc/local.d/api.sh; done' >/etc/local.d/api
chmod +x /etc/local.d/api.start /etc/local.d/api
rc-update add local default

# disable unneeded stuff:
sed -i -e 's/^.*swap/# &/' -e 's/^.*cdrom/# &/' -e 's/^.*usbdisk/# &/' /etc/fstab
sed -i 's|.*getty.*|# &|' /etc/inittab
rc-update del syslog boot	# check with 'rc-status'
rc-update del crond default
rc-update del dropbear default
rc-update del acpid		# still working 'poweroff'
reboot

# später alles in eine datei:
wget -O setup.sh "github..." && sh setup
# +datei: /etc/local.d/api.sh
# +datei: /root/worker.sh

OPTS="-nic user,hostfwd=tcp::10022-:22,hostfwd=tcp::10080-:80,hostfwd=tcp::10059-:5900 -hda"
qemu-system-x86_64 -cpu host -enable-kvm -display none -nodefaults -m 512 -snapshot $OPTS $HDD

# de, en-US, en    // HTTP_ACCEPT_LANGUAGE
# e.g.: vncviewer 127.0.0.1:10059 or e.g. xtightvncviewer -viewonly 127.0.0.1:10059
```

foo:~# touch /etc/local.d/api.sh && chmod +x /etc/local.d/api.sh
foo:~# cat  >/etc/local.d/api.sh <<EOF
#!/bin/sh

read _ QUERY _ && QUERY="\${QUERY#?}"
printf '%s\n\n' 'HTTP/1.1 200 OK'

case "\$QUERY" in
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
		pidof x11vnc >/dev/null || x11vnc -display :1 -cursor most -bg -nopw -xkb 2>/dev/null >/dev/null
	;;
	action=sysinfo)
		uname -a && uptime && free
		ps | while read -r LINE; do case "\$LINE" in *']') ;; *) printf '%s\n' "\$LINE" ;; esac; done
	;;
	action=report)
		/root/worker.sh "\${QUERY#*=}"
	;;
	action=resetbrowser)
		/root/worker.sh resetbrowser >/dev/null 2>&1 & disown
	;;
	language=*|screensize=*|screenshot*)
		/root/worker.sh "\${QUERY%%=*}" "\${QUERY#*=}"
	;;
	loadurl=*)
		pidof firefox >/dev/null || /root/worker.sh resetbrowser >/dev/null 2>&1 & disown
		/root/worker.sh "\${QUERY%%=*}" "\${QUERY#*=}"
	;;
	*)
		/root/worker.sh showusage "\$QUERY"
	;;
esac
EOF
foo:~# touch /root/worker.sh && chmod +x /root/worker.sh
foo:~# cat  >/root/worker.sh <<EOF
#!/bin/sh

ACTION="\$1"
ARG="\$2"

export DISPLAY=:1
read -r RESOLUTION 2>/dev/null </tmp/RESOLUTION || RESOLUTION=1920x1080

resetbrowser()
{
	sysctl -qw vm.panic_on_oom=2
	sysctl -qw kernel.panic_on_oops=1
	sysctl -qw kernel.panic=10
	sysctl -qw vm.min_free_kbytes=4096

	while pidof firefox >/dev/null; do xdotool key ctrl+w; sleep 1; killall firefox; sleep 1; done

	pidof Xvfb >/dev/null || nohup Xvfb \$DISPLAY -screen 0 \${RESOLUTION}x24+32 &

	firefox --version >/tmp/BROWSER
	nohup firefox >>/tmp/debug-firefox.1 2>>/tmp/debug-firefox.2 &
	while ! ID="\$( xdotool search --classname Navigator )"; do sleep 1; done
}

press_enter_and_measure_time_till_network_relax_max10sec()
{
	local i j dev line old=
	local bytes_dn bytes_dn_old diff_dn sum_dn
	local bytes_up bytes_up_old diff_up sum_up
	local up rest t0 t1 time list=

	# e.g. default via 10.63.22.97 dev eth0 proto static metric 100
	#                                  ^^^^
	for dev in \$( ip route list exact '0.0.0.0/0' ); do test "\$old" = dev && break; old="\$dev"; done

	byte_counter()
	{
		while read -r line; do {
			case "\$line" in
				*"\$1:"*)
					# shellcheck disable=SC2086
					set -- \${line#*:}

					bytes_dn="\$1"
					bytes_up="\$9"
					return
				;;
			esac
		} done </proc/net/dev
	}
	
	# initial values for uptime:
	read -r up rest </proc/uptime
	t0="\${up%.*}\${up#*.}0"

	# initial values for network:
	byte_counter "\$dev"
	bytes_dn_old="\$bytes_dn"	# our baseline
	bytes_up_old="\$bytes_up"
	sum_up="\$bytes_dn"
	sum_dn="\$bytes_up"

local bdn=0
local bup=0
	j=8	# consecutive measurepoints without traffic
	i=100	# 100 x 0.1 sec = 10 sec maxtime

	date +%s >/tmp/URL_START
	xdotool key Return

	while case "\$i" in 0) false ;; esac
	do
		i=\$(( i - 1 ))

		read -r up rest </proc/uptime
		t1="\${up%.*}\${up#*.}0"

		byte_counter "\$dev"
		diff_dn=\$(( bytes_dn - bytes_dn_old ))
		diff_up=\$(( bytes_up - bytes_up_old ))
		bytes_dn_old="\$bytes_dn"
		bytes_up_old="\$bytes_up"
# debug:
		bdn=\$(( bdn + bytes_dn ))
		bup=\$(( bdn + bytes_up ))

		time="\$(( t1 - t0 ))"
		list="\$list \$time,\$diff_dn,\$diff_up"

		case "\$j-\$diff_dn-\$diff_up" in
			0-0-0) break ;;
			*-0-0) j=\$(( j - 1 )) ;;
		esac

		sleep 0.1
	done

	sum_dn=\$(( bytes_dn - sum_dn ))
	sum_up=\$(( bytes_up - sum_up ))

	export LIST="\$list"
	echo "\$(( 100 - (i + 8) ))00" >/tmp/DOWNLOAD_TIME_MS
	echo "\$sum_dn | \$bdn" >/tmp/DN
	echo "\$sum_up | \$bup" >/tmp/UP
}

base64image()
{
	if test -s /tmp/screen.png; then
		printf '%s' '"'
		base64 -w0 /tmp/screen.png
		printf '%s' '"'
	else
		echo 'null'
	fi
}

get_url()
{
	xdotool key ctrl+l		# jump to url-bar
	xdotool key ctrl+c
	OUT="\$( xclip -out -selection 'clipboard' )"
	xdotool key Escape
	xdotool key Tab

	printf '%s\n' "\$OUT"
}

case "\$ACTION" in
	screenshot)
		# GTmetrix.com
		# call main with args + TODO: count bytes + streams + time + w3c validator? + effective URL + compression?
		case "\$ARG" in
			png) scrot --silent --overwrite /tmp/screen.png	            || echo "scrot-RC:\$?" ;;
			  *) scrot --silent --overwrite /tmp/screen.jpg -quality 30 || echo "scrot-RC:\$?" ;;
		esac
	;;
	report)
#		cat <<EOF
#{
  "time_unix": "\$( cat /tmp/URL_START )",
  "time_date": "\$( read -r UNIX </tmp/URL_START && LC_ALL=C date -d@\$UNIX && printf '%s' ' timezone ' && tail -n1 /etc/localtime )",
  "url_userinput": "\$( cat /tmp/URL )",
  "url_effective": "\$( get_url )",
  "http_accept_language": "ToDo",
  "user_agent": "ToDo",
  "download_time_ms": "\$( cat /tmp/DOWNLOAD_TIME_MS )",
  "download_size_bytes": "\$( cat /tmp/DOWNLOAD_BYTES )",
  "network_action": "array",
  "browser_version": "\$( cat /tmp/BROWSER )",
  "resolution": "\$RESOLUTION",
  "screenshot": \$( base64image )
#}
#EOF
	;;
	reboot)
		sync && reboot -f
	;;
	safe_poweroff)
		while pidof firefox >/dev/null; do xdotool key ctrl+w; sleep 1; killall firefox; sleep 1; done
		poweroff
	;;
	resetbrowser)
		resetbrowser
	;;
	language)
		# about:config => intl.accept_languages
	;;
	screensize)
		printf '%s\n' "\$ARG" >/tmp/RESOLUTION
	;;
	geturl)
		geturl
	;;
	loadurl)
		url_decode() {
			local url="\$1"
			local hex_encoded

			tohex() { sed -E -e 's/\+/ /g' -e 's/%([0-9a-fA-F]{2})/\\\x\1/g'; }
			hex_encoded="\$( printf '%s\n' "\$url" | tohex )"

			printf '%b\n' "\$hex_encoded"
		}

		ID="\$( xdotool search --classname Navigator )" || resetbrowser
		URL="\$( url_decode "\$ARG" )"
		echo "\$URL" >/tmp/URL

		# prepare:
		xdotool windowsize "\$ID" \$X \$Y
		xdotool key ctrl+t		# new tab
		xdotool key ctrl+Page_Up	# go back to old tab
		xdotool key ctrl+w		# close (old) tab
		xdotool key ctrl+l		# jump to url-bar
        	xdotool key BackSpace sleep 0.3	# make sure we start empty
        	xdotool type --delay 300 "\$URL"

		>/tmp/screen.png
		press_enter_and_measure_time_till_network_relax_max10sec
		echo "\$LIST"
	;;
	*)
		printf '%s\n' "ERROR - detected: \${ARG:-<empty>} | KEY=\$ACTION VALUE=\$ARG"
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
EOF

