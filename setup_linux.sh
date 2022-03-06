#!/bin/sh
#
# tiny setup = 271mb image
# full setup = ???mb image
#
# TODO: repeat on error?

export PATH='/usr/bin:/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin'

while ! wget -qO - "http://detectportal.firefox.com"; do sleep 1; done

# move cache to ramdisk:
mkdir /run/apkcache && rm -fR /var/cache/apk && ln -s /run/apkcache /var/cache/apk
# enable community repo:
sed -i 's|^[# ]*\(.*[0-9]/community\)$|\1|' /etc/apk/repositories

apk update
apk add zram-init && rc-update add zram-init default
apk add xvfb
apk add firefox-esr
apk add scrot		# screenshots
apk add xdotool
apk add xclip		# clipboard buffer copy/paste
apk add coreutils	# only needed for 'base64 -w0 file.bin'
apk add font-noto

full()
{
  apk add dropbear-scp
  apk add ffmpeg
  apk add x11vnc
  apk add dnsmasq	# really?
  apk add file		# only for png_resolution_get()
  apk add imagemagick
  apk add sshuttle	# poor mens VPN

  # visgrep:
  URL="http://intercity-vpn.de/alpine-usr-local-bin-visgrep"
  wget -qO /usr/local/bin/visgrep "$URL"
  chmod +x /usr/local/bin/visgrep

  # calc bezier curves for mouse:
  URL="http://intercity-vpn.de/Bezier.pm"
  mkdir -p /usr/local/lib/perl5/site_perl/Math
  wget -qO /usr/local/lib/perl5/site_perl/Math/Bezier.pm "$URL"

  apk add perl
  URL="http://intercity-vpn.de/bezier.pl"
  wget -qO bezier.pl "$URL"
  chmod +x bezier.pl
}

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

BASE='https://raw.githubusercontent.com/bittorf/simple-real-browser-automation/main'
FILE='/etc/local.d/api.sh' && wget -O "$FILE" "$BASE/api.sh"    && chmod +x "$FILE"
FILE='/root/worker.sh'     && wget -O "$FILE" "$BASE/worker.sh" && chmod +x "$FILE"
poweroff
