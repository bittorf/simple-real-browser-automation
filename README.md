### Usage

./boot-vm.sh

curl "http://127.0.0.1:10080/help
curl "http://127.0.0.1:10080/loadurl=http://c64.de"
curl "http://127.0.0.1:10080/screenshot=jpg"
curl "http://127.0.0.1:10080/action=report"

```
{
  "time_unix": 1643808355,
  "time_date": "Wed Feb  2 14:25:55 CET 2022 timezone CET-1CEST,M3.5.0,M10.5.0/3",
  "url_userinput": "http://c64.de",
  "url_effective": "https://icomp.de/shop-icomp/en/news.html",
  "http_accept_language": "ToDo",
  "user_agent": "ToDo",
  "download_time_ms": 2420,
  "download_size_bytes": 496404,
  "netowrk_public_ip": "185.97.181.129",
  "netowrk_country": "Germany",
  "network_action": [
    {"tims_ms":   20, "bytes_down":      0, "bytes_up":      0},
    {"tims_ms":  130, "bytes_down":    949, "bytes_up":   1324},
    {"tims_ms":  230, "bytes_down":   6618, "bytes_up":   1707},
    {"tims_ms":  330, "bytes_down":    975, "bytes_up":    578},
    {"tims_ms":  440, "bytes_down":    915, "bytes_up":    527},
    {"tims_ms":  540, "bytes_down":      0, "bytes_up":      0},
    {"tims_ms":  640, "bytes_down":   6224, "bytes_up":    120},
    {"tims_ms":  740, "bytes_down":   5152, "bytes_up":   1064},
    {"tims_ms":  850, "bytes_down":      0, "bytes_up":      0},
    {"tims_ms":  960, "bytes_down":    145, "bytes_up":    100},
    {"tims_ms": 1060, "bytes_down":     60, "bytes_up":      0},
    {"tims_ms": 1170, "bytes_down":      0, "bytes_up":      0},
    {"tims_ms": 1280, "bytes_down":  26321, "bytes_up":   6050},
    {"tims_ms": 1390, "bytes_down": 109899, "bytes_up":   3488},
    {"tims_ms": 1500, "bytes_down":  95390, "bytes_up":   3462},
    {"tims_ms": 1600, "bytes_down": 234656, "bytes_up":   4380},
    {"tims_ms": 1710, "bytes_down":      0, "bytes_up":      0},
    {"tims_ms": 1810, "bytes_down":      0, "bytes_up":      0},
    {"tims_ms": 1910, "bytes_down":      0, "bytes_up":      0},
    {"tims_ms": 2020, "bytes_down":   7576, "bytes_up": 124228},
    {"tims_ms": 2120, "bytes_down":    972, "bytes_up":  13524},
    {"tims_ms": 2220, "bytes_down":    368, "bytes_up":    700},
    {"tims_ms": 2320, "bytes_down":      0, "bytes_up":      0},
    {"tims_ms": 2420, "bytes_down":    184, "bytes_up":    310}],
  "browser_version": "Mozilla Firefox 78.3.0esr",
  "resolution": "1280x720",
  "screenshot_size": 37744,
  "screenshot_format": "jpg",
  "screenshot": "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDACAWGBwYFCAcGhwkIiAmMFA0MCwsMGJGSjpQdG....."
}
```

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

# TODO: all in one setupfile:
# wget -O setup.sh "github..." && sh setup
BASE='https://raw.githubusercontent.com/bittorf/simple-real-browser-automation/main'
FILE='/etc/local.d/api.sh' && wget -O "$FILE" "$BASE/api.sh"    && chmod +x "$FILE"
FILE='/root/worker.sh'     && wget -O "$FILE" "$BASE/worker.sh" && chmod +x "$FILE"
poweroff

# now snapshotted:
OPTS="-nic user,hostfwd=tcp::10022-:22,hostfwd=tcp::10080-:80,hostfwd=tcp::10059-:5900 -hda"
qemu-system-x86_64 -cpu host -enable-kvm -display none -nodefaults -m 512 -snapshot $OPTS $HDD

# de, en-US, en    // HTTP_ACCEPT_LANGUAGE
# e.g.: vncviewer 127.0.0.1:10059 or e.g. xtightvncviewer -viewonly 127.0.0.1:10059
```
