### Usage

```
./boot-vm.sh	# needs ~5 sec till port 10080 is yours!

curl "http://127.0.0.1:10080/loadurl=http://c64.de"
curl "http://127.0.0.1:10080/screenshot=jpg"
curl "http://127.0.0.1:10080/action=report"
```
outputs a JSON like:
```
{
  "time_unix": 1643808355,
  "time_date": "Wed Feb  2 14:25:55 CET 2022 CET-1CEST,M3.5.0,M10.5.0/3",
  "url_userinput": "http://c64.de",
  "url_effective": "https://icomp.de/shop-icomp/en/news.html",
  "http_accept_language": "en-US,en;q=0.5",
  "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8)",
  "download_time_ms": 2380,
  "download_size_bytes": 510237,
  "network_public_ip": "185.97.181.129",
  "network_country": "Germany",
  "network_action": [
    {"tims_ms":   20, "bytes_down":      0, "bytes_up":      0},
    {"tims_ms":  130, "bytes_down":   2076, "bytes_up":   9555},
    {"tims_ms":  230, "bytes_down":   6802, "bytes_up":   2128},
    {"tims_ms":  330, "bytes_down":   1343, "bytes_up":   1446},
    {"tims_ms":  430, "bytes_down":   1343, "bytes_up":   1291},
    {"tims_ms":  530, "bytes_down":    184, "bytes_up":    346},
    {"tims_ms":  640, "bytes_down":   8282, "bytes_up":    797},
    {"tims_ms":  740, "bytes_down":   3720, "bytes_up":   1297},
    {"tims_ms":  850, "bytes_down":    732, "bytes_up":   1609},
    {"tims_ms":  960, "bytes_down":    205, "bytes_up":    100},
    {"tims_ms": 1070, "bytes_down":    428, "bytes_up":    512},
    {"tims_ms": 1190, "bytes_down":  22427, "bytes_up":  14549},
    {"tims_ms": 1300, "bytes_down": 112978, "bytes_up":   6702},
    {"tims_ms": 1400, "bytes_down":  48929, "bytes_up":   3994},
    {"tims_ms": 1510, "bytes_down": 276035, "bytes_up":   7668},
    {"tims_ms": 1630, "bytes_down":  18361, "bytes_up":  76433},
    {"tims_ms": 1770, "bytes_down":   1884, "bytes_up":  17347},
    {"tims_ms": 1870, "bytes_down":    976, "bytes_up":  16633},
    {"tims_ms": 1970, "bytes_down":   1520, "bytes_up":  24645},
    {"tims_ms": 2070, "bytes_down":   1276, "bytes_up":  18329},
    {"tims_ms": 2180, "bytes_down":    552, "bytes_up":   1049},
    {"tims_ms": 2280, "bytes_down":      0, "bytes_up":      0},
    {"tims_ms": 2380, "bytes_down":    184, "bytes_up":    303}],
  "browser_version": "Mozilla Firefox 78.3.0esr",
  "resolution": "1280x720",
  "screenshot_size": 37744,
  "screenshot_format": "jpg",
  "screenshot": "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDACAWGBwYFC....."
}
```

there is more help:
```
curl "http://127.0.0.1:10080/help
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

# TODO: de, en-US, en    // HTTP_ACCEPT_LANGUAGE
# e.g.: vncviewer 127.0.0.1:10059 or e.g. xtightvncviewer -viewonly 127.0.0.1:10059
```
