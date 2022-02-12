#!/bin/sh

URL='https://dl-cdn.alpinelinux.org/alpine/v3.12/releases/x86_64/alpine-virt-3.12.9-x86_64.iso'
ISO="$( basename "$URL" )"
HDD='image.bin' && rm -f "$HDD"

wget -cO "$ISO" "$URL" || exit 1

qemu-img create -f qcow2 "$HDD" 2G 2>/dev/null || \
echo 'H4sICJln+mEAA2Zvby5iaW4A7c7NasJAFAbQifYBfIR5mkKXXXU9asRA/GE60uqTF7ppFKW6Mdllc87AhYH7Xb7317ffEMI0PJqdx/L//3KZt63qbvY7Z9fr6c9HF4nd1SaXY5w3ZVi6WuxyPuzL0MSk/i513qY2LlNJcdW09dPzoU2nY8z1arE7bMtn7/nQ9dikfe/ibb/K6Ss+dBqYBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGMFk7AIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACMrro+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeOIPewYwSSAAAwA=' | base64 -d >"$HDD.gz" && gzip -d "$HDD.gz"

# needs ~30 sec with KVM and ~130 sec without to produce a 175mb image
FIFO="$( mktemp )" && rm -f "$FIFO" && mkfifo "$FIFO.in" "$FIFO.out"
qemu-system-x86_64 -enable-kvm -m 96 -nic user -boot d -cdrom "$ISO" -hda "$HDD" -serial "pipe:$FIFO" -nographic &
QEMU_PID=$!

say() { printf '%s\n' "$1" >"$FIFO.in"; }
press_enter() { say ''; }
zram_start() { say 'read _ TOTAL _ </proc/meminfo;modprobe zram;echo $((TOTAL*1024)) >/sys/block/zram0/disksize;mkswap /dev/zram0;swapon -d -p 5 /dev/zram0;cat /proc/swaps'; }

I=999
while read -r LINE; do
  I=$(( I + 1 ))

  # enforce baseline for some sections:
  case "$LINE" in
    *"(/dev/ttyS0)"*) I=0 ;;
    *'obtained, lease time'*) I=100 ;;
    *'password for root changed'*) I=200 ;;
    *'Edit /etc/apk/repositories'*) I=300 ;;
    *'Updating repository indexes'*) I=400 ;;
    *'Installation is complete'*) I=500 ;;
  esac

  printf '%s\n' "$LINE" | cut -b1-80 | hexdump -C
  printf '%s\n' "linenumber: $I"

  case "$I" in
    1) say 'root' ;;				# login
   11) zram_start ;;				# so 96mb RAM is enough
   12) say 'export BOOT_SIZE=20 SWAP_SIZE=0 && setup-alpine && poweroff' ;;	# start setup
   23) say 'de' ;;				# keymap
   25) say 'de-nodeadkeys' ;;			# keymap-subtype
   30) say 'hostname-auto' ;;			# hostname
   33) press_enter ;;				# network: bridges?
   34) press_enter ;;				# network: init eth0?
   35) press_enter ;;				# network: dhcp?
  101) say 'alpine99foobar' ;;			# password for root
  102) say 'alpine99foobar' ;;			# password repeat
  103) say 'alpine99foobar' ;;			# password repeat
  104) say 'alpine99foobar' ;;			# password repeat
  106) say 'alpine99foobar' ;;			# password repeat
  107) say 'alpine99foobar' ;;			# password repeat
  108) say 'alpine99foobar' ;;			# password repeat
  202) say 'Europe' ;;				# timezone
  203) say 'Berlin' ;;				# timezone-subtype
  208) press_enter ;;				# proxy?
  301) press_enter ;;				# mirror?
  400) say 'dropbear' ;;			# which SSHd?
  406) say 'sda' ;;				# which harddisk?
  409) say 'sys' ;;				# which usecase?
  430) say 'y' ;;				# really?
  esac
done <"$FIFO.out"

while kill -0 "$QEMU_PID" 2>/dev/null; do sleep 1; done
rm -f "$FIFI.in" "$FIFI.out"
