#!/bin/sh

ACTION="$1"	# <empty>, debug, writeable

IMAGE='image.bin'
MEM='768m'
PORTS="user,hostfwd=tcp::10022-:22,hostfwd=tcp::10080-:80,hostfwd=tcp::10059-:5900"
SNAPSHOT="-snapshot"
DEBUG='-display none'

if grep -q 'vmx\|svm' /proc/cpuinfo; then
	echo "[OK] trying to run qemu in KVM mode (mybe needs sudo)"
	qemu-system-x86_64 -cpu host -enable-kvm $DEBUG -nodefaults -m $MEM $SNAPSHOT -nic "$PORTS" -hda "$IMAGE"
else
	echo "[OK] trying to run qemu (slow mode, no suitable cpuflags found)"
	qemu-system-x86_64 -cpu host             $DEBUG -nodefaults -m $MEM $SNAPSHOT -nic "$PORTS" -hda "$IMAGE"
fi
