#!/bin/sh

ACTION="$1"	# <empty>, debug, writeable

IMAGE='image.bin'

[ -f "$IMAGE.xz-1" ] && {
	echo "uncompressing $IMAGE.xz"
	cat "$IMAGE.xz-"* >"$IMAGE.xz"
	xz -d "$IMAGE.xz" && rm -f "$IMAGE.xz"*
}

[ -f "$IMAGE" ] || {
	echo "can not found '$IMAGE', please run ./setup_aline.sh"
	exit 1
}

MEM='768m'
PORT_HTTP=10080
PORTS="user,hostfwd=tcp::10022-:22,hostfwd=tcp::${PORT_HTTP}-:80,hostfwd=tcp::10059-:5900"
SNAPSHOT="-snapshot"
DEBUG='-display none'

if grep -q 'vmx\|svm' /proc/cpuinfo; then
	echo "[OK] trying to run qemu in KVM mode (mybe needs sudo)"
	qemu-system-x86_64 -cpu host -enable-kvm $DEBUG -nodefaults -m $MEM $SNAPSHOT -nic "$PORTS" -hda "$IMAGE" &
else
	echo "[OK] trying to run qemu (slow mode, no suitable cpuflags found)"
	qemu-system-x86_64 -cpu host             $DEBUG -nodefaults -m $MEM $SNAPSHOT -nic "$PORTS" -hda "$IMAGE" &
fi

PID=$!
echo "[OK] vm is booting"
sleep 1
vm_runs() { kill -0 "$PID"; }

if vm_runs; then
	while ! nc -z 127.0.0.1 $PORT_HTTP; do sleep 1; done

	echo
	echo "[OK] vm ready, you can enable SSH access with e.g.:"
	echo "     curl http://127.0.0.1:$PORT_HTTP/action=startssh"
	echo "  or speak with the API with e.g.:"
	echo "     curl http://127.0.0.1:$PORT_HTTP/help"
	echo
	echo "(waiting for end of qemu with process-id $PID, e.g. with CTRL+C)"

	while vm_runs; do sleep 1; done
else
	echo "[ERROR] on startup, process-id $PID died"
	exit 1
fi
