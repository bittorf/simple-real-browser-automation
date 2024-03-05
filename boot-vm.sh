#!/bin/sh

ACTION="$1"	# <empty>, debug, writeable

IMAGE='image.bin'

[ -f "$IMAGE.xz-1" ] && [ ! -f "$IMAGE" ] && {
	echo "uncompressing $IMAGE.xz"
	cat "$IMAGE.xz-"* >"$IMAGE.xz"
	xz -d "$IMAGE.xz"
}

[ -f "$IMAGE" ] || {
	echo "can not found '$IMAGE', please run ./setup_aline.sh"
	exit 1
}

MEM='512m'
PORT_HTTP=10080
PORTS="user,hostfwd=tcp::10022-:22,hostfwd=tcp::${PORT_HTTP}-:80,hostfwd=tcp::10059-:5900"
SNAPSHOT="-snapshot"
DEBUG='-display none'
[ "$ACTION" = debug ] && DEBUG='-nographic'

supports_kvm()
{
	test "$NOKVM" && return 1
	grep -q 'Microsoft' /proc/version && return 1	# tested on WSL1
	grep -q 'vmx\|svm' /proc/cpuinfo
}

if supports_kvm; then
	echo "[OK] trying to run QEMU in KVM mode (maybe needs sudo)"
	# shellcheck disable=SC2086
	qemu-system-x86_64 -cpu host -enable-kvm $DEBUG -nodefaults -m $MEM $SNAPSHOT -nic "$PORTS" -hda "$IMAGE" &
else
	echo "[OK] trying to run QEMU (slow mode, no suitable CPU-flags found)"
set -x
	# shellcheck disable=SC2086
	qemu-system-x86_64                       $DEBUG -nodefaults -m $MEM $SNAPSHOT -nic "$PORTS" -hda "$IMAGE" &
set +x
fi

PID=$!
sleep 1
echo "[OK] VM starts booting"

http_get() {
	if command -v 'curl' >/dev/null; then
		curl --silent --max-time 1 --output /dev/null "$1"
	else
		wget -T1 -t1 -qO /dev/null "$1"
	fi
}

vm_runs() { kill -0 "$PID" 2>/dev/null; }
update_vm() { http_get "http://127.0.0.1:$PORT_HTTP/action=update" && return; echo "[DEBUG] waiting for API readiness"; false; }

if vm_runs; then
	while ! update_vm; do sleep 1; done; update_vm

	echo
	echo "[OK] VM is ready, you can enable SSH access with:"
	echo "     curl http://127.0.0.1:$PORT_HTTP/action=startssh"
	echo "  or speak with the API like:"
	echo "     curl http://127.0.0.1:$PORT_HTTP/help"
	echo
	echo "(waiting for end of QEMU with process-ID $PID, e.g. with CTRL+C)"

	while vm_runs; do sleep 1; done
else
	echo "[ERROR] on startup, process-ID $PID died - you can try e.g. NOKVM=true $0 $*"
	exit 1
fi
