#!/bin/sh
set -eu
# This simulator is private to this container and disposable. Never clear a physical TPM.
mkdir -p /tmp/integrity-swtpm
swtpm socket --tpm2 --tpmstate dir=/tmp/integrity-swtpm --ctrl type=tcp,port=2322,bindaddr=127.0.0.1 --server type=tcp,port=2321,bindaddr=127.0.0.1 --flags not-need-init &
TPM_PID=$!
trap 'kill "$TPM_PID" 2>/dev/null || true' EXIT
export TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321
sleep 1
tpm2_startup -c
tpm2_getcap properties-fixed > /tmp/tpm-capabilities.txt
tpm2_createek -c 0x81010001 -G rsa >/dev/null
tpm2_createak -C 0x81010001 -c /tmp/ak.ctx -G rsa -g sha256 -s rsassa -u /tmp/ak.pem -f pem >/dev/null
tpm2_evictcontrol -C o -c /tmp/ak.ctx 0x81010002 >/dev/null
tpm2_flushcontext -t
export TPM_AK=0x81010002 TPM_PEM=/tmp/ak.pem
"$@"
