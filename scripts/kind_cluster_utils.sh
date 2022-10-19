#!/bin/bash
# Requires kind v0.11.1
# Requires kubectl v1.21.1


SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
logdir=../logs/
mkdir -p $logdir || exit

usage()
{
    echo "Usage: $0 command [args]" >&2
    echo "Commands [args]:" >&2
    cat >&2 << EOF
    create
    delete
EOF
    echo "Logs in $logdir" >&2
    echo "" >&2
    exit 1
}

###############################################################################
stamp=`date +%y%m%d-%H%M%S`
err_=$logdir/simple-$stamp-err-
out_=$logdir/simple-$stamp-out-
warn=3

case "${1:-?}" in
*[!a-z0-9-]*)
    usage
esac

log=$1.txt out=$out_$log err=$err_$log
val=0

case $1 in
create)
    echo "Creating kind cluster"
    kind create cluster --config $SCRIPT_DIR/kind-default.yaml --name prada
;;
###############################################################################
delete)
    echo "Deletind kind cluster"
    kind delete cluster -n prada
;;
*)
    usage
esac

echo "The command finished with exit code $val (logs in $logdir)"
exit $val
