#!/bin/sh -x

if [ $(id -u) -ne 0 ]; then
    exec sudo -E "$0" "$@"
fi

base=$(dirname $0)

APP="$base/build-root/install-vpp_debug-native/vpp/bin/vpp"
ARGS="-c $base/startup.conf"

USAGE="Usage: run.sh [ debug ]
       debug:	executes vpp under gdb"

if test -z "$1"; then
    $APP $ARGS
elif test "$1" = "debug"; then
    shift
    gdb -ex 'set print pretty on' -ex 'run' --args $APP $ARGS $@
else
    echo "$USAGE"
fi
