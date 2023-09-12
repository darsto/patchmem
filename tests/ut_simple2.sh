#!/bin/bash
set -eouix pipefail

LD_PRELOAD=build/ut_simple2_preload.so build/ut_simple2 &
pid=$!

gdb_out=$(gdb -q \
    -ex "attach $pid" \
    -ex "set confirm off" \
    -ex "set \$dlopen = (void*(*)(char*)) dlopen" \
    -ex "set \$ret = \$dlopen(\"$PWD/build/ut_simple2_injected.so\", 0x102)" \
    -ex "printf \"\$ret = 0x%x\n\", \$ret" \
    -ex "q")

libhandle=$(awk '/\$ret = /{print $NF}' <<< "$gdb_out")
[[ libhandle != "0x0" ]]

sleep 0.5

gdb -q \
    -ex "attach $pid" \
    -ex "set confirm off" \
    -ex "set \$deinit = (void(*)(int)) deinit" \
    -ex "set \$dlclose = (int(*)(void*)) dlclose" \
    -ex "call \$deinit(1)" \
    -ex "call \$dlclose($libhandle)" \
    -ex "q"

wait