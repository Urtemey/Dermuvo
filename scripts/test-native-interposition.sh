#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir "$work/control" "$work/hardened"
cp "$root/native/durevo_vm.c" "$root/native/durevo_encrypted.c" "$work/control/"
# Deliberately vulnerable positive control, derived only in the temporary test tree.
# All other code and compiler/linker flags are identical to production.
grep -q 'answer = durevo_run_core(program' "$work/control/durevo_encrypted.c"
sed -i 's/answer = durevo_run_core(program, words, arguments, argc, locals, stack, mask, steps, result, strings);/answer = durevo_run(program, words, arguments, argc, locals, stack, mask, steps, result);/' "$work/control/durevo_encrypted.c"
gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -fvisibility=hidden -shared "$work/control/durevo_encrypted.c" -lcrypto -o "$work/control/libdurevo_vm.so"
gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -fvisibility=hidden -shared "$root/native/durevo_encrypted.c" -lcrypto -o "$work/hardened/libdurevo_vm.so"
gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared "$root/native/tests/dispatch_interposer.c" -o "$work/interposer.so"
gcc -std=c11 -O2 -Wall -Wextra -Werror "$root/native/tests/dispatch_probe.c" -L "$work/hardened" -ldurevo_vm -lcrypto -ldl -o "$work/driver"
LD_LIBRARY_PATH="$work/control" LD_PRELOAD="$work/interposer.so" "$work/driver" exposed
LD_LIBRARY_PATH="$work/hardened" LD_PRELOAD="$work/interposer.so" "$work/driver" closed
