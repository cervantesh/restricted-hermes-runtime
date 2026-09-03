#!/bin/sh
set -eu

test "$(id -u)" = 0
install -d -o 10008 -g 20006 -m 0770 /run/restricted-clinical
test "$(stat -c '%u:%g:%a' /run/restricted-clinical)" = "10008:20006:770"
