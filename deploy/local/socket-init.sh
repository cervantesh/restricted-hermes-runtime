#!/bin/sh
set -eu
install -d -o 0 -g 20000 -m 1770 /run/restricted-inference
install -d -o 0 -g 20004 -m 1770 /run/restricted-postgres
