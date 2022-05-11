#!/usr/bin/env bash
set -euo pipefail

rm -r 'out' || true
rm -r 'in' || true
cargo run -p embedded-tls-afl --bin gencorpus
mkdir 'in'
mv corpus 'in'
cargo afl build -p embedded-tls-afl
cargo afl fuzz -i in -o out target/debug/embedded-tls-afl
