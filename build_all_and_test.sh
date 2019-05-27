#!/bin/bash
set -e

cargo test
cargo bench -- --nocapture
cargo build --examples
cargo build --release --examples
xargo build --target x86_64-apple-darwin --release
strip -u -r -x -S target/release/libossuary.dylib
strip -u -r -x -S target/x86_64-apple-darwin/release/libossuary.dylib
mkdir -p examples/build/
pushd examples/build > /dev/null
cmake ..
make
popd > /dev/null

echo ""
echo "Debug build:"
ls target/debug/*.dylib

echo ""
echo "Release build:"
ls target/x86_64-apple-darwin/release/*.dylib

echo ""
echo "Examples:"
find target/debug/examples/ -type f -perm +111 -d 1
find examples/build/ -type f -perm +111 -d 1
