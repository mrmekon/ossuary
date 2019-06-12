#!/bin/bash

case `uname` in
    "Linux")
	STRIP_ARGS=""
	LIB_EXT="so"
	XARGO_TARGET="x86_64-unknown-linux-gnu"
	FIND_MODE="-maxdepth 1 -type f -perm /111"
	;;
    "Darwin")
	STRIP_ARGS="-u -r -x -S"
	LIB_EXT="dylib"
	XARGO_TARGET="x86_64-apple-darwin"
	FIND_MODE="-perm +111 -d 1 -type f"
	;;
    *)
	echo "Platform not supported:" `uname`
	exit 1
	;;
esac

command -v xargo > /dev/null
if [[ $? -ne 0 ]]; then
    echo "xargo required."
    echo "run:"
    echo "  $ cargo install xargo"
    echo "  $ rustup component add rust-src"
    exit 1
fi

set -e

cargo test
cargo bench -- --nocapture
cargo build
cargo build --examples
cargo build --release
cargo build --release --examples
xargo build --target $XARGO_TARGET --release
strip $STRIP_ARGS "target/release/libossuary.$LIB_EXT"
strip $STRIP_ARGS "target/$XARGO_TARGET/release/libossuary.$LIB_EXT"
mkdir -p examples/build/
pushd examples/build > /dev/null
cmake ..
make
popd > /dev/null

echo ""
echo "Debug build:"
ls target/debug/*.$LIB_EXT

echo ""
echo "Release build:"
ls target/$XARGO_TARGET/release/*.$LIB_EXT

echo ""
echo "Examples:"
find target/debug/examples/ $FIND_MODE
find examples/build/ $FIND_MODE
