#!/bin/sh
# Run all tests inside the omega-sdk container (Linux with gcc, python3, zlib
# and the SocketCAN headers). The native tests need Linux; on a Linux host
# just run:  python3 -m unittest discover -v -s test
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEST=/work/can2udp-test

docker start omega-sdk >/dev/null
docker exec omega-sdk rm -rf "$DEST"
docker exec omega-sdk mkdir -p "$DEST"
docker cp "$ROOT/src" omega-sdk:"$DEST"/src
docker cp "$ROOT/test" omega-sdk:"$DEST"/test
docker cp "$ROOT/files" omega-sdk:"$DEST"/files
docker exec -w "$DEST" omega-sdk python3 -m unittest discover -v -s test -p 'test_*.py'
