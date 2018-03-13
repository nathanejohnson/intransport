#!/bin/bash
set -e
SRCDIR=/root/go/src/github.com/nathanejohnson/intransport
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

hosts=$(sed 's/^127.0.0.1 //' ${DIR}/_testdata/hostaliases.linux)

cd $DIR

docker=$(which docker)

args=(run -t -v "${DIR}":"${SRCDIR}")

for host in $hosts; do
	args+=(--add-host ${host}:127.0.0.1)
done

args+=(iron/go:dev /bin/ash -c "cd $SRCDIR && GODEBUG=netdns=cgo /usr/local/go/bin/go test -v")

exec "$docker" "${args[@]}"
