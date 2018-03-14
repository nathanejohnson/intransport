#!/bin/bash
set -e


SRCDIR=/root/
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

hosts=$(sed 's/^127.0.0.1 //' ${DIR}/_testdata/insecurities.txt)

cd $DIR

GODEBUG=netdns=cgo go test -c -o intransporttest

docker=$(which docker)

args=(run -t -v "${DIR}":"${SRCDIR}")

for host in $hosts; do
	args+=(--add-host ${host}:127.0.0.1)
done

args+=(trusty /bin/bash -c "${SRCDIR}/intransporttest")

exec "$docker" "${args[@]}"
#echo "${args[@]}"
