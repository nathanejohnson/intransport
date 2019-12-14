#!/bin/bash
set -ex


SRCDIR=/root
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

hosts=$(cat ${DIR}/_testdata/insecurities.txt)

cd $DIR

LABEL="intransport_test"
docker rm -f ${LABEL} || true
docker rmi ${LABEL} || true

docker=$(which docker)

args=(build --label ${LABEL} -t ${LABEL})

for host in $hosts; do
	args+=(--add-host ${host}:127.0.0.1)
done

## butt wait, there's more!
args+=( . )

exec "$docker" "${args[@]}"

docker run ${LABEL}
