#!/bin/bash
set -ex

SRCDIR=/root
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

hosts=$(cat ${DIR}/_testdata/insecurities.txt)

cd $DIR
docker=$(which docker)

LABEL="intransport_test"
${docker} rmi ${LABEL} || true

args=(build --label ${LABEL} -t ${LABEL})

for host in $hosts; do
	args+=(--add-host ${host}:127.0.0.1)
done

## butt wait, there's more!
args+=( . )

eval "$docker" "${args[@]}"

${docker} rmi ${LABEL}
