#!/bin/bash

set -euo pipefail

export RESTCHAIN_HOST=localhost
export RESTCHAIN_PORT=6060
export RESTCHAIN_LISTEN="$RESTCHAIN_HOST:$RESTCHAIN_PORT"
export RESTCHAIN_API="http://$RESTCHAIN_LISTEN/api"

export RESTCHAIN_REF_HOST=localhost
export RESTCHAIN_REF_PORT=6061
export RESTCHAIN_REF_LISTEN="$RESTCHAIN_REF_HOST:$RESTCHAIN_REF_PORT"
export RESTCHAIN_REF_API="http://$RESTCHAIN_REF_LISTEN/api"

exitcode=0

echo '>>> Testing Python Client'
python/restchain/client.py "$RESTCHAIN_API" || { exitcode=1; echo '>>> FAIL'; } && echo '>>> OK'

echo '>>> Testing Java Client'
java -cp java:java/restchain.jar RunSelfTest "$RESTCHAIN_API" || { exitcode=1; echo '>>> FAIL'; } && echo '>>> OK'

echo '>>> Testing Checker'
if [ -z "${CTF_GAMESERVER_CHECKOUT+x}" ]; then
	echo '>>> skipping because not running in CI'
else
	first=$(date +"%s")
	data=$(mktemp -d)
	BASEDIR=$(dirname "$(readlink -f "$0/..")")
	export PYTHONPATH="$CTF_GAMESERVER_CHECKOUT/src:$BASEDIR/checker"
	for i in {1..10}; do
		echo ">> Tick $i"
		"$CTF_GAMESERVER_CHECKOUT"/checker/ctf-testrunner \
			--first "$first" \
			--backend "$data" \
			--tick $i \
			--ip "$RESTCHAIN_HOST" \
			--team 1 \
			--service 1 \
			restchain.checker:RestchainChecker
		(cd "$data" && grep -Fr '')
	done

	for exploit in "$BASEDIR"/exploits/*/exploit.py; do
		echo ">>> Testing exploit $(basename "$(dirname "$exploit")")"
		for tick in {001..010}; do
			flag_id=$(cat "$data/flagid_$tick.blob")
			echo ">>> Testing tick $tick (flagid $flag_id)"
			exec 42>&1
			"$exploit" "$RESTCHAIN_API" "$flag_id" | tee /proc/self/fd/42 | grep -qE 'FAUST_[A-Za-z0-9/\+]{32}'
			exec 42>&-
		done
	done
fi

exit $exitcode
