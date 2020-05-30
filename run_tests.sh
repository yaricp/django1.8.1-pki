#!/bin/bash -e

if [[ $# -ge 1 ]]; then
    if [[ $1 != "--38-only" ]]; then
        echo "Unrecognized argument: $1" 1>&2
	exit 1
    fi
    tox -e py38
else
    tox
fi
