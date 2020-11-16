#!/bin/bash

set -eu

if [ ! -f "build.sh" ]; then
        echo "$0 must be run from the root of the repository."
	    exit 2
fi

export GO111MODULE=on
export GOPROXY=https://goproxy.io

for mod in $@; do
    go run build/ci.go install ./cmd/$mod
done

#/* vim: set ts=4 sts=4 sw=4 et : */

