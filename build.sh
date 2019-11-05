#!/bin/bash

set -eu

if [ ! -f "build.sh" ]; then
        echo "$0 must be run from the root of the repository."
	    exit 2
	fi

	export GO111MODULE=on
	export GOPROXY=https://goproxy.io

	echo "RUN go mod init"
	go mod init github.com/fsn-dev/dcrm-sdk 2>/dev/null || true

	echo "Run go mod vendor"
	go mod vendor -v

	go build -v -mod=vendor -o bin/cmd/bootnode ./cmd/bootnode/*.go
	go build -v -mod=vendor -o bin/cmd/gdcrm ./cmd/gdcrm/*.go
	
	#/* vim: set ts=4 sts=4 sw=4 et : */

