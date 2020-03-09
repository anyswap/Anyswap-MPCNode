#!/bin/bash

find_files() {
  find . ! \( \
      \( \
        -path '*/.git/*' \
        -path '*/.github/*' \
        -o -path '*/vendor/*' \
      \) -prune \
    \) -name '*.go'
}

GOFMT="gofmt -s -w"
GOIMPORTS="goimports -w"
find_files | xargs $GOFMT
find_files | xargs $GOIMPORTS

#/* vim: set ts=4 sts=4 sw=4 et : */
