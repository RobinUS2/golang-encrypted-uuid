#!/bin/bash
export GOPATH=`pwd`

function mytest {
    "$@"
    local status=$?
    if [ $status -ne 0 ]; then
        echo "error with $@" >&2
	exit $status
    fi
    return $status
}

go get ./...
mytest go build .
mytest go test -race -v .
mytest go test -bench=.
