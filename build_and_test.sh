#!/bin/bash
export GOPATH=`pwd`
go get ./...
go build .
go test -v .
go test -bench=.
