#!/bin/bash
export GOPATH=`pwd`
go get ./...
go build .
go test -v .
