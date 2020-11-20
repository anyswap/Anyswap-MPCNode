# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: all mpcnode bootnode cfaucet clean fmt mpcnode-client

all:
	./build.sh mpcnode bootnode mpcnode-client
	cp cmd/conf.toml bin/cmd
	@echo "Done building."

mpcnode:
	./build.sh mpcnode
	@echo "Done building."

bootnode:
	./build.sh bootnode
	@echo "Done building."

mpcnode-client:
	./build.sh mpcnode-client
	@echo "Done building."

cfaucet:
	./build.sh cfaucet
	@echo "Done building."

clean:
	rm -fr bin/cmd/* 

fmt:
	./gofmt.sh
