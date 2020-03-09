# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: all gdcrm bootnode cfaucet clean fmt

all:
	./build.sh gdcrm bootnode
	cp cmd/conf.toml bin/cmd
	@echo "Done building."

gdcrm:
	./build.sh gdcrm
	@echo "Done building."

bootnode:
	./build.sh bootnode
	@echo "Done building."

cfaucet:
	./build.sh cfaucet
	@echo "Done building."

clean:
	rm -fr bin/cmd/* 

fmt:
	./gofmt.sh
