# Introduction
DCRM wallet service is a distributed key generation and distributed signature service that can serve as a distributed custodial solution.

*Note : dcrm-walletService is considered beta software. We make no warranties or guarantees of its security or stability.*

# Prerequisites
1. VPS server with 1 CPU and 2G mem
2. Static public IP
3. Golang ^1.12

# Setting Up
## Clone The Repository
To get started, launch your terminal and download the latest version of the SDK.
```
mkdir -p $GOPATH/src/github.com/fsn-dev

cd $GOPATH/src/github.com/fsn-dev

git clone https://github.com/fsn-dev/dcrm-walletService.git
```
## Build
Next compile the code.  Make sure you are in dcrm-walletService directory.
```
cd dcrm-walletService && make
```

## Run
First generate the node key: 
```
./bin/cmd/gdcrm --genkey node1.key
```

then run the dcrm node 7x24 in the background:
```
nohup ./bin/cmd/gdcrm --nodekey node1.key &
```
The `gdcrm` will provide rpc service, the default RPC port is port 4449.

Note: 
Before use [walletService RPC API](https://github.com/fsn-dev/dcrm-walletService/wiki/walletService-RPC-API), please wait at least 5 minutes after running the node which need to prepare dcrm env.

# Front-end

After running the dcrm wallet rpc service and get the rpc IP:port, we can use [SMPCWallet](https://github.com/fsn-dev/SMPCWallet/releases) to connect the rpc service. This front-end can create distributed custodial account which support BTC/ETH/FSN.


