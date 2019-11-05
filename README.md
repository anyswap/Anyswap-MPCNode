## Clone The Repository
mkdir -p $GOPATH/src/github.com/fsn-dev

cd $GOPATH/src/github.com/fsn-dev

git clone https://github.com/fsn-dev/dcrm-sdk.git

cd dcrm-sdk

## Build

make

## Run

./bin/cmd/gdcrm

## JSON RPC API

Default rpc port: 5559

#### dcrm_genPubkey

generate dcrm pubkey.

##### Parameters

none

##### Return

`error` - error info.

`pubkey` - dcrm pubkey.

##### Example

// Request

curl -X POST -H "Content-Type":application/json --data '{"jsonrpc":"2.0","method":"dcrm_genPubkey","params":[],"id":67}' http://127.0.0.1:5559

// Result

{
"error":"",
"pubkey":"049ac626ee0f0f79a49d6ed37f14ff2ad4e4f45fddf6e5293bcaa6a607e5392b49dde27a8f0602e23bc5fa0b847bd28d46e2f2d1d0d8cf59514785e4276b28de9d"
}

#### dcrm_sign

dcrm sign.

##### Parameters

1. `DATA`,pubkey - the pubkey from dcrm_genPubkey request.
2. `String|HexNumber|TAG` - the hash want to sign.it must be 16-in-32-byte character sprang at the beginning of 0x,for example,0x19b6236d2e7eb3e925d0c6e8850502c1f04822eb9aa67cb92e5004f7017e5e41.

##### Return

`error` - error info.

`rsv` - signature str.

##### Example

// Request

curl -X POST -H "Content-Type":application/json --data '{"jsonrpc":"2.0","method":"dcrm_sign","params":["049ac626ee0f0f79a49d6ed37f14ff2ad4e4f45fddf6e5293bcaa6a607e5392b49dde27a8f0602e23bc5fa0b847bd28d46e2f2d1d0d8cf59514785e4276b28de9d","0x19b6236d2e7eb3e925d0c6e8850502c1f04822eb9aa67cb92e5004f7017e5e41"],"id":67}' http://127.0.0.1:5559

// Result

{
"error":"",
"rsv":"FFBB398B95ED2ED308B0FE87BC254FFC2C9957742EA05C18A1411C672B74FBDF6FBD6F4915799F2B4186192581D4506039ADEB79C8EB954E779901FDB9575C8301"
}

## Run Local

#### Run bootnode
./bin/cmd/bootnode --genkey ./bootnode.key

./bin/cmd/bootnode --nodekey ./bootnode.key --addr :5550 --group 0

will print bootnode which use for run node with args --bootnodes
bootnode key such as enode://16ab118525ec559dde2640b513676b8df7368aac3a80cc5c9d9e8b9c71781c09103fe3e8b5dd17bf245f0c71b891ec4848b142852763ab2146a1e288df15da40@[::]:5550

##### Run nodes (3 nodes at least)
INFO: if want reboot node, please wait 1 minute to run node after close node

without args:

./bin/cmd/gdcrm

(default: --nodekey ~/node.key --rpcport 5559 --port 5551 --bootnodes "enode://200cb94957955bfa331ce14b72325c39f3eaa6bcfa962308c967390e5722f6fda0f6080781fde6a025a6280fbf23f38ca454e51a6b75ddbc1f9d57593790545a@47.107.50.83:5550")

with args,for example:

./bin/cmd/gdcrm --rpcport 9012 --bootnodes "enode://16ab118525ec559dde2640b513676b8df7368aac3a80cc5c9d9e8b9c71781c09103fe3e8b5dd17bf245f0c71b891ec4848b142852763ab2146a1e288df15da40@192.168.1.104:12340" --port 12341 --nodekey "node1.key"

