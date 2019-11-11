## Clone The Repository
mkdir -p $GOPATH/src/github.com/fsn-dev

cd $GOPATH/src/github.com/fsn-dev

git clone https://github.com/zhaojun-sh/dcrm5-libcoins.git 

cd dcrm5-libcoins

## Build

make

## Run

./bin/cmd/gdcrm

## JSON RPC API

Default rpc port: 4449

#### dcrm_reqDcrmAddr

generate dcrm pubkey and dcrm address by coin type.

##### Parameters

1. `String|HexNumber|TAG`, - fusion account.
2. `String|HexNumber|TAG`, - coin type,include "ALL".

##### Return

`Account` - user account.

`PubKey` - dcrm pubkey.

`Address` - coins dcrm address.

##### Example

// Request

curl -X POST -H "Content-Type":application/json --data '{"jsonrpc":"2.0","method":"dcrm_reqDcrmAddr","params":["0x3a1b3b81ed061581558a81f11d63e03129347437","ALL"],"id":67}' http://127.0.0.1:4449

// Result

{"jsonrpc":"2.0","id":67,"result":"{\"Account\":\"0x3a1b3b81ed061581558a81f11d63e03129347437\",\"PubKey\":\"0479ba0f7b660c91e102de6ff4a5593007aad74020ec4cfdd36babf32dc3e049ad53e7ca9ad6685c4f0d1ad9623b2122cff873f26afcb7cc4bbb883be0b985d7f8\",\"Address\":{\"ATOM\":\"cosmos1jxyqvgr5x7ej2gkjetv56a0dvq5avzqfyklzkz\",\"BCH\":\"qzgcsp3qwsmmxffz6t9djnt4a4szn4sgpy9nt9caam\",\"BEP2GZX_754\":\"tbnb1jxyqvgr5x7ej2gkjetv56a0dvq5avzqfg8f2ha\",\"BNB\":\"tbnb1jxyqvgr5x7ej2gkjetv56a0dvq5avzqfg8f2ha\",\"BTC\":\"mtnTDyg8U7MSte2371dYg5SDrYzZfqZGSs\",\"EOS\":\"dwkjqutesmwhy44zkmx4jx3icuqkolxovs\",\"ERC20BNB\":\"0xBe46691BEeEAfC302c11bD2F2C306c31d8d1905c\",\"ERC20GUSD\":\"0xBe46691BEeEAfC302c11bD2F2C306c31d8d1905c\",\"ERC20HT\":\"0xBe46691BEeEAfC302c11bD2F2C306c31d8d1905c\",\"ERC20MKR\":\"0xBe46691BEeEAfC302c11bD2F2C306c31d8d1905c\",\"ERC20RMBT\":\"0xBe46691BEeEAfC302c11bD2F2C306c31d8d1905c\",\"ETH\":\"0xBe46691BEeEAfC302c11bD2F2C306c31d8d1905c\",\"EVT1\":\"EVT5p6hdZL6bgdDwphH3vR6LQfgD4CCnnNh6M7qBUaPxz3sHTgkT2\",\"EVT1001\":\"EVT5p6hdZL6bgdDwphH3vR6LQfgD4CCnnNh6M7qBUaPxz3sHTgkT2\",\"TRX\":\"41be46691beeeafc302c11bd2f2c306c31d8d1905c\",\"USDT\":\"mtnTDyg8U7MSte2371dYg5SDrYzZfqZGSs\",\"XRP\":\"rNGVvvb9CnvUfXYRPSCwiwDtzZPiFG8zZz\"}}"}

#### dcrm_getNonce

get nonce by fusion account and cointype.

#### Parameters

1. `String|HexNumber|TAG`, - fusion account.
2. `String|HexNumber|TAG`, - coin type,not include "ALL".

#### Return

`result` - the nonce value.

#### Example

// Request

curl -X POST -H "Content-Type":application/json --data '{"jsonrpc":"2.0","method":"dcrm_getNonce","params":["0x3a1b3b81ed061581558a81f11d63e03129347437","ETH"],"id":67}' http://127.0.0.1:4449

// Result

{"jsonrpc":"2.0","id":67,"result":"0"}

#### dcrm_getBalance

get balance by fusion account and cointype.

#### Parameters

1. `String|HexNumber|TAG`, - fusion account.
2. `String|HexNumber|TAG`, - coin type,not include "ALL".

#### Return

`result` - the balance.

#### Example

// Request

curl -X POST -H "Content-Type":application/json --data '{"jsonrpc":"2.0","method":"dcrm_getBalance","params":["0x3a1b3b81ed061581558a81f11d63e03129347437","ETH"],"id":67}' http://127.0.0.1:4449

// Result

{"jsonrpc":"2.0","id":67,"result":"0"}

#### dcrm_lockOut

dcrm lockout.

##### Parameters

1. `String|HexNumber|TAG`, - the raw transaction data string.

##### Return

`result` - tx hash.

##### Example

// Request

curl -X POST -H "Content-Type":application/json --data '{"jsonrpc":"2.0","method":"dcrm_lockOut","params":["0xf89d80830f4240830f42409400000000000000000000000000000000000000dc80b8394c4f434b4f55543a3078303036363534414165323733393466304337386432633634324562343663323842333637626336463a31303a4554481ca03364040de4205d5fae08bd34e462994c9d72b105edb3c6a903345c3700aa241da01f54f1ff5784e204025e222338218eb03e65fbf5bb801ee4ad978c688c9f8a12"],"id":67}' http://127.0.0.1:4449

// Result

{"jsonrpc":"2.0","id":67,"result":{"TxHash":"0xb8725b174243fb1b7baedf96f85e409f9ad47181d59eb062c126016bad5f4255"}}

## Run Local

#### Run bootnode
./bin/cmd/bootnode --genkey ./bootnode.key

./bin/cmd/bootnode --nodekey ./bootnode.key --addr :4440 --group 0

will print bootnode which use for run node with args --bootnodes
bootnode key such as enode://16ab118525ec559dde2640b513676b8df7368aac3a80cc5c9d9e8b9c71781c09103fe3e8b5dd17bf245f0c71b891ec4848b142852763ab2146a1e288df15da40@[::]:4440

##### Run nodes (3 nodes at least)
INFO: if want reboot node, please wait 1 minute to run node after close node

without args:

./bin/cmd/gdcrm

(default: --nodekey ~/node.key --rpcport 4449 --port 4441 --bootnodes "enode://aad98f8284b99d2438516c37d3d2d5d9b29a259d8ce8fe38eff303c8cac9eb002699d23d276951e77e123f47522b978ad419c0e418a7109aa40cf600bd07d6ac@47.107.50.83:4440")

with args,for example:

./bin/cmd/gdcrm --rpcport 9012 --bootnodes "enode://aad98f8284b99d2438516c37d3d2d5d9b29a259d8ce8fe38eff303c8cac9eb002699d23d276951e77e123f47522b978ad419c0e418a7109aa40cf600bd07d6ac@47.107.50.83:4440" --port 12341 --nodekey "node1.key"

