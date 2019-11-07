## Clone The Repository
mkdir -p $GOPATH/src/github.com/fsn-dev

cd $GOPATH/src/github.com/fsn-dev

git clone https://github.com/zhaojun-sh/dcrm5-libcoins.git 

mv dcrm5-libcoins dcrm-sdk

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

1. `String|HexNumber|TAG`, - coin type,include "ALL".

##### Return

`Account` - user account.

`PubKey` - dcrm pubkey.

`Address` - coins dcrm address.

##### Example

// Request

curl -X POST -H "Content-Type":application/json --data '{"jsonrpc":"2.0","method":"dcrm_reqDcrmAddr","params":["ALL"],"id":67}' http://127.0.0.1:5559

// Result

{"jsonrpc":"2.0","id":67,"result":"{\"Account\":\"\",\"PubKey\":\"049c1c8934b136e94f283caaa1a8d02d4c4c14eac3d41d405ec6062ae50c802a1c24a33b6334a2af274a6677c6c84b6fddfa056e466a588b322220ab937d002fb9\",\"Address\":{\"ATOM\":\"cosmos13uazqef8wrp8pz896m7w7kmw0ldhcxxknkn3xw\",\"BCH\":\"qz8n5gr9yacvyuyguht0em6mdelaklqc6cwcgp9ccn\",\"BEP2GZX_754\":\"tbnb13uazqef8wrp8pz896m7w7kmw0ldhcxxkl89e83\",\"BNB\":\"tbnb13uazqef8wrp8pz896m7w7kmw0ldhcxxkl89e83\",\"BTC\":\"mtaGZBuRtyFc2uU1ia8VFUXCLpVukNJL2V\",\"EOS\":\"dnp2lykzbzhusjnenjelg12sx45qhtppl2\",\"ERC20BNB\":\"0x843C40B78063a62119E1682B7c6F964e634c00a0\",\"ERC20GUSD\":\"0x843C40B78063a62119E1682B7c6F964e634c00a0\",\"ERC20HT\":\"0x843C40B78063a62119E1682B7c6F964e634c00a0\",\"ERC20MKR\":\"0x843C40B78063a62119E1682B7c6F964e634c00a0\",\"ERC20RMBT\":\"0x843C40B78063a62119E1682B7c6F964e634c00a0\",\"ETH\":\"0x843C40B78063a62119E1682B7c6F964e634c00a0\",\"EVT1\":\"EVT81zBrfNwvG9nPUGGu3x9Eppz5oGvM1xckqoXC3jSP8L1wUEqLc\",\"EVT1001\":\"EVT81zBrfNwvG9nPUGGu3x9Eppz5oGvM1xckqoXC3jSP8L1wUEqLc\",\"TRX\":\"41843c40b78063a62119e1682b7c6f964e634c00a0\",\"USDT\":\"mtaGZBuRtyFc2uU1ia8VFUXCLpVukNJL2V\",\"XRP\":\"rpzvrabbQc7ZPYqTs8EdAa6QuPR9KArLV2\"}}"}

#### dcrm_sign

dcrm sign.

##### Parameters

1. `DATA`,pubkey - the pubkey from dcrm_genPubkey request.
2. `String|HexNumber|TAG`, - coin type.
3. `String|HexNumber|TAG`, - value to lockout,use smallest unit.
4. `String|HexNumber|TAG`, - the address lockout to.

##### Return

`result` - tx hash.

##### Example

// Request

curl -X POST -H "Content-Type":application/json --data '{"jsonrpc":"2.0","method":"dcrm_lockOut","params":["049c1c8934b136e94f283caaa1a8d02d4c4c14eac3d41d405ec6062ae50c802a1c24a33b6334a2af274a6677c6c84b6fddfa056e466a588b322220ab937d002fb9","ETH","1000","0xd92c6581cb000367c10a1997070ccd870287f2da"],"id":67}' http://127.0.0.1:5559

// Result

{"jsonrpc":"2.0","id":67,"result":"0xb8725b174243fb1b7baedf96f85e409f9ad47181d59eb062c126016bad5f4255"}

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

