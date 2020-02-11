/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  gaozhengxin@fusion.org
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the Apache License, Version 2.0.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package config

var defaultConfig string = `
# cosmos gaiad cosmoshub-2
[CosmosGateway]
ApiAddress = "https://stargate.cosmos.network"


# tron shasta testnet api
[TronGateway]
ApiAddress = "https://api.shasta.trongrid.io"


# bitcoind testnet3
[BitcoinGateway]
ElectrsAddress = "http://5.189.139.168:4000"
Host = "47.107.50.83"
Port = 8000
User = "xxmm"
Passwd = "123456"
Usessl = false


# omnid testnet3
[OmniGateway]
Host = "5.189.139.168"
Port = 9772
User = "xxmm"
Passwd = "123456"
Usessl = false


# bitcoincashd testnet
[BitcoincashGateway]
Host = "5.189.139.168"
Port = 9552
User = "xxmm"
Passwd = "123456"
Usessl = false

# fsn testnet
[FusionGateway]
ApiAddress = "https://testnet.fsn.dev/api"

# geth rinkeby testnet
[EthereumGateway]
ApiAddress = "http://5.189.139.168:8018"
#ApiAddress = "http://54.183.185.30:8018"


# eos kylincrypto testnet api
[EosGateway]
#Nodeos = "https://api.kylin.alohaeos.com" # eos api nodes support get actions (filter-on=*)
Nodeos = "https://api-kylin.eoslaomao.com" # eos api nodes support get actions (filter-on=*)
ChainID = "5fff1dae8dc8e2fc4d5b23b2c7665c97f9e9d8edf2b6485a86ba311c25639191"
BalanceTracker = "http://127.0.0.1:7000/"

# evt testnet api
[EvtGateway]
ApiAddress = "https://testnet1.everitoken.io"

# ripple testnet api
[RippleGateway]
ApiAddress = "https://s.altnet.rippletest.net:51234"
`
