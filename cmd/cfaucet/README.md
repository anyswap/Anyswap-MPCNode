## 获取外链测试币
### 使用方式
```
./build/bin/cfaucet -to="0x426B635fD6CdAf5E4e7Bf5B2A2Dd7bc6c7360FBd" -amount="20" -cointype="ERC20GUSD"
```
* `amount`使用最小单位


### cfaucet目前支持币种

币种|简称|网络|cfaucet帐号/地址|其它获取方式
:---:|:---:|:---:|:---|:---
Bitcoin测试币|BTC|Testnet3测试网|mtjq9RmBBDVne7YB4AFHYCZFn3P2AXv9D5|...
Eth测试币|ETH|Rinkeby测试网|0x426B635fD6CdAf5E4e7Bf5B2A2Dd7bc6c7360FBd|...
ERC20测试币|ERC20GUSD<br>ERC20HT<br>ERC20BNB<br>ERC20MKR|Rinkeby测试网|0x7b5Ec4975b5fB2AA06CB60D0187563481bcb6140|...
Ripple测试币|XRP|Ripple测试网|rwLc28nRV7WZiBv6vsHnpxUGAVcj8qpAtE|https://developers.ripple.com/xrp-test-net-faucet.html
TRON测试币|TRX|Shasta测试网|417e5f4552091a69125d5dfcb7b8c2659029395bdf|https://www.trongrid.io/shasta/#request
EOS测试币|EOS|CryptoKylin测试网|gzx123454321|创建免费账号: http://faucet.cryptokylin.io/create_account?new_account_name<br>获得Token: http://faucet.cryptokylin.io/get_token?your_account_name
* 第一次 Lockin `XRP` 至少要发送`100000000 drops = 100 XRP`用于激活账户, Lockout `XRP` 至少要保留`200 drop`
* TRX目前使用16进制格式, 用这个工具把Base58格式转换成16进制: https://tronscan.org/#/tools/tron-convert-tool
* Lockin `EOS` 要向链上设置的主账户发送转账, 把`DCRM EOS`地址写入交易备注, 不能直接向`DCRM EOS`地址转账!



### 获取其它币种测试币
##### USDT
在bitcoin testnet3上给moneyqMan7uh8FqdCA2BV5yZ8qVrc9ikLP打钱打钱, 获得两种测试币
```
propertyname=Omni
propertyid=1

propertyname=Test Omni
propertyid=2
```
目前用`propertyid=1`的测试币作为USDT测试币



##### Everitoken (EVT)
水龙头: `https://www.everitoken.io/testnet/faucet` 获取`sym_id=1`的token  
这种token记作`EVT-1`  

查账户下的交易
```
curl -X POST -d '{"sym_id":1,"addr":"EVT5EbwKfAUyTEpQCX2U4WGf73yUmbTVGjVgrikG3Ve5ufoQyXWYc"}' https://testnet1.everitoken.io/v1/history/get_fungible_actions
```



##### Bitcoin Cash (BCH)
浏览器: https://www.blockchain.com/explorer 选择Bitcoin Cash测试网  
水龙头: https://developer.bitapp.net/faucet/bch



##### Cosmos Atom
目前使用`cosmoshub-2`主网, 没有测试币  
主网浏览器: https://hubble.figment.network/cosmos/chains/cosmoshub-2  

`gaia-13003`测试网的浏览器和水龙头  
https://hubble.figment.network/cosmos/chains/gaia-13003   https://hubble.figment.network/cosmos/chains/gaia-13003/faucet
