# everiToken API library for Golang

## Includes 

1. everitoken Api Client 
2. everiToken Wallet
3. Processes for posting actions

## Basic Usage

Create a configuration and the evt instance

    config := evtconfig.New(httpPath)
    evtinstance := evt.New(config)
    result, err := evtinstance.Api.V1.Chain.GetInfo()
 
## Create a wallet

    privateKey, err := ecc.NewRandomPrivateKey()
    
and to save and load it use (no encryption enforced yet)

    privateKey.Save("some_wallet_file")
    
    privateKey, err := ecc.LoadPrivateKey("some_wallet_file")
    
## EVT Actions

* [Fungible](docs/fungibile.md)
 

## Api methods supported (so far...)

### Chain

- [x] [chain/get_info](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US) 
- [x] [chain/get_head_block_header_state](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US) 
- [x] [chain/abi_json_to_bin](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US) 
- [x] [chain/trx_json_to_digest](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US) 
- [ ] [chain/get_required_keys](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US) 
- [x] [chain/push_transaction](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US) 
- [ ] [chain/get_suspend_required_keys](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US)  
- [x] [chain/get_block](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US) 
- [ ] [chain/get_charge](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US) 
- [x] [chain/get_block_header_state](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US) 
- [x] [chain/get_transaction](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US) 
- [x] [chain/get_trx_id_for_link_id](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US)
- [x] [chain/get_transaction_ids_for_block](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US)

### Evt_Link

- [x] [evt_link/get_trx_id_for_link_id](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US)

### Evt

- [x] [evt/get_domain](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US)
- [x] [evt/get_group](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US)
- [x] [evt/get_token](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US)
- [x] [evt/get_tokens](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US)
- [x] [evt/get_fungible](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US)
- [x] [evt/get_fungible_balance](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US)
- [x] [evt/get_suspend](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US) 
 

### History

- [ ] [history/get_tokens](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US)
- [ ] [history/get_domains](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US)
- [ ] [history/get_groups](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US)
- [ ] [history/get_fungibles](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US)
- [ ] [history/get_actions](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US)
- [ ] [history/get_fungible_actions](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US)
- [ ] [history/get_transaction](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US)
- [x] [history/get_transactions](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US)
- [x] [history/get_transaction_actions](https://www.everitoken.io/developers/apis,_sdks_and_tools/api_reference/en_US)
