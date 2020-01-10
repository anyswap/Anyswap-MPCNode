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

package eos
import (
	eos "github.com/eoscanada/eos-go"

	"github.com/fsn-dev/dcrm-walletService/coins/config"
)

func EOSConfigInit() {
	nodeos = config.ApiGateways.EosGateway.Nodeos
	opts = &eos.TxOptions{
		ChainID: hexToChecksum256(config.ApiGateways.EosGateway.ChainID),
		MaxNetUsageWords: uint32(999),
		//DelaySecs: uint32(120),
		MaxCPUUsageMS: uint8(200),
		Compress: eos.CompressionNone,
	}
	BALANCE_SERVER = config.ApiGateways.EosGateway.BalanceTracker
}

var (
	//nodeos = config.EOS_NODEOS
	//nodeos = config.ApiGateways.EosGateway.Nodeos
	nodeos string

	/*opts = &eos.TxOptions{
		ChainID: hexToChecksum256(config.ApiGateways.EosGateway.ChainID),
		MaxNetUsageWords: uint32(999),
		//DelaySecs: uint32(120),
		MaxCPUUsageMS: uint8(200),
		Compress: eos.CompressionNone,
	}*/
	opts *eos.TxOptions
)

const CREATOR_ACCOUNT = "gzx123454321"

const CREATOR_PRIVKEY = "5JqBVZS4shWHBhcht6bn3ecWDoZXPk3TRSVpsLriQz5J3BKZtqH"

const ALPHABET = "defghijklmnopqrstuvwxyz12345abcdefghijklmnopqrstuvwxyz12345abc"

//var BALANCE_SERVER = config.ApiGateways.EosGateway.BalanceTracker

var BALANCE_SERVER string

var InitialRam = uint32(5000)

var InitialCPU = int64(1000)

var InitialStakeNet = int64(1000)




