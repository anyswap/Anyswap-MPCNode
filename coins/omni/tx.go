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

package omni

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

type RpcResult struct {
	Result OmniTx `json:"result"`
	Error  string `json:"error"`
}

type OmniTx struct {
	Confirmations int64  `json:"confirmations"`
	Fee           string `json:"fee"`
	Valid         bool   `json:"valid"`
	From          string `json:"sendingaddress"`
	To            string `json:"referenceaddress"`
	AmountString  string `json:"amount"`
	Amount        *big.Int
	Type          string  `json:"type"`
	PropertyName  string  `json:"propertyname"`
	PropertyId    float64 `json:"propertyid"`
	Error         error
}

func DecodeOmniTx(ret string) *OmniTx {
	var res = new(RpcResult)
	json.Unmarshal([]byte(ret), res)
	omnitx := res.Result
	if res.Error != "" {
		omnitx.Error = fmt.Errorf(res.Error)
	}
	s := strings.Replace(omnitx.AmountString, ".", "", -1)
	omnitx.Amount, _ = new(big.Int).SetString(s, 10)
	omnitx.PropertyName = "OMNI" + omnitx.PropertyName
	return &omnitx
}
