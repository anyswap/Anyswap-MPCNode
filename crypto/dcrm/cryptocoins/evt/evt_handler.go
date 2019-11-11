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

package evt

import (
	"fmt"
	"math/big"
	"encoding/hex"
	"encoding/json"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
	"github.com/fsn-dev/dcrm5-libcoins/crypto/dcrm/cryptocoins/eos"
	"github.com/fsn-dev/dcrm5-libcoins/crypto/dcrm/cryptocoins/types"
	"github.com/fsn-dev/dcrm5-libcoins/crypto/dcrm/cryptocoins/config"
	"github.com/btcsuite/btcd/btcec"
	//"github.com/ellsol/evt/ecc"
	//"github.com/ellsol/evt/evtapi/client"
	//"github.com/ellsol/evt/evtapi/v1/evt"
	//"github.com/ellsol/evt/evtapi/v1/chain"
	//"github.com/ellsol/evt/evtapi/v1/history"
	//"github.com/ellsol/evt/evtconfig"
	//"github.com/ellsol/evt/evttypes"


	"github.com/fsn-dev/dcrm5-libcoins/external/evt/ecc"
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evtapi/client"
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evtapi/v1/evt"
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evtapi/v1/chain"
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evtapi/v1/history"
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evtconfig"
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evttypes"
	"github.com/sirupsen/logrus"
)

type Authorizers struct {
	Ref    string `json:"ref"`
	Weight int    `json:"weight"`
}

type ActionType struct {
	Name        string        `json:"name"`
	Threshold   int           `json:"threshold"`
	Authorizers []Authorizers `json:"authorizers"`
}

type Args struct {
	Name        string         `json:"name,omitempty"`
	Creator     string         `json:"creator,omitempty"`
	Issue       ActionType     `json:"issue,omitempty"`
	Transfer    ActionType     `json:"transfer,omitempty"`
	Manage      ActionType     `json:"manage,omitempty"`
	TotalSupply int64          `json:"total_supply,omitempty"`
	From        string         `json:"from,omitempty"`
	To          string         `json:"to,omitempty"`
	Number      string         `json:"number,omitempty"`
	Memo        string         `json:"memo,omitempty"`
}

func EVTInit() {
}

type EvtHandler struct {
	TokenId uint
}

// 只支持fungible token
// EVT币是id=1的token, 用EVT1表示, 其他token表示成EVTid, 比如: EVT2, EVT3
func NewEvtHandler (tokenId string) *EvtHandler {
	tid, err := strconv.Atoi(strings.TrimPrefix(tokenId,"EVT"))
	if err != nil {
		return nil
	}
	return &EvtHandler{
		TokenId: uint(tid),
	}
}

// EVT地址就是EVT格式的pubkey
func (h *EvtHandler) PublicKeyToAddress(pubKeyHex string) (address string, err error){
	pk, err := HexToPubKey(pubKeyHex)
	if err != nil {
		return
	}
	address = pk.String()
	return
}

func (h *EvtHandler) BuildUnsignedTransaction(fromAddress, fromPublicKey, toAddress string, amount *big.Int, jsonstring string) (transaction interface{}, digests []string, err error) {

	key := strconv.Itoa(int(h.TokenId))
	number := makeEVTFTNumber(amount, key)
	//number := "0.00010 S#1"

	// 1. abi_json_to_bin https://www.everitoken.io/developers/apis,_sdks_and_tools/abi_reference
	args := chain.Args{
		Transfer:chain.ActionType{
			Name:"transfer",
			Threshold:1,
			Authorizers:[]chain.Authorizers{chain.Authorizers{Ref:"[A] "+fromAddress,Weight:1}},
		},
		From:fromAddress,
		To:toAddress,
		Number:number,
		Memo:"this is a dcrm lockout (^_^)",
	}
	actarg := chain.ActionArguments{
		Action:"transferft",
		Args:args,
	}
	bb, _ := json.Marshal(actarg)
	fmt.Printf("\n%+v\n",string(bb))

	evtcfg := evtconfig.New(config.ApiGateways.EvtGateway.ApiAddress)
	//evtcfg := evtconfig.New("https://testnet1.everitoken.io")
	clt := client.New(evtcfg, logrus.New())
	apichain := chain.New(evtcfg, clt)

	res, apierr := apichain.AbiJsonToBin(&actarg)
	if apierr != nil {
		err = apierr.Error()
		return
	}

	// 2. evttypes.Trxjson
	action := evttypes.Action{
		Name:"transferft",
		Domain:".fungible",
		Key:key,
	}
	trx := &evttypes.TRXJson{
		MaxCharge: 10000,
		Actions: []evttypes.SimpleAction{evttypes.SimpleAction{Action:action,Data:res.Binargs}},
		Payer: fromAddress,
		TransactionExtensions: make([]interface{},0),
	}

	// 3. chain/trx_json_to_digest expiration??? ref_block_num??? ref_block_prefix??? ...
	layout := "2006-01-02T15:04:05"

	res2, apierr := apichain.GetInfo()
	if apierr != nil {
		err = apierr.Error()
		return
	}
	fmt.Printf("\n\ncnm\ngetinfo result\n%+v\nmsln\n\n",res2)

	headtime, _ := time.Parse(layout,res2.HeadBlockTime)
	exptime := headtime.Add(time.Duration(60)*time.Minute)

	trx.Expiration = exptime.Format(layout)

	trx.RefBlockNum = res2.LastIrreversibleBlockNum
	//trx.RefBlockNum = res2.HeadBlockNum

	res3, apierr := apichain.GetBlock (strconv.Itoa(trx.RefBlockNum))
	if apierr != nil {
		err = apierr.Error()
		return
	}
	trx.RefBlockPrefix = res3.RefBlockPrefix

	b, _ := json.Marshal(trx)
	fmt.Printf("\ncnm\ntrx is \n%+v\n\n%v\nnmsl\n\n",trx,string(b))

	// 4. TRXJsonToDigest
	res4, apierr := apichain.TRXJsonToDigest(trx)
	if apierr != nil {
		err = apierr.Error()
		return
	}
	fmt.Printf("\ncnm\nnmsl\nres is \n%+v\n\n",res4)

	trx.Id = res4.Id

	transaction = trx
	digests = append(digests,res4.Digest)
	fmt.Println("EVT Unsigned Transaction Is Conformed")
	return
}

func (h *EvtHandler) MakeSignedTransaction(rsv []string, transaction interface{}) (signedTransaction interface{}, err error) {
	fmt.Println("======== EVT Make Signed Transaction ========")
	sig, err := eos.RSVToSignature(rsv[0])
	if err != nil {
		return
	}
	// evttypes.SignedTRXJson
	signedTransaction = &evttypes.SignedTRXJson{
		Signatures: []string{sig.String()},
		Compression: "none",
		Transaction: transaction.(*evttypes.TRXJson),
	}
	return
}

func (h *EvtHandler) SubmitTransaction(signedTransaction interface{}) (txhash string, err error) {
        txhash = signedTransaction.(*evttypes.SignedTRXJson).Transaction.Id

	fmt.Println("======== EVT Submit Transaction ========")
	// chain/push_transaction
	evtcfg := evtconfig.New(config.ApiGateways.EvtGateway.ApiAddress)
	//evtcfg := evtconfig.New("https://testnet1.everitoken.io")
	clt := client.New(evtcfg, logrus.New())
	apichain := chain.New(evtcfg, clt)
	b, _ := json.Marshal(signedTransaction)
	fmt.Println(string(b))
	res, apierr := apichain.PushTransaction(signedTransaction.(*evttypes.SignedTRXJson))
	if apierr != nil {
		err = apierr.Error()
		return
	}
	txhash = res.TransactionId
	return
}

func (h *EvtHandler) GetTransactionInfo(txhash string) (fromAddress string, txOutputs []types.TxOutput, jsonstring string, confirmed bool, fee types.Value, err error) {
	defer func () {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	} ()

	fee = h.GetDefaultFee()
	// TODO 获取真实fee
	// EVT1 transfer 不消耗手续费?

	//log.Debug("Evt.GetTransactionInfo","config.ApiGateways",config.ApiGateways,"config.ApiGateways.EVTGateway",config.ApiGateways.EVTGateway,"config.ApiGateways.EVTGateway.ApiAddress",config.ApiGateways.EVTGateway.ApiAddress)
	evtcfg := evtconfig.New(config.ApiGateways.EvtGateway.ApiAddress)
	//evtcfg := evtconfig.New("https://testnet1.everitoken.io")
	clt := client.New(evtcfg, logrus.New())
	apihistory := history.New(evtcfg, clt)
	res, apierr := apihistory.GetTransaction(txhash)
	if apierr != nil {
		err = apierr.Error()
		return
	}
	confirmed = true
	fromAddress = res.InnerTransaction.Payer
	actions := res.InnerTransaction.Actions
	var transfer *chain.Action
	for _, act := range actions {
		if act.Name == "transferft" || act.Name == "issuefungible" {
			transfer = &act
			txout, err := parseAction(h.TokenId, transfer)
			if err != nil {
				continue
			}
			txOutputs = append(txOutputs, *txout)
		}
	}
	return
}

func parseAction (tarid uint, transfer *chain.Action) (*types.TxOutput, error) {
	if transfer.Name == "transferft" {
		tmp := strings.Split(transfer.Data.Number,"#")[1]
		symid, _ := strconv.Atoi(tmp)
		if uint(symid) != tarid {
			return nil, fmt.Errorf("sym id is %v, want %v", symid, tarid)
		}
		amtstr := strings.Replace(strings.Split(transfer.Data.Number," ")[0],".","",-1)
		fmt.Printf("amtstr is %s\n", amtstr)
		amt, ok := new(big.Int).SetString(amtstr, 10)
		if !ok {
			err := fmt.Errorf("transfer amount error: %s", transfer.Data.Number)
			return nil, err
		}
		txout := &types.TxOutput{ToAddress:transfer.Data.To,Amount:amt}
		fmt.Printf("txout is %+v\n", txout)
		return txout, nil
	}
	if transfer.Name == "issuefungible" {
		amtstr := strings.Replace(strings.Split(transfer.Data.Number," ")[0],".","",-1)
                amt, ok := new(big.Int).SetString(amtstr, 10)
                if !ok {
			err := fmt.Errorf("transfer amount error: %s", transfer.Data.Number)
                        return nil, err
                }
		txout := &types.TxOutput{ToAddress:transfer.Data.Address,Amount:amt}
		return txout, nil
	}
	return nil, fmt.Errorf("evt parse action: unknown error.")
}

func (h *EvtHandler) GetAddressBalance(address string, jsonstring string) (balance types.Balance, err error) {
	defer func () {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	} ()

	evtcfg := evtconfig.New(config.ApiGateways.EvtGateway.ApiAddress)
	//evtcfg := evtconfig.New("https://testnet1.everitoken.io")
	clt := client.New(evtcfg, logrus.New())
	apievt := evt.New(evtcfg, clt)
	res, apierr := apievt.GetFungibleBalance(h.TokenId, address)
	if apierr != nil {
		err = apierr.Error()
		return
	}
	amtstr := strings.Replace(strings.Split((*res)[0]," ")[0],".","",-1)
	bal, ok := new(big.Int).SetString(amtstr, 10)
	if !ok {
		err = fmt.Errorf("balance amount error: %s", (*res)[0])
		return
	}
	balance.TokenBalance.Cointype = "EVT" + strconv.Itoa(int(h.TokenId))
	balance.TokenBalance.Val = bal

	if h.TokenId == uint(1) {
		// EVT1
		balance.CoinBalance = balance.TokenBalance
	} else {
		// other EVT tokens
		balance.CoinBalance.Cointype = "EVT1"
		res1, apierr1 := apievt.GetFungibleBalance(uint(1), address)
		if apierr1 != nil {
			err = apierr.Error()
			return
		}
		amtstr1 := strings.Replace(strings.Split((*res1)[0]," ")[0],".","",-1)
		bal1, ok := new(big.Int).SetString(amtstr1, 10)
		if !ok {
			err = fmt.Errorf("balance amount error: %s", (*res1)[0])
			return
		}
		balance.CoinBalance.Val = bal1
	}
	return
}

func (h *EvtHandler) GetDefaultFee () types.Value{
	// TODO EVT链上所有的操作都用EVT1支付手续费
	return types.Value{Cointype:"EVT1",Val:big.NewInt(1)}
}

func (h *EvtHandler) IsToken() bool {
	if h.TokenId == uint(1) {
		// EVT1 算作coin
		return false
	}
	return true
}

func makeEVTFTNumber (amt *big.Int, tokenid string) string {
	return strconv.FormatFloat(float64(amt.Int64()) / 100000, 'f', 5, 64) + " S#" + tokenid
}

func PubKeyToHex(pk string) (pubKeyHex string, _ error) {
	pubKey, err := ecc.NewPublicKey(pk)
	if err != nil {
		return "", err
	}
	pubKeyHex = "0x" + hex.EncodeToString(pubKey.Content)
	return
}

func HexToPubKey(pubKeyHex string) (ecc.PublicKey, error) {
	fmt.Printf("hex is %v\nlen(hex) is %v\n\n", pubKeyHex, len(pubKeyHex))
	if pubKeyHex[:2] == "0x" || pubKeyHex[:2] == "0X" {
		pubKeyHex = pubKeyHex[2:]
	}
	// TODO 判断长度
	if len(pubKeyHex) == 130 {
		uBytes, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			return ecc.PublicKey{}, err
		}
		pubkey, err := btcec.ParsePubKey(uBytes, btcec.S256())
		if err != nil {
			return ecc.PublicKey{}, err
		}
		pubkeyBytes := pubkey.SerializeCompressed()
		pubkeyBytes = append([]byte{0}, pubkeyBytes...)  // byte{0} 表示 curve K1, byte{1} 表示 curve R1
		return ecc.NewPublicKeyFromData(pubkeyBytes)
	}

	if len(pubKeyHex) == 66 {
		pubkeyBytes, _ := hex.DecodeString(pubKeyHex)
		pubkeyBytes = append([]byte{0}, pubkeyBytes...)
		return ecc.NewPublicKeyFromData(pubkeyBytes)
	}

	return ecc.PublicKey{}, fmt.Errorf("unexpected public key length  %v", len(pubKeyHex))
}
