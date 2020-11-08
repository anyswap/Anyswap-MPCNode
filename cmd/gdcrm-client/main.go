/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  hezhaojun@fusion.org huangweijun@fusion.org
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

package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/onrik/ethrpc"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec"
)

const (
	KEYFILE      = `{"version":3,"id":"16b5e31c-cd1a-4cdc-87a6-fc4164766698","address":"00c37841378920e2ba5151a5d1e074cf367586c4","crypto":{"ciphertext":"2070bf8491759f01b4f3f4d6d4b2e274f105be8dc01edd1ebce8d7d954eb64bd","cipherparams":{"iv":"03263465543e4631db50ecfc6b75a74f"},"cipher":"aes-128-ctr","kdf":"scrypt","kdfparams":{"dklen":32,"salt":"9c7b6430552524f0bc1b47bed69e34b0595bc29af4d12e65ec966b16af9c2cf6","n":8192,"r":8,"p":1},"mac":"44d1b7106c28711b06cda116205ee741cba90ab3df0776d59c246b876ded0e97"}}`
	DCRM_TO_ADDR = `0x00000000000000000000000000000000000000dc`
	CHAIN_ID     = 30400 //DCRM_walletService  ID
)

var (
	keyfile  *string
	passwd   *string
	url      *string
	cmd      *string
	gid      *string
	ts       *string
	mode     *string
	toAddr   *string
	value    *string
	coin     *string
	fromAddr *string
	memo     *string
	accept   *string
	key      *string
	keyType  *string
	pubkey   *string
	inputcode   *string
	msghash  *string
	enode    *string
	tsgid    *string
	netcfg    *string

	enodesSig  arrayFlags
	nodes      arrayFlags
	hashs      arrayFlags
	subgids      arrayFlags
	contexts      arrayFlags
	keyWrapper *keystore.Key
	signer     types.EIP155Signer
	client     *ethrpc.EthRPC
)

func main() {
	switch *cmd {
	case "EnodeSig":
		// get enode after sign
		enodeSig()
	case "SetGroup":
		// get GID
		setGroup()
	case "REQDCRMADDR":
		// req DCRM account
		reqDcrmAddr()
	case "ACCEPTREQADDR":
		// req condominium account
		acceptReqAddr()
	case "LOCKOUT":
		lockOut()
	case "ACCEPTLOCKOUT":
		// approve condominium account lockout
		acceptLockOut()
	case "SIGN":
		// test sign
		sign()
	case "PRESIGNDATA":
		// test pre sign data
		preGenSignData()
	case "ACCEPTSIGN":
		// approve condominium account sign
		acceptSign()
	case "RESHARE":
		// test reshare
		reshare()
	case "ACCEPTRESHARE":
		// approve condominium account reshare
		acceptReshare()
	case "CREATECONTRACT":
		err := createContract()
		if err != nil {
			fmt.Printf("createContract failed. %v\n", err)
		}
	case "GETDCRMADDR":
	    err := getDcrmAddr()
	    if err != nil {
			fmt.Printf("pubkey = %v, get dcrm addr failed. %v\n", pubkey,err)
	    }
	default:
		fmt.Printf("\nCMD('%v') not support\nSupport cmd: EnodeSig|SetGroup|REQDCRMADDR|ACCEPTREQADDR|LOCKOUT|ACCEPTLOCKOUT|SIGN|PRESIGNDATA|ACCEPTSIGN|RESHARE|ACCEPTRESHARE|CREATECONTRACT|GETDCRMADDR\n", *cmd)
	}
}

func init() {
	keyfile = flag.String("keystore", "", "Keystore file")
	passwd = flag.String("passwd", "111111", "Password")
	url = flag.String("url", "http://127.0.0.1:9011", "Set node RPC URL")
	cmd = flag.String("cmd", "", "EnodeSig|SetGroup|REQDCRMADDR|ACCEPTREQADDR|LOCKOUT|ACCEPTLOCKOUT|SIGN|PRESIGNDATA|ACCEPTSIGN|RESHARE|ACCEPTRESHARE|CREATECONTRACT|GETDCRMADDR")
	gid = flag.String("gid", "", "groupID")
	ts = flag.String("ts", "2/3", "Threshold")
	mode = flag.String("mode", "1", "Mode:private=1/managed=0")
	toAddr = flag.String("to", "0x0520e8e5E08169c4dbc1580Dc9bF56638532773A", "To address")
	value = flag.String("value", "10000000000000000", "lockout value")
	coin = flag.String("coin", "FSN", "Coin type")
	netcfg = flag.String("netcfg", "mainnet", "chain config") //mainnet or testnet
	fromAddr = flag.String("from", "", "From address")
	memo = flag.String("memo", "smpcwallet.com", "Memo")
	accept = flag.String("accept", "AGREE", "AGREE|DISAGREE")
	key = flag.String("key", "", "Accept key")
	keyType = flag.String("keytype", "ECDSA", "ECDSA|ED25519")
	pubkey = flag.String("pubkey", "", "Dcrm pubkey")
	inputcode = flag.String("inputcode", "", "bip32 input code")
	//msghash = flag.String("msghash", "", "msghash=Keccak256(unsignTX)")
	pkey := flag.String("pkey", "", "Private key")
	enode = flag.String("enode", "", "enode")
	tsgid = flag.String("tsgid", "", "Threshold group ID")
	// array
	flag.Var(&enodesSig, "sig", "Enodes Sig list")
	flag.Var(&nodes, "node", "Node rpc url")
	flag.Var(&hashs, "msghash", "unsigned tx hash array")
	flag.Var(&contexts, "msgcontext", "unsigned tx context array")
	flag.Var(&subgids, "subgid", "sub group id array")

	// create contract flags
	flag.StringVar(&nodeChainIDStr, "chainID", nodeChainIDStr, "chain ID of full node")
	flag.StringVar(&gatewayURL, "gateway", gatewayURL, "gateway of full node RPC address")
	flag.Uint64Var(&gasLimit, "gas", gasLimit, "gas limit")
	flag.StringVar(&gasPriceStr, "gasPrice", gasPriceStr, "gas price")
	flag.StringVar(&bytecodeFile, "bytecode", bytecodeFile, "path of bytecode file")
	flag.BoolVar(&dryrun, "dryrun", dryrun, "dry run")

	flag.Parse()

	// To account
	toAccDef := accounts.Account{
		Address: common.HexToAddress(DCRM_TO_ADDR),
	}
	fmt.Println("To address: = ", toAccDef.Address.String())
	var err error
	// decrypt private key
	var keyjson []byte
	if *keyfile != "" {
		keyjson, err = ioutil.ReadFile(*keyfile)
		if err != nil {
			fmt.Println("Read keystore fail", err)
		}
	} else {
		keyjson = []byte(KEYFILE)
	}
	keyWrapper, err = keystore.DecryptKey(keyjson, *passwd)
	if err != nil {
		fmt.Println("Key decrypt error:")
		panic(err)
	}
	if *pkey != "" {
		priKey, err := crypto.HexToECDSA(*pkey)
		if err != nil {
			panic(err)
		}
		keyWrapper.PrivateKey = priKey
	}

	fmt.Printf("Recover from address = %s\n", keyWrapper.Address.String())
	// set signer and chain id
	chainID := big.NewInt(CHAIN_ID)
	signer = types.NewEIP155Signer(chainID)
	// init RPC client
	client = ethrpc.New(*url)
}

func enodeSig() {
	enodeRep, err := client.Call("dcrm_getEnode")
	if err != nil {
		panic(err)
	}
	fmt.Printf("getEnode = %s\n\n", enodeRep)
	var enodeJSON dataEnode
	enodeData, _ := getJSONData(enodeRep)
	if err := json.Unmarshal(enodeData, &enodeJSON); err != nil {
		panic(err)
	}
	fmt.Printf("enode = %s\n", enodeJSON.Enode)
	// get pubkey from enode
	if *enode != "" {
		enodeJSON.Enode = *enode
	}
	s := strings.Split(enodeJSON.Enode, "@")
	enodePubkey := strings.Split(s[0], "//")
	fmt.Printf("enodePubkey = %s\n", enodePubkey[1])
	sig, err := crypto.Sign(crypto.Keccak256([]byte(enodePubkey[1])), keyWrapper.PrivateKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\nenodeSig self = \n%s\n\n", enodeJSON.Enode+common.ToHex(sig))
}

func setGroup() {
	var enodeList []string
	// get enodes from enodesSig by arg -sig
	if len(enodesSig) > 0 {
		enodeList = make([]string, len(enodesSig))
		for i := 0; i < len(enodesSig); i++ {
			s := strings.Split(enodesSig[i], "0x")
			enodeList[i] = s[0]
			fmt.Printf("enode[%d] = %s\n", i, enodeList[i])
		}
		// get enodes from rpc by arg -node
	} else if len(nodes) > 0 {
		enodeList = make([]string, len(nodes))
		for i := 0; i < len(nodes); i++ {
			client := ethrpc.New(nodes[i])
			enodeRep, err := client.Call("dcrm_getEnode")
			if err != nil {
				panic(err)
			}
			var enodeJSON dataEnode
			enodeData, _ := getJSONData(enodeRep)
			if err := json.Unmarshal(enodeData, &enodeJSON); err != nil {
				panic(err)
			}
			enodeList[i] = enodeJSON.Enode
			fmt.Printf("enode[%d] = %s\n", i, enodeList[i])
		}
	}
	// get gid by send createGroup
	groupRep, err := client.Call("dcrm_createGroup", *ts, enodeList)
	if err != nil {
		panic(err)
	}
	fmt.Printf("dcrm_createGroup = %s\n", groupRep)
	var groupJSON groupInfo
	groupData, _ := getJSONData(groupRep)
	if err := json.Unmarshal(groupData, &groupJSON); err != nil {
		panic(err)
	}
	fmt.Printf("\nGid = %s\n\n", groupJSON.Gid)
}
func reqDcrmAddr() {
	// get nonce
	reqAddrNonce, err := client.Call("dcrm_getReqAddrNonce", keyWrapper.Address.String())
	if err != nil {
		panic(err)
	}
	nonceStr, _ := getJSONResult(reqAddrNonce)
	nonce, _ := strconv.ParseUint(nonceStr, 0, 64)
	fmt.Printf("dcrm_getReqAddrNonce = %s\nNonce = %d\n", reqAddrNonce, nonce)
	// build Sigs list parameter
	sigs := ""
	if *mode == "0" {
		for i := 0; i < len(enodesSig)-1; i++ {
			sigs = sigs + enodesSig[i] + "|"
		}
		sigs = sigs + enodesSig[len(enodesSig)-1]
	}
	// build tx data
	timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
	txdata := reqAddrData{
		TxType:    *cmd,
		GroupID:   *gid,
		ThresHold: *ts,
		Mode:      *mode,
		TimeStamp: timestamp,
		Sigs:      sigs,
	}
	playload, _ := json.Marshal(txdata)

	// sign tx
	rawTX, err := signTX(signer, keyWrapper.PrivateKey, nonce, playload)
	if err != nil {
		panic(err)
	}
	// send rawTx
	reqKeyID, err := client.Call("dcrm_reqDcrmAddr", rawTX)
	if err != nil {
		panic(err)
	}
	// get keyID
	keyID, err := getJSONResult(reqKeyID)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\ndcrm_reqDcrmAddr keyID = %s\n\n", keyID)

	fmt.Printf("\nWaiting for stats result...\n")
	// get accounts
	time.Sleep(time.Duration(20) * time.Second)
	accounts, err := client.Call("dcrm_getAccounts", keyWrapper.Address.String(), *mode)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\naddress = %s\naccounts = %s\n\n", keyWrapper.Address.String(), accounts)

	// traverse key from reqAddr failed by keyID
	time.Sleep(time.Duration(2) * time.Second)
	fmt.Printf("\nreqDCRMAddr:User=%s", keyWrapper.Address.String())
	var statusJSON reqAddrStatus
	reqStatus, err := client.Call("dcrm_getReqAddrStatus", keyID)
	if err != nil {
		fmt.Println("\tdcrm_getReqAddrStatus rpc error:", err)
		return
	}
	statusJSONStr, err := getJSONResult(reqStatus)
	if err != nil {
		fmt.Printf("\tdcrm_getReqAddrStatus=NotStart\tkeyID=%s ", keyID)
		fmt.Println("\tRequest not complete:", err)
		return
	}
	if err := json.Unmarshal([]byte(statusJSONStr), &statusJSON); err != nil {
		fmt.Println("\treqDCRMAddr:User=%s\tUnmarshal statusJSONStr fail:", err)
		return
	}
	if statusJSON.Status != "Success" {
		fmt.Printf("\tdcrm_getReqAddrStatus=%s\tkeyID=%s", statusJSON.Status, keyID)
	} else {
		fmt.Printf("\tSuccess\tPubkey=%s\n", statusJSON.PubKey)
	}
}

func acceptReqAddr() {
	// get reqAddr account list
	reqListRep, err := client.Call("dcrm_getCurNodeReqAddrInfo", keyWrapper.Address.String())
	if err != nil {
		panic(err)
	}
	reqListJSON, _ := getJSONData(reqListRep)
	fmt.Printf("dcrm_getCurNodeReqAddrInfo = %s\n", reqListJSON)

	var keyList []reqAddrCurNodeInfo
	if err := json.Unmarshal(reqListJSON, &keyList); err != nil {
		fmt.Println("Unmarshal reqAddrCurNodeInfo fail:", err)
		return
	}

	// gen key list which not approve, auto accept replace input by arg -key
	for i := 0; i < len(keyList); i++ {
		// build tx data
		var keyStr string
		if *key != "" {
			i = len(keyList)
			keyStr = *key
		} else {
			keyStr = keyList[i].Key
		}

		timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
		data := acceptData{
			TxType:    *cmd,
			Key:       keyStr,
			Accept:    *accept,
			TimeStamp: timestamp,
		}
		playload, err := json.Marshal(data)
		if err != nil {
			fmt.Println("error:", err)
		}
		// sign tx
		rawTX, err := signTX(signer, keyWrapper.PrivateKey, 0, playload)
		if err != nil {
			panic(err)
		}
		// send rawTx
		acceptReqAddrRep, err := client.Call("dcrm_acceptReqAddr", rawTX)
		if err != nil {
			panic(err)
		}
		// get result
		acceptRet, err := getJSONResult(acceptReqAddrRep)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\ndcrm_acceptReq result: key[%d]\t%s = %s\n\n", i+1, keyStr, acceptRet)
	}
}

func lockOut() {
	// get lockout nonce
	lockoutNonce, err := client.Call("dcrm_getLockOutNonce", keyWrapper.Address.String())
	if err != nil {
		panic(err)
	}
	nonceStr, err := getJSONResult(lockoutNonce)
	if err != nil {
		panic(err)
	}
	nonce, _ := strconv.ParseUint(nonceStr, 0, 64)
	fmt.Printf("dcrm_getLockOutNonce = %s\nNonce = %d\n", lockoutNonce, nonce)
	// build tx data
	timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
	txdata := lockoutData{
		TxType:    *cmd,
		DcrmAddr:  *fromAddr,
		DcrmTo:    *toAddr,
		Value:     *value,
		Cointype:  *coin,
		GroupID:   *gid,
		ThresHold: *ts,
		Mode:      *mode,
		TimeStamp: timestamp,
		Memo:      *memo,
	}
	playload, _ := json.Marshal(txdata)
	// sign tx
	rawTX, err := signTX(signer, keyWrapper.PrivateKey, nonce, playload)
	if err != nil {
		panic(err)
	}
	// send rawTx
	reqKeyID, err := client.Call("dcrm_lockOut", rawTX)
	if err != nil {
		panic(err)
	}
	// get keyID from result
	keyID, err := getJSONResult(reqKeyID)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\ndcrm_lockOut keyID = %s\n\n", keyID)
	fmt.Printf("\nWaiting for stats result...\n")
	// traverse key from reqAddr failed by keyID
	time.Sleep(time.Duration(30) * time.Second)
	fmt.Printf("\n\nUser=%s\n", keyWrapper.Address.String())
	var statusJSON lockoutStatus
	reqStatus, err := client.Call("dcrm_getLockOutStatus", keyID)
	if err != nil {
		fmt.Println("\ndcrm_getLockOutStatus rpc error:", err)
		return
	}
	statusJSONStr, err := getJSONResult(reqStatus)
	if err != nil {
		fmt.Printf("\tdcrm_getLockOutStatus=NotStart\tkeyID=%s ", keyID)
		fmt.Println("\tRequest not complete:", err)
		return
	}
	if err := json.Unmarshal([]byte(statusJSONStr), &statusJSON); err != nil {
		fmt.Println("\tUnmarshal statusJSONStr fail:", err)
		return
	}
	if statusJSON.Status != "Success" {
		fmt.Printf("\tdcrm_getLockOutStatus=%s\tkeyID=%s  ", statusJSON.Status, keyID)
	} else {
		fmt.Printf("\tSuccess\tOutTXhash=%s", statusJSON.OutTxHash)
	}
}
func acceptLockOut() {
	// get approve list of condominium account
	reqListRep, err := client.Call("dcrm_getCurNodeLockOutInfo", keyWrapper.Address.String())
	if err != nil {
		panic(err)
	}
	reqListJSON, _ := getJSONData(reqListRep)
	fmt.Printf("dcrm_getCurNodeLockOutInfo = %s\n", reqListJSON)

	var keyList []lockoutCurNodeInfo
	if err := json.Unmarshal(reqListJSON, &keyList); err != nil {
		fmt.Println("Unmarshal lockoutCurNodeInfo fail:", err)
		return
	}
	// gen key list which not approve, auto accept replace input by arg -key
	for i := 0; i < len(keyList); i++ {
		// build tx data
		var keyStr string
		if *key != "" {
			i = len(keyList)
			keyStr = *key
		} else {
			keyStr = keyList[i].Key
		}
		timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
		data := acceptData{
			TxType:    *cmd,
			Key:       keyStr,
			Accept:    *accept,
			TimeStamp: timestamp,
		}
		playload, err := json.Marshal(data)
		if err != nil {
			fmt.Println("error:", err)
		}
		// sign tx
		rawTX, err := signTX(signer, keyWrapper.PrivateKey, 0, playload)
		if err != nil {
			panic(err)
		}
		// send rawTx
		acceptLockOutRep, err := client.Call("dcrm_acceptLockOut", rawTX)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\ndcrm_acceptLockOut = %s\n\n", acceptLockOutRep)
		// get result
		acceptRet, err := getJSONResult(acceptLockOutRep)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\ndcrm_acceptLockOut result: key[%d]\t%s = %s\n\n", i+1, keyStr, acceptRet)
	}
}
func sign() {
	//if *msghash == "" {
	//	*msghash = common.ToHex(crypto.Keccak256([]byte(*memo)))
	//}
	if len(hashs) == 0 {
	    hashs = append(hashs,common.ToHex(crypto.Keccak256([]byte(*memo))))
	}

	if len(contexts) == 0 {
	    contexts = append(contexts,*memo)
	}

	signMsgHash(hashs,contexts, -1)
}
func preGenSignData() {
	if len(subgids) == 0 {
	    panic(fmt.Errorf("error:sub group id array is empty"))
	}

	txdata := preSignData{
		TxType:     "PRESIGNDATA",
		PubKey:     *pubkey,
		SubGid:    subgids,
	}
	playload, _ := json.Marshal(txdata)
	// sign tx
	rawTX, err := signTX(signer, keyWrapper.PrivateKey, 0, playload)
	if err != nil {
		panic(err)
	}
	// get rawTx
	_, err = client.Call("dcrm_preGenSignData", rawTX)
	if err != nil {
		panic(err)
	}
}
func signMsgHash(hashs []string, contexts []string,loopCount int) (rsv []string) {
	// get sign nonce
	signNonce, err := client.Call("dcrm_getSignNonce", keyWrapper.Address.String())
	if err != nil {
		panic(err)
	}
	nonceStr, err := getJSONResult(signNonce)
	if err != nil {
		panic(err)
	}
	nonce, _ := strconv.ParseUint(nonceStr, 0, 64)
	fmt.Printf("dcrm_getSignNonce = %s\nNonce = %d\n", signNonce, nonce)
	// build tx data
	timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
	txdata := signData{
		TxType:     "SIGN",
		PubKey:     *pubkey,
		InputCode:     *inputcode,
		MsgContext: contexts,
		MsgHash:    hashs,
		Keytype:    *keyType,
		GroupID:    *gid,
		ThresHold:  *ts,
		Mode:       *mode,
		TimeStamp:  timestamp,
	}
	playload, _ := json.Marshal(txdata)
	// sign tx
	rawTX, err := signTX(signer, keyWrapper.PrivateKey, nonce, playload)
	if err != nil {
		panic(err)
	}
	// get rawTx
	reqKeyID, err := client.Call("dcrm_sign", rawTX)
	if err != nil {
		panic(err)
	}
	// get keyID
	keyID, err := getJSONResult(reqKeyID)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\ndcrm_sign keyID = %s\n\n", keyID)
	for i, j := loopCount, 1; i != 0; j++ {
		fmt.Printf("\nWaiting for stats result (loop %v)...\n", j)
		if i > 0 {
			i--
		}
		// traverse key from reqAddr failed by keyID
		time.Sleep(time.Duration(20) * time.Second)
		fmt.Printf("\n\nUser=%s", keyWrapper.Address.String())
		var statusJSON signStatus
		reqStatus, err := client.Call("dcrm_getSignStatus", keyID)
		if err != nil {
			fmt.Println("\ndcrm_getSignStatus rpc error:", err)
			continue
		}
		statusJSONStr, err := getJSONResult(reqStatus)
		if err != nil {
			fmt.Printf("\tdcrm_getSignStatus=NotStart\tkeyID=%s ", keyID)
			fmt.Println("\tRequest not complete:", err)
			continue
		}
		if err := json.Unmarshal([]byte(statusJSONStr), &statusJSON); err != nil {
			fmt.Println("\tUnmarshal statusJSONStr fail:", err)
			continue
		}
		switch statusJSON.Status {
		case "Timeout", "Failure":
			fmt.Printf("\tdcrm_getSignStatus=%s\tkeyID=%s\n", statusJSON.Status, keyID)
			return
		case "Success":
			fmt.Printf("\tSuccess\tRSV=%s\n", statusJSON.Rsv)
			return statusJSON.Rsv
		default:
			fmt.Printf("\tdcrm_getSignStatus=%s\tkeyID=%s\n", statusJSON.Status, keyID)
			continue
		}
	}
	return
}
func acceptSign() {
	// get approve list of condominium account
	reqListRep, err := client.Call("dcrm_getCurNodeSignInfo", keyWrapper.Address.String())
	if err != nil {
		panic(err)
	}
	reqListJSON, _ := getJSONData(reqListRep)
	fmt.Printf("dcrm_getCurNodeSignInfo = %s\n", reqListJSON)

	var keyList []signCurNodeInfo
	if err := json.Unmarshal(reqListJSON, &keyList); err != nil {
		fmt.Println("Unmarshal signCurNodeInfo fail:", err)
		return
	}
	// gen key list which not approve, auto accept replace input by arg -key
	for i := 0; i < len(keyList); i++ {
		// build tx data
		var keyStr string
		var msgHash []string
		var msgContext []string
		
		if len(hashs) == 0 {
		    hashs = append(hashs,common.ToHex(crypto.Keccak256([]byte(*memo))))
		}

		if len(contexts) == 0 {
		    contexts = append(contexts,*memo)
		}

		if *key != "" {
			i = len(keyList)
			keyStr = *key
			msgHash = hashs
			msgContext = contexts
		} else {
			keyStr = keyList[i].Key
			msgHash = keyList[i].MsgHash
			msgContext = keyList[i].MsgContext
		}
		timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
		data := acceptSignData{
			TxType:     *cmd,
			Key:        keyStr,
			Accept:     *accept,
			MsgHash:    msgHash,
			MsgContext: msgContext,
			TimeStamp:  timestamp,
		}
		playload, err := json.Marshal(data)
		if err != nil {
			fmt.Println("error:", err)
		}
		// sign tx
		rawTX, err := signTX(signer, keyWrapper.PrivateKey, 0, playload)
		if err != nil {
			panic(err)
		}
		// send rawTx
		acceptSignRep, err := client.Call("dcrm_acceptSign", rawTX)
		if err != nil {
			panic(err)
		}
		// get result
		acceptRet, err := getJSONResult(acceptSignRep)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\ndcrm_acceptSign result: key[%d]\t%s = %s\n\n", i+1, keyStr, acceptRet)
	}
}
func reshare() {
	// build tx data
	sigs := ""
	for i := 0; i < len(enodesSig)-1; i++ {
		sigs = sigs + enodesSig[i] + "|"
	}

	sigs = sigs + enodesSig[len(enodesSig)-1]
	timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
	txdata := reshareData{
		TxType:    *cmd,
		PubKey:    *pubkey,
		GroupID:   *gid,
		TSGroupID: *tsgid,
		ThresHold: *ts,
		Account:   keyWrapper.Address.String(),
		Mode:      *mode,
		Sigs:      sigs,
		TimeStamp: timestamp,
	}
	playload, _ := json.Marshal(txdata)
	// sign tx
	rawTX, err := signTX(signer, keyWrapper.PrivateKey, 0, playload)
	if err != nil {
		panic(err)
	}
	// send rawTx
	reqKeyID, err := client.Call("dcrm_reShare", rawTX)
	if err != nil {
		panic(err)
	}
	// get keyID
	keyID, err := getJSONResult(reqKeyID)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\ndcrm_reShare keyID = %s\n\n", keyID)
}
func acceptReshare() {
	// get account reshare approve list
	reqListRep, err := client.Call("dcrm_getCurNodeReShareInfo")
	if err != nil {
		panic(err)
	}
	reqListJSON, _ := getJSONData(reqListRep)
	fmt.Printf("dcrm_getCurNodeReShareInfo = %s\n", reqListJSON)

	var keyList []reshareCurNodeInfo
	if err := json.Unmarshal(reqListJSON, &keyList); err != nil {
		fmt.Println("Unmarshal reshareCurNodeInfo fail:", err)
		return
	}
	// gen key list which not approve, auto accept replace input by arg -key
	for i := 0; i < len(keyList); i++ {
		// build tx data
		var keyStr string
		if *key != "" {
			i = len(keyList)
			keyStr = *key
		} else {
			keyStr = keyList[i].Key
		}
		timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
		data := acceptData{
			TxType:    *cmd,
			Key:       keyStr,
			Accept:    *accept,
			TimeStamp: timestamp,
		}
		playload, err := json.Marshal(data)
		if err != nil {
			fmt.Println("error:", err)
		}
		// sign tx
		rawTX, err := signTX(signer, keyWrapper.PrivateKey, 0, playload)
		if err != nil {
			panic(err)
		}
		// send rawTx
		acceptSignRep, err := client.Call("dcrm_acceptReShare", rawTX)
		if err != nil {
			panic(err)
		}
		// get result
		acceptRet, err := getJSONResult(acceptSignRep)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\ndcrm_acceptReShare result: key[%d]\t%s = %s\n\n", i+1, keyStr, acceptRet)
	}
}

func getDcrmAddr() error {
    if pubkey == nil {
	return fmt.Errorf("pubkey error")
    }

    pub := (*pubkey)

    if pub == "" || (*coin) == "" {
	return fmt.Errorf("pubkey error.")
    }

    if (*coin) != "FSN" && (*coin) != "BTC" { //only btc/fsn tmp
	return fmt.Errorf("coin type unsupported.")
    }

    if len(pub) != 132 && len(pub) != 130 {
	    return fmt.Errorf("invalid public key length")
    }
    if pub[:2] == "0x" || pub[:2] == "0X" {
	    pub = pub[2:]
    }

    if (*coin) == "FSN" {
	pubKeyHex := strings.TrimPrefix(pub, "0x")
	data := hexEncPubkey(pubKeyHex[2:])

	pub2, err := decodePubkey(data)
	if err != nil {
	    return err
	}

	address := crypto.PubkeyToAddress(*pub2).Hex()
	fmt.Printf("\ngetDcrmAddr result: %s\n\n", address)
	return nil
    }
    
    bb, err := hex.DecodeString(pub)
    if err != nil {
	    return err
    }
    pub2, err := btcec.ParsePubKey(bb, btcec.S256())
    if err != nil {
	    return err
    }
    
    ChainConfig := chaincfg.MainNetParams
    if (*netcfg) == "testnet" {
	ChainConfig = chaincfg.TestNet3Params
    }

    b := pub2.SerializeCompressed()
    pkHash := btcutil.Hash160(b)
    addressPubKeyHash, err := btcutil.NewAddressPubKeyHash(pkHash, &ChainConfig)
    if err != nil {
	    return err
    }
    address := addressPubKeyHash.EncodeAddress()
    fmt.Printf("\ngetDcrmAddr result: %s\n\n", address)
    return nil
}

func hexEncPubkey(h string) (ret [64]byte) {
	b, err := hex.DecodeString(h)
	if err != nil {
		//panic(err)
		fmt.Printf("=============== parse pubkey error = %v ==============\n", err)
		return ret
	}
	if len(b) != len(ret) {
		//panic("invalid length")
		fmt.Printf("invalid length\n")
		return ret
	}
	copy(ret[:], b)
	return ret
}

func decodePubkey(e [64]byte) (*ecdsa.PublicKey, error) {
	p := &ecdsa.PublicKey{Curve: crypto.S256(), X: new(big.Int), Y: new(big.Int)}
	half := len(e) / 2
	p.X.SetBytes(e[:half])
	p.Y.SetBytes(e[half:])
	if !p.Curve.IsOnCurve(p.X, p.Y) {
		return nil, errors.New("invalid secp256k1 curve point")
	}
	return p, nil
}

// parse result from rpc return data
func getJSONResult(successResponse json.RawMessage) (string, error) {
	var data dataResult
	repData, err := getJSONData(successResponse)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(repData, &data); err != nil {
		fmt.Println("getJSONResult Unmarshal json fail:", err)
		return "", err
	}
	return data.Result, nil
}

func getJSONData(successResponse json.RawMessage) ([]byte, error) {
	var rep response
	if err := json.Unmarshal(successResponse, &rep); err != nil {
		fmt.Println("getJSONData Unmarshal json fail:", err)
		return nil, err
	}
	if rep.Status != "Success" {
		return nil, errors.New(rep.Error)
	}
	repData, err := json.Marshal(rep.Data)
	if err != nil {
		fmt.Println("getJSONData Marshal json fail:", err)
		return nil, err
	}
	return repData, nil
}

// return: raw hex
func signTX(signer types.EIP155Signer, privatekey *ecdsa.PrivateKey, nonce uint64, playload []byte) (string, error) {
	toAccDef := accounts.Account{
		Address: common.HexToAddress(DCRM_TO_ADDR),
	}
	// build tx
	tx := types.NewTransaction(
		uint64(nonce),     // nonce
		toAccDef.Address,  // to address
		big.NewInt(0),     // value
		100000,            // gasLimit
		big.NewInt(80000), // gasPrice
		playload)          // data
	// sign tx by privatekey
	signature, signatureErr := crypto.Sign(signer.Hash(tx).Bytes(), privatekey)
	if signatureErr != nil {
		fmt.Println("signature create error:")
		panic(signatureErr)
	}
	// build tx with sign
	sigTx, signErr := tx.WithSignature(signer, signature)
	if signErr != nil {
		fmt.Println("signer with signature error:")
		panic(signErr)
	}
	// get raw TX
	txdata, txerr := rlp.EncodeToBytes(sigTx)
	if txerr != nil {
		panic(txerr)
	}
	rawTX := common.ToHex(txdata)
	fmt.Printf("\nSignTx:\nChainId\t\t=%s\nGas\t\t=%d\nGasPrice\t=%s\nNonce\t\t=%d\nToAddr\t\t=%s\nHash\t\t=%s\nData\t\t=%s\n",
		sigTx.ChainId(), sigTx.Gas(), sigTx.GasPrice(), sigTx.Nonce(), sigTx.To().String(), sigTx.Hash().Hex(), sigTx.Data())
	fmt.Printf("RawTransaction = %+v\n", rawTX)
	return rawTX, nil
}

type response struct {
	Status string      `json:"Status"`
	Tip    string      `json:"Tip"`
	Error  string      `json:"Error"`
	Data   interface{} `json:"Data"`
}
type dataResult struct {
	Result string `json:"result"`
}
type dataEnode struct {
	Enode string `json:"Enode"`
}
type groupInfo struct {
	Gid    string      `json:"Gid"`
	Mode   string      `json:"Mode"`
	Count  int         `json:"Count"`
	Enodes interface{} `json:"Enodes"`
}
type reqAddrData struct {
	TxType    string `json:"TxType"`
	GroupID   string `json:"GroupId"`
	ThresHold string `json:"ThresHold"`
	Mode      string `json:"Mode"`
	TimeStamp string `json:"TimeStamp"`
	Sigs      string `json:"Sigs"`
}
type acceptData struct {
	TxType    string `json:"TxType"`
	Key       string `json:"Key"`
	Accept    string `json:"Accept"`
	TimeStamp string `json:"TimeStamp"`
}
type acceptSignData struct {
	TxType     string   `json:"TxType"`
	Key        string   `json:"Key"`
	Accept     string   `json:"Accept"`
	MsgHash    []string `json:"MsgHash"`
	MsgContext []string `json:"MsgContext"`
	TimeStamp  string   `json:"TimeStamp"`
}
type lockoutData struct {
	TxType    string `json:"TxType"`
	DcrmAddr  string `json:"DcrmAddr"`
	DcrmTo    string `json:"DcrmTo"`
	Value     string `json:"Value"`
	Cointype  string `json:"Cointype"`
	GroupID   string `json:"GroupId"`
	ThresHold string `json:"ThresHold"`
	Mode      string `json:"Mode"`
	TimeStamp string `json:"TimeStamp"`
	Memo      string `json:"Memo"`
}
type signData struct {
	TxType     string `json:"TxType"`
	PubKey     string `json:"PubKey"`
	InputCode     string `json:"InputCode"`
	MsgContext []string `json:"MsgContext"`
	MsgHash    []string `json:"MsgHash"`
	Keytype    string `json:"Keytype"`
	GroupID    string `json:"GroupId"`
	ThresHold  string `json:"ThresHold"`
	Mode       string `json:"Mode"`
	TimeStamp  string `json:"TimeStamp"`
}
type preSignData struct {
    TxType string `json:"TxType"`
    PubKey string `json:"PubKey"`
    SubGid []string `json:"SubGid"`
}
type reshareData struct {
	TxType    string `json:"TxType"`
	PubKey    string `json:"PubKey"`
	GroupID   string `json:"GroupId"`
	TSGroupID string `json:"TSGroupId"`
	ThresHold string `json:"ThresHold"`
	Account   string `json:"Account"`
	Mode      string `json:"Mode"`
	Sigs      string `json:"Sigs"`
	TimeStamp string `json:"TimeStamp"`
}
type reqAddrStatus struct {
	Status    string      `json:"Status"`
	PubKey    string      `json:"PubKey"`
	Tip       string      `json:"Tip"`
	Error     string      `json:"Error"`
	AllReply  interface{} `json:"AllReply"`
	TimeStamp string      `json:"TimeStamp"`
}
type lockoutStatus struct {
	Status    string      `json:"Status"`
	OutTxHash string      `json:"OutTxHash"`
	Tip       string      `json:"Tip"`
	Error     string      `json:"Error"`
	AllReply  interface{} `json:"AllReply"`
	TimeStamp string      `json:"TimeStamp"`
}
type signStatus struct {
	Status    string      `json:"Status"`
	Rsv       []string      `json:"Rsv"`
	Tip       string      `json:"Tip"`
	Error     string      `json:"Error"`
	AllReply  interface{} `json:"AllReply"`
	TimeStamp string      `json:"TimeStamp"`
}
type reqAddrCurNodeInfo struct {
	Account   string `json:"Account"`
	Cointype  string `json:"Cointype"`
	GroupID   string `json:"GroupId"`
	Key       string `json:"Key"`
	Mode      string `json:"Mode"`
	Nonce     string `json:"Nonce"`
	ThresHold string `json:"ThresHold"`
	TimeStamp string `json:"TimeStamp"`
}
type lockoutCurNodeInfo struct {
	Account   string `json:"Account"`
	GroupID   string `json:"GroupId"`
	Key       string `json:"Key"`
	Nonce     string `json:"Nonce"`
	Mode      string `json:"Mode"`
	DcrmFrom  string `json:"DcrmFrom"`
	DcrmTo    string `json:"DcrmTo"`
	Value     string `json:"Value"`
	CoinType  string `json:"CoinType"`
	ThresHold string `json:"ThresHold"`
	TimeStamp string `json:"TimeStamp"`
}
type signCurNodeInfo struct {
	Account    string `json:"Account"`
	GroupID    string `json:"GroupId"`
	Key        string `json:"Key"`
	KeyType    string `json:"KeyType"`
	Mode       string `json:"Mode"`
	MsgContext []string `json:"MsgContext"`
	MsgHash    []string `json:"MsgHash"`
	Nonce      string `json:"Nonce"`
	PubKey     string `json:"PubKey"`
	ThresHold  string `json:"ThresHold"`
	TimeStamp  string `json:"TimeStamp"`
}
type reshareCurNodeInfo struct {
	Key       string `json:"Key"`
	PubKey    string `json:"PubKey"`
	GroupID   string `json:"GroupId"`
	TSGroupID string `json:"TSGroupId"`
	ThresHold string `json:"ThresHold"`
	Account   string `json:"Account"`
	Mode      string `json:"Mode"`
	TimeStamp string `json:"TimeStamp"`
}

// Value set args to start
type Value interface {
	String() string
	Set(string) error
}
type arrayFlags []string

func (i *arrayFlags) String() string {
	return fmt.Sprint(*i)
}
func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}
