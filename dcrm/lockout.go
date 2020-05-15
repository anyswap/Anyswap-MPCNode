/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  caihaijun@fusion.org
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

package dcrm 

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fsn-dev/dcrm-walletService/mpcdsa/crypto/ec2"
	"github.com/fsn-dev/dcrm-walletService/mpcdsa/ecdsa/signing"
	"github.com/fsn-dev/dcrm-walletService/mpcdsa/ecdsa/keygen"
	"github.com/fsn-dev/dcrm-walletService/mpcdsa/crypto/ed"
	"github.com/fsn-dev/dcrm-walletService/crypto/secp256k1"
	"github.com/fsn-dev/dcrm-walletService/crypto/sha3"

	"crypto/ecdsa"
	crand "crypto/rand"
	"runtime/debug"

	"github.com/agl/ed25519"
	"github.com/astaxie/beego/logs"
	"github.com/fsn-dev/cryptoCoins/coins"
	"github.com/fsn-dev/cryptoCoins/coins/eos"
	"github.com/fsn-dev/cryptoCoins/coins/types"
	"github.com/fsn-dev/dcrm-walletService/crypto"
	"github.com/fsn-dev/dcrm-walletService/crypto/ecies"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
)

func GetSignNonce(account string) (string, string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + "Sign"))).Hex()
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if exsit == false {
	    return "0", "", nil
	}

	nonce, _ := new(big.Int).SetString(string(da.([]byte)), 10)
	one, _ := new(big.Int).SetString("1", 10)
	nonce = new(big.Int).Add(nonce, one)
	return fmt.Sprintf("%v", nonce), "", nil
}

func SetSignNonce(account string,nonce string) (string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + "Sign"))).Hex()
	kd := KeyData{Key: []byte(key), Data: nonce}
	PubKeyDataChan <- kd
	LdbPubKeyData.WriteMap(key, []byte(nonce))
	return "", nil
}

func GetLockOutNonce(account string) (string, string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + "LOCKOUT"))).Hex()
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		return "0", "", nil
	}

	nonce, _ := new(big.Int).SetString(string(da.([]byte)), 10)
	one, _ := new(big.Int).SetString("1", 10)
	nonce = new(big.Int).Add(nonce, one)
	return fmt.Sprintf("%v", nonce), "", nil
}

func SetLockOutNonce(account string,nonce string) (string, error) {
	key2 := Keccak256Hash([]byte(strings.ToLower(account + ":" + "LOCKOUT"))).Hex()
	kd := KeyData{Key: []byte(key2), Data: nonce}
	PubKeyDataChan <- kd
	LdbPubKeyData.WriteMap(key2, []byte(nonce))

	return "", nil
}

func sign(wsid string,account string,pubkey string,unsignhash string,keytype string,nonce string,mode string,ch chan interface{}) {
	dcrmpks, _ := hex.DecodeString(pubkey)
	exsit,da := GetValueFromPubKeyData(string(dcrmpks[:]))
	///////
	if exsit == false {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get sign data from db fail", Err: fmt.Errorf("get sign data from db fail")}
		ch <- res
		return
	}

	_,ok := da.(*PubKeyData)
	if ok == false {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get sign data from db fail", Err: fmt.Errorf("get sign data from db fail")}
		ch <- res
		return
	}

	save := (da.(*PubKeyData)).Save
	dcrmpub := (da.(*PubKeyData)).Pub

	var dcrmpkx *big.Int
	var dcrmpky *big.Int
	if keytype == "ECDSA" {
		dcrmpks := []byte(dcrmpub)
		dcrmpkx, dcrmpky = secp256k1.S256().Unmarshal(dcrmpks[:])
	}

	var rsv string
	var cherrtmp error
	rch := make(chan interface{}, 1)
	if keytype == "ED25519" {
	    sign_ed(wsid,unsignhash,save,dcrmpub,keytype,rch)
	    ret, tip, cherr := GetChannelValue(ch_t, rch)
	    if cherr != nil {
		    res := RpcDcrmRes{Ret: "", Tip: tip, Err: cherr}
		    ch <- res
		    return
	    }

	    rsv = ret
	    cherrtmp = cherr
	} else {
	    sign_ec(wsid,unsignhash,save,dcrmpkx,dcrmpky,keytype,rch)
	    ret, tip, cherr := GetChannelValue(ch_t,rch)
	    if cherr != nil {
		    res := RpcDcrmRes{Ret: "", Tip: tip, Err: cherr}
		    ch <- res
		    return
	    }

	    rsv = ret
	    cherrtmp = cherr
	}

	//bug
	rets := []rune(rsv)
	if len(rets) != 130 {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:wrong rsv size", Err: GetRetErr(ErrDcrmSigWrongSize)}
		ch <- res
		return
	}

	if rsv != "" {
		w, err := FindWorker(wsid)
		if w == nil || err != nil {
			fmt.Printf("%v ==========sign,no find worker,nonce = %v,err = %v================\n", common.CurrentTime(), nonce, err)
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker", Err: fmt.Errorf("get worker error.")}
			ch <- res
			return
		}

		///////TODO tmp
		//sid-enode:SendSignRes:Success:rsv
		//sid-enode:SendSignRes:Fail:err
		mp := []string{w.sid, cur_enode}
		enode := strings.Join(mp, "-")
		s0 := "SendSignRes"
		s1 := "Success"
		s2 := rsv
		ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
		SendMsgToDcrmGroup(ss, w.groupid)
		///////////////

		//msg = fusionaccount:pubkey:unsignhash:keytype:groupid:nonce:threshold:mode:key:timestamp
		tip,reply := AcceptSign("",account,pubkey,unsignhash,keytype,w.groupid,nonce,w.limitnum,mode,"true", "true", "Success", rsv,"","",nil,w.id)
		if reply != nil {
			res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("update sign status error.")}
			ch <- res
			return
		}

		fmt.Printf("%v ================sign,the terminal sign res is success. nonce =%v ==================\n", common.CurrentTime(), nonce)
		res := RpcDcrmRes{Ret: rsv, Tip: tip, Err: err}
		ch <- res
		return
	}

	if cherrtmp != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:sign fail", Err: cherrtmp}
		ch <- res
		return
	}

	res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:sign fail", Err: fmt.Errorf("sign fail.")}
	ch <- res
	return
}

func sign_ec(msgprex string, txhash string, save string, dcrmpkx *big.Int, dcrmpky *big.Int, keytype string, ch chan interface{}) string {

	/////////////
	txhashs := []rune(txhash)
	if string(txhashs[0:2]) == "0x" {
		txhash = string(txhashs[2:])
	}

	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		fmt.Printf("%v ==========dcrm_sign,no find worker,key = %v,err = %v================\n", common.CurrentTime(), msgprex, err)
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker", Err: fmt.Errorf("no find worker.")}
		ch <- res
		return ""
	}
	id := w.id

	cur_enode = GetSelfEnode()

	fmt.Println("===================!!!Start!!!====================")

	///////
	var ch1 = make(chan interface{}, 1)
	var bak_sig string
	for i:=0;i < recalc_times;i++ {
	    fmt.Printf("%v===============sign_ec, recalc i = %v, key = %v ================\n",common.CurrentTime(),i,msgprex)
	    if len(ch1) != 0 {
		<-ch1
	    }

	    w := workers[id]
	    w.Clear2()
	    //fmt.Printf("%v=====================sign_ec, i = %v, key = %v ====================\n",common.CurrentTime(),i,msgprex)
	    bak_sig = Sign_ec2(msgprex, save, txhash, keytype, dcrmpkx, dcrmpky, ch1, id)
	    ret, _, cherr := GetChannelValue(ch_t, ch1)
	    //fmt.Printf("%v=====================sign_ec,ret = %v, cherr = %v, key = %v ====================\n",common.CurrentTime(),ret,cherr,msgprex)
	    if ret != "" && cherr == nil {
		//fmt.Printf("%v=====================sign_ec,success sign, ret = %v, cherr = %v, key = %v ====================\n",common.CurrentTime(),ret,cherr,msgprex)
		    res := RpcDcrmRes{Ret: ret, Tip: "", Err: cherr}
		    ch <- res
		    break
	    }
	    
	    time.Sleep(time.Duration(3) * time.Second) //1000 == 1s
	}
	return bak_sig
}

func validate_lockout(wsid string, account string, dcrmaddr string, cointype string, value string, to string, nonce string, memo string,ch chan interface{}) {
	var ret2 Err
	chandler := coins.NewCryptocoinHandler(cointype)
	if chandler == nil {
		res := RpcDcrmRes{Ret: "", Tip: "cointype is not supported", Err: GetRetErr(ErrCoinTypeNotSupported)}
		ch <- res
		return
	}

	key2 := Keccak256Hash([]byte(strings.ToLower(dcrmaddr))).Hex()
	exsit,da := GetValueFromPubKeyData(key2)
	///////
	if exsit == false {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get lockout data from db fail", Err: fmt.Errorf("get lockout data from db fail")}
		ch <- res
		return
	}

	_,ok := da.(*PubKeyData)
	if ok == false {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get lockout data from db fail", Err: fmt.Errorf("get lockout data from db fail")}
		ch <- res
		return
	}

	save := (da.(*PubKeyData)).Save
	dcrmpub := (da.(*PubKeyData)).Pub

	var dcrmpkx *big.Int
	var dcrmpky *big.Int
	if !types.IsDefaultED25519(cointype) {
		dcrmpks := []byte(dcrmpub)
		dcrmpkx, dcrmpky = secp256k1.S256().Unmarshal(dcrmpks[:])
	}

	pubkey := hex.EncodeToString([]byte(dcrmpub))
	realdcrmfrom, err := chandler.PublicKeyToAddress(pubkey)
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get dcrm addr error from pubkey:" + pubkey, Err: fmt.Errorf("get dcrm addr fail")}
		ch <- res
		return
	}

	if !strings.EqualFold(dcrmaddr, realdcrmfrom) {
		res := RpcDcrmRes{Ret: "", Tip: "verify lockout dcrm addr fail,maybe input parameter error", Err: fmt.Errorf("check dcrm addr fail.")}
		ch <- res
		return
	}

	amount, ok := new(big.Int).SetString(value, 10)
	if ok == false {
		fmt.Printf("%v =============validate_lockout,transfer amount to big.Int fail ===============\n", common.CurrentTime())
		res := RpcDcrmRes{Ret: "", Tip: "lockout value error", Err: fmt.Errorf("lockout value error")}
		ch <- res
		return
	}

	jsonstring := "" // TODO erc20
	// For EOS, realdcrmpubkey is needed to calculate userkey,
	// but is not used as real transaction maker.
	// The real transaction maker is eospubkey.
	var eosaccount string
	if strings.EqualFold(cointype, "EOS") {
		eosaccount, _, _ = GetEosAccount()
		if eosaccount == "" {
			res := RpcDcrmRes{Ret: "", Tip: "get real eos user fail", Err: GetRetErr(ErrGetRealEosUserFail)}
			ch <- res
			return
		}
	}

	var lockouttx interface{}
	var digests []string
	var buildTxErr error
	if strings.EqualFold(cointype, "EOS") {
		lockouttx, digests, buildTxErr = chandler.BuildUnsignedTransaction(eosaccount, pubkey, to, amount, jsonstring,memo)
	} else {
		lockouttx, digests, buildTxErr = chandler.BuildUnsignedTransaction(realdcrmfrom, pubkey, to, amount, jsonstring,memo)
	}

	if buildTxErr != nil || lockouttx == nil || len(digests) == 0 {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:build unsign transaction fail", Err: buildTxErr}
		ch <- res
		return
	}

	rch := make(chan interface{}, 1)
	var sigs []string
	var bak_sigs []string
	for _, digest := range digests {
		if types.IsDefaultED25519(cointype) {
			bak_sig := dcrm_sign_ed(wsid, digest, save, dcrmpub, cointype, rch)
			ret, tip, cherr := GetChannelValue(ch_t, rch)
			if cherr != nil {
				res := RpcDcrmRes{Ret: "", Tip: tip, Err: cherr}
				ch <- res
				return
			}

			sigs = append(sigs, ret)
			if bak_sig != "" {
				bak_sigs = append(bak_sigs, bak_sig)
			}

			continue
		}

		fmt.Printf("%v==================start call dcrm_sign, digest = %v, key = %v ===================\n",common.CurrentTime(),digest,wsid)
		bak_sig := dcrm_sign(wsid, digest, save, dcrmpkx, dcrmpky, cointype, rch)
		ret, tip, cherr := GetChannelValue(ch_t, rch)
		fmt.Printf("%v==================end call dcrm_sign, digest = %v, ret = %v, cherr = %v, key = %v ===================\n",common.CurrentTime(),digest,ret,cherr,wsid)
		if cherr != nil {
			res := RpcDcrmRes{Ret: "", Tip: tip, Err: cherr}
			ch <- res
			return
		}

		//bug
		rets := []rune(ret)
		if len(rets) != 130 {
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:wrong rsv size", Err: GetRetErr(ErrDcrmSigWrongSize)}
			ch <- res
			return
		}
		sigs = append(sigs, string(ret))
		if bak_sig != "" {
			bak_sigs = append(bak_sigs, bak_sig)
		}
	}

	signedTx, err := chandler.MakeSignedTransaction(sigs, lockouttx)
	if err != nil {
		ret2.Info = err.Error()
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:new sign transaction fail", Err: ret2}
		ch <- res
		return
	}

	lockout_tx_hash, err := chandler.SubmitTransaction(signedTx)
	fmt.Printf("%v ==========validate_lockout,send to outside net,nonce =%v,lockout txhash =%v,err = %v================\n", common.CurrentTime(), nonce, lockout_tx_hash, err)
	/////////add for bak sig
	if err != nil && len(bak_sigs) != 0 {
		signedTx, err = chandler.MakeSignedTransaction(bak_sigs, lockouttx)
		if err != nil {
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:new sign transaction fail", Err: err}
			ch <- res
			return
		}

		lockout_tx_hash, err = chandler.SubmitTransaction(signedTx)
		fmt.Printf("%v ==========validate_lockout,use bak_sigs,send to outside net,nonce =%v,lockout txhash =%v,err = %v================\n", common.CurrentTime(), nonce, lockout_tx_hash, err)
	}
	/////////

	if lockout_tx_hash != "" {
		w, err := FindWorker(wsid)
		if w == nil || err != nil {
			fmt.Printf("%v ==========validate_lockout,no find worker,nonce = %v,err = %v================\n", common.CurrentTime(), nonce, err)
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker", Err: fmt.Errorf("get worker error.")}
			ch <- res
			return
		}

		///////TODO tmp
		//sid-enode:SendLockOutRes:Success:lockout_tx_hash
		//sid-enode:SendLockOutRes:Fail:err
		mp := []string{w.sid, cur_enode}
		enode := strings.Join(mp, "-")
		s0 := "SendLockOutRes"
		s1 := "Success"
		s2 := lockout_tx_hash
		ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
		SendMsgToDcrmGroup(ss, w.groupid)
		///////////////

		tip, reply := AcceptLockOut("",account, w.groupid, nonce, dcrmaddr, w.limitnum, "true", "true", "Success", lockout_tx_hash, "", "", nil, w.id)
		if reply != nil {
			res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("update lockout status error.")}
			ch <- res
			return
		}

		fmt.Printf("%v ================validate_lockout,the terminal lockout res is success. nonce =%v ==================\n", common.CurrentTime(), nonce)
		res := RpcDcrmRes{Ret: lockout_tx_hash, Tip: tip, Err: err}
		ch <- res
		return
	}

	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:send lockout tx to network fail", Err: err}
		ch <- res
		return
	}

	res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:lockout fail", Err: GetRetErr(ErrSendTxToNetFail)}
	ch <- res
	return
}

//ec2
//msgprex = hash
//return value is the backup for dcrm sig.
func dcrm_sign(msgprex string, txhash string, save string, dcrmpkx *big.Int, dcrmpky *big.Int, cointype string, ch chan interface{}) string {

	if strings.EqualFold(cointype, "EOS") == true {

		var eosstr string
		key := string([]byte("eossettings"))
		exsit,da := GetValueFromPubKeyData(key)
		if exsit == true {
			eosstr = string(da.([]byte))
		}
		///////
		if eosstr == "" {
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get eos setting data from db fail", Err: fmt.Errorf("get save date fail.")}
			ch <- res
			return ""
		}

		// Retrieve eospubkey
		eosstrs := strings.Split(string(eosstr), ":")
		fmt.Println("======== get eos settings,eosstr = %s ========", eosstr)
		if len(eosstrs) != 5 {
			var ret2 Err
			ret2.Info = "get eos settings error: " + string(eosstr)
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:eos setting data error", Err: ret2}
			ch <- res
			return ""
		}
		pubhex := eosstrs[3]
		dcrmpks, _ := hex.DecodeString(pubhex)
		dcrmpkx2, dcrmpky2 := secp256k1.S256().Unmarshal(dcrmpks[:])
		//dcrmaddr := pubhex
		fmt.Println("======== dcrm_sign eos,pkx = %+v,pky = %+v,==========", dcrmpkx2, dcrmpky2)
		txhashs := []rune(txhash)
		if string(txhashs[0:2]) == "0x" {
			txhash = string(txhashs[2:])
		}

		w, err := FindWorker(msgprex)
		if w == nil || err != nil {
			fmt.Printf("%v ==========dcrm_sign,no find worker,key = %v,err = %v================\n", common.CurrentTime(), msgprex, err)
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker", Err: GetRetErr(ErrNoFindWorker)}
			ch <- res
			return ""
		}
		id := w.id

		var ch1 = make(chan interface{}, 1)
		var flag = false
		var ret string
		var tip string
		var bak_sig string
		//25-->1
		for i := 0; i < recalc_times; i++ {
			fmt.Printf("%v===============dcrm_sign, recalc i = %v, key = %v ================\n",common.CurrentTime(),i,msgprex)
			if len(ch1) != 0 {
			    <-ch1
			}

			w := workers[id]
			w.Clear2()
			bak_sig = Sign_ec2(msgprex, save, txhash, cointype, dcrmpkx2, dcrmpky2, ch1, id)
			ret, tip, _ = GetChannelValue(ch_t, ch1)
			//if ret != "" && eos.IsCanonical([]byte(ret)) == true
			if ret == "" {
				time.Sleep(time.Duration(1) * time.Second) //1000 == 1s
				continue
			}
			b, _ := hex.DecodeString(ret)
			if eos.IsCanonical(b) == true {
				flag = true
				break
			}
			time.Sleep(time.Duration(3) * time.Second) //1000 == 1s
		}
		if flag == false {
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:eos dcrm sign fail", Err: GetRetErr(ErrDcrmSigFail)}
			ch <- res
			return ""
		}

		res := RpcDcrmRes{Ret: ret, Tip: tip, Err: nil}
		ch <- res
		return bak_sig
	}

	/////////////
	txhashs := []rune(txhash)
	if string(txhashs[0:2]) == "0x" {
		txhash = string(txhashs[2:])
	}

	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		fmt.Printf("%v ==========dcrm_sign,no find worker,key = %v,err = %v================\n", common.CurrentTime(), msgprex, err)
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker", Err: fmt.Errorf("no find worker.")}
		ch <- res
		return ""
	}
	id := w.id

	cur_enode = GetSelfEnode()

	fmt.Println("===================!!!Start!!!====================")

	///////
	if strings.EqualFold(cointype, "EVT1") == true {
		logs.Debug("======== dcrm_sign ready to call Sign_ec2", "msgprex", msgprex, "save", save, "txhash", txhash, "cointype", cointype, "pkx", dcrmpkx, "pky", dcrmpky, "id", id)
		logs.Debug("!!! token type is EVT1 !!!")
		var ch1 = make(chan interface{}, 1)
		var flag = false
		var ret string
		var tip string
		var cherr error
		var bak_sig string
		//25-->1
		for i := 0; i < recalc_times; i++ {
			fmt.Printf("%v===============dcrm_sign, recalc i = %v, key = %v ================\n",common.CurrentTime(),i,msgprex)
			if len(ch1) != 0 {
			    <-ch1
			}

			w := workers[id]
			w.Clear2()
			bak_sig = Sign_ec2(msgprex, save, txhash, cointype, dcrmpkx, dcrmpky, ch1, id)
			ret, tip, cherr = GetChannelValue(ch_t, ch1)
			if cherr != nil {
				time.Sleep(time.Duration(3) * time.Second) //1000 == 1s
				continue
			}
			//if ret != "" && eos.IsCanonical([]byte(ret)) == true
			if ret == "" {
				time.Sleep(time.Duration(3) * time.Second) //1000 == 1s
				continue
			}
			b, _ := hex.DecodeString(ret)
			if eos.IsCanonical(b) == true {
				fmt.Printf("\nret is a canonical signature\n")
				flag = true
				break
			}
			time.Sleep(time.Duration(3) * time.Second) //1000 == 1s
		}
		logs.Debug("======== dcrm_sign evt", "got rsv flag", flag, "ret", ret, "", "========")
		if flag == false {
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:dcrm sign fail", Err: GetRetErr(ErrDcrmSigFail)}
			ch <- res
			return ""
		}
		//ch <- ret
		res := RpcDcrmRes{Ret: ret, Tip: tip, Err: cherr}
		ch <- res
		return bak_sig
	} else {
	    var ch1 = make(chan interface{}, 1)
	    var bak_sig string
	    for i:=0;i < recalc_times;i++ {
		fmt.Printf("%v===============dcrm_sign, recalc i = %v, key = %v ================\n",common.CurrentTime(),i,msgprex)
		if len(ch1) != 0 {
		    <-ch1
		}

		w := workers[id]
		w.Clear2()
		fmt.Printf("%v=====================dcrm_sign, i = %v, key = %v ====================\n",common.CurrentTime(),i,msgprex)
		bak_sig = Sign_ec2(msgprex, save, txhash, cointype, dcrmpkx, dcrmpky, ch1, id)
		ret, _, cherr := GetChannelValue(ch_t, ch1)
		fmt.Printf("%v=====================dcrm_sign,ret = %v, cherr = %v, key = %v ====================\n",common.CurrentTime(),ret,cherr,msgprex)
		if ret != "" && cherr == nil {
			fmt.Printf("%v=====================dcrm_sign,success sign, ret = %v, cherr = %v, key = %v ====================\n",common.CurrentTime(),ret,cherr,msgprex)
			res := RpcDcrmRes{Ret: ret, Tip: "", Err: cherr}
			ch <- res
			break
		}
		
		time.Sleep(time.Duration(3) * time.Second) //1000 == 1s
		fmt.Printf("%v=====================dcrm_sign,22222222222222222222222222,key = %v ====================\n",common.CurrentTime(),msgprex)
	    }
	    return bak_sig
	}

	return ""
}

func MapPrivKeyShare(cointype string, w *RpcReqWorker, idSign sortableIDSSlice, privshare string) (*big.Int, *big.Int) {
	if cointype == "" || w == nil || len(idSign) == 0 || privshare == "" {
		return nil, nil
	}

	// 1. map the share of private key to no-threshold share of private key
	var self *big.Int
	lambda1 := big.NewInt(1)
	for _, uid := range idSign {
		enodes := GetEnodesByUid(uid, cointype, w.groupid)
		if IsCurNode(enodes, cur_enode) {
			self = uid
			break
		}
	}

	if self == nil {
		return nil, nil
	}

	for i, uid := range idSign {
		enodes := GetEnodesByUid(uid, cointype, w.groupid)
		if IsCurNode(enodes, cur_enode) {
			continue
		}

		sub := new(big.Int).Sub(idSign[i], self)
		subInverse := new(big.Int).ModInverse(sub, secp256k1.S256().N)
		times := new(big.Int).Mul(subInverse, idSign[i])
		lambda1 = new(big.Int).Mul(lambda1, times)
		lambda1 = new(big.Int).Mod(lambda1, secp256k1.S256().N)
	}

	skU1 := new(big.Int).SetBytes([]byte(privshare))
	w1 := new(big.Int).Mul(lambda1, skU1)
	w1 = new(big.Int).Mod(w1, secp256k1.S256().N)

	return skU1, w1
}

func DECDSASignRoundOne(msgprex string, w *RpcReqWorker, idSign sortableIDSSlice, ch chan interface{}) (*big.Int, *big.Int, *ec2.Commitment) {
	if msgprex == "" || w == nil || len(idSign) == 0 {
		res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetC11Timeout)}
		ch <- res
		return nil, nil, nil
	}

	u1K, u1Gamma, commitU1GammaG := signing.DECDSA_Sign_RoundOne()
	// 4. Broadcast
	//	commitU1GammaG.C, commitU2GammaG.C, commitU3GammaG.C
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "C11"
	s1 := string(commitU1GammaG.C.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	////fix bug: get C11 timeout
	_, enodestmp := GetGroup(w.groupid)
	nodestmp := strings.Split(enodestmp, common.Sep2)
	for _, node := range nodestmp {
	    node2 := ParseNode(node)
	    c1data := msgprex + "-" + node2 + common.Sep + "C11"
	    c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
	    if exist {
		DisMsg(c1.(string))
		go C1Data.DeleteMap(strings.ToLower(c1data))
	    }
	}
	////

	// 1. Receive Broadcast
	//	commitU1GammaG.C, commitU2GammaG.C, commitU3GammaG.C
	common.Info("===================send C11 finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bc11)
	common.Info("===================finish get C11, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"C11",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: GetRetErr(ErrGetC11Timeout)}
		ch <- res
		return nil, nil, nil
	}

	return u1K, u1Gamma, commitU1GammaG
}

func DECDSASignPaillierEncrypt(cointype string, save string, w *RpcReqWorker, idSign sortableIDSSlice, u1K *big.Int, ch chan interface{}) (map[string]*big.Int, map[string]*big.Int, map[string]*ec2.PublicKey) {
	if cointype == "" || w == nil || len(idSign) == 0 || u1K == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil, nil, nil
	}

	// 2. MtA(k, gamma) and MtA(k, w)
	// 2.1 encrypt c_k = E_paillier(k)
	var ukc = make(map[string]*big.Int)
	var ukc2 = make(map[string]*big.Int)
	var ukc3 = make(map[string]*ec2.PublicKey)

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			u1PaillierPk := signing.GetPaillierPk(save, GetRealByUid(cointype,w,id))
			//u1PaillierPk := GetPaillierPk2(cointype,w,id)
			if u1PaillierPk == nil {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get save paillier pk fail")}
				ch <- res
				return nil, nil, nil
			}

			u1KCipher, u1R, _ := signing.DECDSA_Sign_Paillier_Encrypt(u1PaillierPk, u1K)
			ukc[en[0]] = u1KCipher
			ukc2[en[0]] = u1R
			ukc3[en[0]] = u1PaillierPk
			break
		}
	}

	return ukc, ukc2, ukc3
}

func DECDSASignRoundTwo(msgprex string, cointype string, save string, w *RpcReqWorker, idSign sortableIDSSlice, ch chan interface{}, u1K *big.Int, ukc2 map[string]*big.Int, ukc3 map[string]*ec2.PublicKey) (map[string]*ec2.MtAZK1Proof_nhh, map[string]*ec2.NtildeH1H2) {
	if msgprex == "" || cointype == "" || save == "" || w == nil || len(idSign) == 0 || u1K == nil || len(ukc2) == 0 || len(ukc3) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil, nil
	}

	// 2.2 calculate zk(k)
	var zk1proof = make(map[string]*ec2.MtAZK1Proof_nhh)
	var zkfactproof = make(map[string]*ec2.NtildeH1H2)
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")

		u1zkFactProof := signing.GetZkFactProof(save, GetRealByUid(cointype,w,id), w.NodeCnt)
		if u1zkFactProof == nil {
			fmt.Println("=================Sign_ec2,u1zkFactProof is nil. Nonce =%s=====================", msgprex)
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get ntildeh1h2 fail")}
			ch <- res
			return nil, nil
		}

		if len(en) == 0 || en[0] == "" {
			fmt.Println("=================Sign_ec2,get enode error,Nonce =%s,enodes = %s,uid = %v,cointype = %s,groupid = %s =====================", msgprex, enodes, id, cointype, w.groupid)
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get ntildeh1h2 fail")}
			ch <- res
			return nil, nil
		}

		zkfactproof[en[0]] = u1zkFactProof
		if IsCurNode(enodes, cur_enode) {
			u1u1MtAZK1Proof := signing.DECDSA_Sign_MtAZK1Prove(u1K, ukc2[en[0]], ukc3[en[0]], u1zkFactProof)
			zk1proof[en[0]] = u1u1MtAZK1Proof
		} else {
			u1u1MtAZK1Proof := signing.DECDSA_Sign_MtAZK1Prove(u1K, ukc2[cur_enode], ukc3[cur_enode], u1zkFactProof)
			mp := []string{msgprex, cur_enode}
			enode := strings.Join(mp, "-")
			s0 := "MTAZK1PROOF"
			s1 := string(u1u1MtAZK1Proof.Z.Bytes())
			s2 := string(u1u1MtAZK1Proof.U.Bytes())
			s3 := string(u1u1MtAZK1Proof.W.Bytes())
			s4 := string(u1u1MtAZK1Proof.S.Bytes())
			s5 := string(u1u1MtAZK1Proof.S1.Bytes())
			s6 := string(u1u1MtAZK1Proof.S2.Bytes())
			ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2 + common.Sep + s3 + common.Sep + s4 + common.Sep + s5 + common.Sep + s6
			SendMsgToPeer(enodes, ss)
		}
	}

	_, tip, cherr := GetChannelValue(ch_t, w.bmtazk1proof)
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"MTAZK1PROOF",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: GetRetErr(ErrGetMTAZK1PROOFTimeout)}
		ch <- res
		return nil, nil
	}

	return zk1proof, zkfactproof
}

func DECDSASignRoundThree(msgprex string, cointype string, save string, w *RpcReqWorker, idSign sortableIDSSlice, ch chan interface{}, ukc map[string]*big.Int) bool {
	if msgprex == "" || cointype == "" || save == "" || w == nil || len(idSign) == 0 || len(ukc) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return false
	}

	// 2.3 Broadcast c_k, zk(k)
	// u1KCipher, u2KCipher, u3KCipher
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "KC"
	s1 := string(ukc[cur_enode].Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	// 2.4 Receive Broadcast c_k, zk(k)
	// u1KCipher, u2KCipher, u3KCipher
	common.Info("===================send KC finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bkc)
	common.Info("===================finish get KC, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"KC",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: GetRetErr(ErrGetKCTimeout)}
		ch <- res
		return false
	}

	kcs := make([]string, w.ThresHold)
	if w.msg_kc.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetAllKCFail)}
		ch <- res
		return false
	}

	itmp := 0
	iter := w.msg_kc.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		kcs[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}

		for _, v := range kcs {
			mm := strings.Split(v, common.Sep)
			if len(mm) < 3 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_kc fail")}
				ch <- res
				return false
			}

			prex := mm[0]
			prexs := strings.Split(prex, "-")
			if prexs[len(prexs)-1] == en[0] {
				kc := new(big.Int).SetBytes([]byte(mm[2]))
				ukc[en[0]] = kc
				break
			}
		}
	}

	return true
}

func DECDSASignVerifyZKNtilde(msgprex string, cointype string, save string, w *RpcReqWorker, idSign sortableIDSSlice, ch chan interface{}, ukc map[string]*big.Int, ukc3 map[string]*ec2.PublicKey, zk1proof map[string]*ec2.MtAZK1Proof_nhh, zkfactproof map[string]*ec2.NtildeH1H2) bool {
	if msgprex == "" || cointype == "" || save == "" || w == nil || len(idSign) == 0 || len(ukc) == 0 || len(ukc3) == 0 || len(zk1proof) == 0 || len(zkfactproof) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return false
	}

	// example for u1, receive: u1u1MtAZK1Proof from u1, u2u1MtAZK1Proof from u2, u3u1MtAZK1Proof from u3
	mtazk1s := make([]string, w.ThresHold-1)
	if w.msg_mtazk1proof.Len() != (w.ThresHold - 1) {
		res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetAllMTAZK1PROOFFail)}
		ch <- res
		return false
	}

	itmp := 0
	iter := w.msg_mtazk1proof.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		mtazk1s[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}

		for _, v := range mtazk1s {
			mm := strings.Split(v, common.Sep)
			if len(mm) < 8 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_mtazk1proof fail")}
				ch <- res
				return false
			}

			prex := mm[0]
			prexs := strings.Split(prex, "-")
			if prexs[len(prexs)-1] == en[0] {
				z := new(big.Int).SetBytes([]byte(mm[2]))
				u := new(big.Int).SetBytes([]byte(mm[3]))
				w := new(big.Int).SetBytes([]byte(mm[4]))
				s := new(big.Int).SetBytes([]byte(mm[5]))
				s1 := new(big.Int).SetBytes([]byte(mm[6]))
				s2 := new(big.Int).SetBytes([]byte(mm[7]))
				mtAZK1Proof := &ec2.MtAZK1Proof_nhh{Z: z, U: u, W: w, S: s, S1: s1, S2: s2}
				zk1proof[en[0]] = mtAZK1Proof
				break
			}
		}
	}

	// 2.5 verify zk(k)
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			if cur_enode == "" || zk1proof[cur_enode] == nil || zkfactproof[cur_enode] == nil || ukc[cur_enode] == nil || ukc3[cur_enode] == nil {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("mtazk1 verification fail")}
				ch <- res
				return false
			}

			//delete zkfactor,add ntilde h1 h2
			u1rlt1 := signing.DECDSA_Sign_MtAZK1Verify(zk1proof[cur_enode], ukc[cur_enode], ukc3[cur_enode], zkfactproof[cur_enode])
			if !u1rlt1 {
				fmt.Println("============sign,111111111,verify mtazk1proof fail===================")
				res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifyMTAZK1PROOFFail)}
				ch <- res
				return false
			}
		} else {
			if len(en) <= 0 {
				res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifyMTAZK1PROOFFail)}
				ch <- res
				return false
			}

			_, exsit := zk1proof[en[0]]
			if exsit == false {
				res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifyMTAZK1PROOFFail)}
				ch <- res
				return false
			}

			_, exsit = ukc[en[0]]
			if exsit == false {
				res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifyMTAZK1PROOFFail)}
				ch <- res
				return false
			}

			u1PaillierPk := signing.GetPaillierPk(save, GetRealByUid(cointype,w,id))
			//u1PaillierPk := GetPaillierPk2(cointype,w,id)
			if u1PaillierPk == nil {
				fmt.Println("============sign,22222222,verify mtazk1proof fail===================")
				res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifyMTAZK1PROOFFail)}
				ch <- res
				return false
			}

			_, exsit = zkfactproof[cur_enode]
			if exsit == false {
				res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifyMTAZK1PROOFFail)}
				ch <- res
				return false
			}

			if len(en) == 0 || en[0] == "" || zk1proof[en[0]] == nil || zkfactproof[cur_enode] == nil || ukc[en[0]] == nil {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("mtazk1 verification fail")}
				ch <- res
				return false
			}

			u1rlt1 := signing.DECDSA_Sign_MtAZK1Verify(zk1proof[en[0]], ukc[en[0]], u1PaillierPk, zkfactproof[cur_enode])
			if !u1rlt1 {
				fmt.Println("============sign,333333333,verify mtazk1proof fail===================")
				res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifyMTAZK1PROOFFail)}
				ch <- res
				return false
			}
		}
	}

	return true
}

func DECDSASignRoundFour(msgprex string, cointype string, save string, w *RpcReqWorker, idSign sortableIDSSlice, ukc map[string]*big.Int, ukc3 map[string]*ec2.PublicKey, zkfactproof map[string]*ec2.NtildeH1H2, u1Gamma *big.Int, w1 *big.Int, betaU1Star []*big.Int, vU1Star []*big.Int, ch chan interface{}) (map[string]*big.Int, map[string]*ec2.MtAZK2Proof_nhh, map[string]*big.Int, map[string]*ec2.MtAZK3Proof_nhh, bool) {
	if msgprex == "" || cointype == "" || save == "" || w == nil || len(idSign) == 0 || len(ukc) == 0 || len(ukc3) == 0 || len(zkfactproof) == 0 || len(betaU1Star) == 0 || len(vU1Star) == 0 || u1Gamma == nil || w1 == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil, nil, nil, nil, false
	}

	// 2.7
	// send c_kGamma to proper node, MtA(k, gamma)   zk
	var mkg = make(map[string]*big.Int)
	var mkg_mtazk2 = make(map[string]*ec2.MtAZK2Proof_nhh)
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			//u1PaillierPk := GetPaillierPk2(cointype,w,id)
			u1PaillierPk := signing.GetPaillierPk(save, GetRealByUid(cointype,w,id))
			if u1PaillierPk == nil {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get paillier pk fail")}
				ch <- res
				return nil, nil, nil, nil, false
			}

			u1KGamma1Cipher := signing.DECDSA_Sign_Paillier_HomoMul(u1PaillierPk, ukc[en[0]], u1Gamma)
			if betaU1Star[k] == nil {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get betaU1Star fail")}
				ch <- res
				return nil, nil, nil, nil, false
			}

			beta1U1StarCipher, u1BetaR1, _ := signing.DECDSA_Sign_Paillier_Encrypt(u1PaillierPk, betaU1Star[k])
			u1KGamma1Cipher = signing.DECDSA_Sign_Paillier_HomoAdd(u1PaillierPk, u1KGamma1Cipher, beta1U1StarCipher) // send to u1

			u1u1MtAZK2Proof := ec2.MtAZK2Prove_nhh(u1Gamma, betaU1Star[k], u1BetaR1, ukc[cur_enode], ukc3[cur_enode], zkfactproof[cur_enode])
			mkg[en[0]] = u1KGamma1Cipher
			mkg_mtazk2[en[0]] = u1u1MtAZK2Proof
			continue
		}

		u2PaillierPk := signing.GetPaillierPk(save, GetRealByUid(cointype,w,id))
		//u2PaillierPk := GetPaillierPk2(cointype,w,id)
		if u2PaillierPk == nil {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get paillier pk fail")}
			ch <- res
			return nil, nil, nil, nil, false
		}

		u2KGamma1Cipher := signing.DECDSA_Sign_Paillier_HomoMul(u2PaillierPk, ukc[en[0]], u1Gamma)
		if betaU1Star[k] == nil {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get betaU1Star fail")}
			ch <- res
			return nil, nil, nil, nil, false
		}

		beta2U1StarCipher, u2BetaR1, _ := signing.DECDSA_Sign_Paillier_Encrypt(u2PaillierPk, betaU1Star[k])
		u2KGamma1Cipher = signing.DECDSA_Sign_Paillier_HomoAdd(u2PaillierPk, u2KGamma1Cipher, beta2U1StarCipher) // send to u2
		u2u1MtAZK2Proof := signing.DECDSA_Sign_MtAZK2Prove(u1Gamma, betaU1Star[k], u2BetaR1, ukc[en[0]], u2PaillierPk, zkfactproof[cur_enode])
		mp := []string{msgprex, cur_enode}
		enode := strings.Join(mp, "-")
		s0 := "MKG"
		s1 := string(u2KGamma1Cipher.Bytes())
		//////
		s2 := string(u2u1MtAZK2Proof.Z.Bytes())
		s3 := string(u2u1MtAZK2Proof.ZBar.Bytes())
		s4 := string(u2u1MtAZK2Proof.T.Bytes())
		s5 := string(u2u1MtAZK2Proof.V.Bytes())
		s6 := string(u2u1MtAZK2Proof.W.Bytes())
		s7 := string(u2u1MtAZK2Proof.S.Bytes())
		s8 := string(u2u1MtAZK2Proof.S1.Bytes())
		s9 := string(u2u1MtAZK2Proof.S2.Bytes())
		s10 := string(u2u1MtAZK2Proof.T1.Bytes())
		s11 := string(u2u1MtAZK2Proof.T2.Bytes())
		///////
		ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2 + common.Sep + s3 + common.Sep + s4 + common.Sep + s5 + common.Sep + s6 + common.Sep + s7 + common.Sep + s8 + common.Sep + s9 + common.Sep + s10 + common.Sep + s11
		SendMsgToPeer(enodes, ss)
	}

	// 2.8
	// send c_kw to proper node, MtA(k, w)   zk
	var mkw = make(map[string]*big.Int)
	var mkw_mtazk2 = make(map[string]*ec2.MtAZK3Proof_nhh)
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			//u1PaillierPk := GetPaillierPk2(cointype,w,id)
			u1PaillierPk := signing.GetPaillierPk(save, GetRealByUid(cointype,w,id))
			if u1PaillierPk == nil {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get paillier pk fail")}
				ch <- res
				return nil, nil, nil, nil, false
			}

			u1Kw1Cipher := signing.DECDSA_Sign_Paillier_HomoMul(u1PaillierPk, ukc[en[0]], w1)
			if vU1Star[k] == nil {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get vU1Star fail")}
				ch <- res
				return nil, nil, nil, nil, false
			}

			v1U1StarCipher, u1VR1, _ := signing.DECDSA_Sign_Paillier_Encrypt(u1PaillierPk, vU1Star[k])
			u1Kw1Cipher = signing.DECDSA_Sign_Paillier_HomoAdd(u1PaillierPk, u1Kw1Cipher, v1U1StarCipher)                                       // send to u1
			u1u1MtAZK2Proof2 := signing.DECDSA_Sign_MtAZK3Prove(w1, vU1Star[k], u1VR1, ukc[cur_enode], ukc3[cur_enode], zkfactproof[cur_enode]) //Fusion_dcrm question 8
			mkw[en[0]] = u1Kw1Cipher
			mkw_mtazk2[en[0]] = u1u1MtAZK2Proof2
			continue
		}

		u2PaillierPk := signing.GetPaillierPk(save, GetRealByUid(cointype,w,id))
		//u2PaillierPk := GetPaillierPk2(cointype,w,id)
		if u2PaillierPk == nil {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get paillier pk fail")}
			ch <- res
			return nil, nil, nil, nil, false
		}

		u2Kw1Cipher := signing.DECDSA_Sign_Paillier_HomoMul(u2PaillierPk, ukc[en[0]], w1)
		if vU1Star[k] == nil {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get vU1Star fail")}
			ch <- res
			return nil, nil, nil, nil, false
		}

		v2U1StarCipher, u2VR1, _ := signing.DECDSA_Sign_Paillier_Encrypt(u2PaillierPk, vU1Star[k])
		u2Kw1Cipher = signing.DECDSA_Sign_Paillier_HomoAdd(u2PaillierPk, u2Kw1Cipher, v2U1StarCipher) // send to u2
		u2u1MtAZK2Proof2 := signing.DECDSA_Sign_MtAZK3Prove(w1, vU1Star[k], u2VR1, ukc[en[0]], u2PaillierPk, zkfactproof[cur_enode])

		mp := []string{msgprex, cur_enode}
		enode := strings.Join(mp, "-")
		s0 := "MKW"
		s1 := string(u2Kw1Cipher.Bytes())
		//////
		//bug
		s2 := string(u2u1MtAZK2Proof2.Ux.Bytes())
		s3 := string(u2u1MtAZK2Proof2.Uy.Bytes())
		//bug
		s4 := string(u2u1MtAZK2Proof2.Z.Bytes())
		s5 := string(u2u1MtAZK2Proof2.ZBar.Bytes())
		s6 := string(u2u1MtAZK2Proof2.T.Bytes())
		s7 := string(u2u1MtAZK2Proof2.V.Bytes())
		s8 := string(u2u1MtAZK2Proof2.W.Bytes())
		s9 := string(u2u1MtAZK2Proof2.S.Bytes())
		s10 := string(u2u1MtAZK2Proof2.S1.Bytes())
		s11 := string(u2u1MtAZK2Proof2.S2.Bytes())
		s12 := string(u2u1MtAZK2Proof2.T1.Bytes())
		s13 := string(u2u1MtAZK2Proof2.T2.Bytes())
		///////

		ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2 + common.Sep + s3 + common.Sep + s4 + common.Sep + s5 + common.Sep + s6 + common.Sep + s7 + common.Sep + s8 + common.Sep + s9 + common.Sep + s10 + common.Sep + s11 + common.Sep + s12 + common.Sep + s13
		SendMsgToPeer(enodes, ss)
	}

	return mkg, mkg_mtazk2, mkw, mkw_mtazk2, true
}

func DECDSASignVerifyZKGammaW(msgprex string,cointype string, save string, w *RpcReqWorker, idSign sortableIDSSlice, ukc map[string]*big.Int, ukc3 map[string]*ec2.PublicKey, zkfactproof map[string]*ec2.NtildeH1H2, mkg map[string]*big.Int, mkg_mtazk2 map[string]*ec2.MtAZK2Proof_nhh, mkw map[string]*big.Int, mkw_mtazk2 map[string]*ec2.MtAZK3Proof_nhh, ch chan interface{}) bool {
	if msgprex == "" || cointype == "" || save == "" || w == nil || len(idSign) == 0 || len(ukc) == 0 || len(ukc3) == 0 || len(zkfactproof) == 0 || len(mkg) == 0 || len(mkw) == 0 || len(mkg_mtazk2) == 0 || len(mkw_mtazk2) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return false
	}

	// 2.9
	// receive c_kGamma from proper node, MtA(k, gamma)   zk
	_, tip, cherr := GetChannelValue(ch_t, w.bmkg)
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"MKG",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: GetRetErr(ErrGetMKGTimeout)}
		ch <- res
		return false
	}

	mkgs := make([]string, w.ThresHold-1)
	if w.msg_mkg.Len() != (w.ThresHold-1) {
		res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetAllMKGFail)}
		ch <- res
		return false
	}

	itmp := 0
	iter := w.msg_mkg.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		mkgs[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return false
		}
		////////
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}
		for _, v := range mkgs {
			mm := strings.Split(v, common.Sep)
			if len(mm) < 13 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_mkg fail")}
				ch <- res
				return false
			}

			prex := mm[0]
			prexs := strings.Split(prex, "-")
			if prexs[len(prexs)-1] == en[0] {
				kg := new(big.Int).SetBytes([]byte(mm[2]))
				mkg[en[0]] = kg

				z := new(big.Int).SetBytes([]byte(mm[3]))
				zbar := new(big.Int).SetBytes([]byte(mm[4]))
				t := new(big.Int).SetBytes([]byte(mm[5]))
				v := new(big.Int).SetBytes([]byte(mm[6]))
				w := new(big.Int).SetBytes([]byte(mm[7]))
				s := new(big.Int).SetBytes([]byte(mm[8]))
				s1 := new(big.Int).SetBytes([]byte(mm[9]))
				s2 := new(big.Int).SetBytes([]byte(mm[10]))
				t1 := new(big.Int).SetBytes([]byte(mm[11]))
				t2 := new(big.Int).SetBytes([]byte(mm[12]))
				mtAZK2Proof := &ec2.MtAZK2Proof_nhh{Z: z, ZBar: zbar, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}
				mkg_mtazk2[en[0]] = mtAZK2Proof
				break
			}
		}
	}

	// 2.10
	// receive c_kw from proper node, MtA(k, w)    zk
	_, tip, cherr = GetChannelValue(ch_t, w.bmkw)
	/////////////////////////request data from dcrm group
	suss = false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"MKW",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: GetRetErr(ErrGetMKWTimeout)}
		ch <- res
		return false
	}

	mkws := make([]string, w.ThresHold-1)
	if w.msg_mkw.Len() != (w.ThresHold-1) {
		res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetAllMKWFail)}
		ch <- res
		return false
	}

	itmp = 0
	iter = w.msg_mkw.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		mkws[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return false
		}
		////////
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}
		for _, v := range mkws {
			mm := strings.Split(v, common.Sep)
			if len(mm) < 15 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_mkw fail")}
				ch <- res
				return false
			}

			prex := mm[0]
			prexs := strings.Split(prex, "-")
			if prexs[len(prexs)-1] == en[0] {
				kw := new(big.Int).SetBytes([]byte(mm[2]))
				mkw[en[0]] = kw

				ux := new(big.Int).SetBytes([]byte(mm[3]))
				uy := new(big.Int).SetBytes([]byte(mm[4]))
				z := new(big.Int).SetBytes([]byte(mm[5]))
				zbar := new(big.Int).SetBytes([]byte(mm[6]))
				t := new(big.Int).SetBytes([]byte(mm[7]))
				v := new(big.Int).SetBytes([]byte(mm[8]))
				w := new(big.Int).SetBytes([]byte(mm[9]))
				s := new(big.Int).SetBytes([]byte(mm[10]))
				s1 := new(big.Int).SetBytes([]byte(mm[11]))
				s2 := new(big.Int).SetBytes([]byte(mm[12]))
				t1 := new(big.Int).SetBytes([]byte(mm[13]))
				t2 := new(big.Int).SetBytes([]byte(mm[14]))
				mtAZK2Proof := &ec2.MtAZK3Proof_nhh{Ux: ux, Uy: uy, Z: z, ZBar: zbar, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}
				mkw_mtazk2[en[0]] = mtAZK2Proof
				break
			}
		}
	}

	// 2.11 verify zk
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return false
		}

		////////
		en := strings.Split(string(enodes[8:]), "@")
		//bug
		if len(en) == 0 || en[0] == "" || mkg_mtazk2[en[0]] == nil || cur_enode == "" || ukc[cur_enode] == nil || mkg[en[0]] == nil || ukc3[cur_enode] == nil || zkfactproof[en[0]] == nil {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("mkw mtazk2 verify fail.")}
			ch <- res
			return false
		}

		//
		rlt111 := signing.DECDSA_Sign_MtAZK2Verify(mkg_mtazk2[en[0]], ukc[cur_enode], mkg[en[0]], ukc3[cur_enode], zkfactproof[en[0]])
		if !rlt111 {
			res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifyMKGFail)}
			ch <- res
			return false
		}

		if len(en) == 0 || en[0] == "" || mkw_mtazk2[en[0]] == nil || cur_enode == "" || ukc[cur_enode] == nil || mkw[en[0]] == nil || ukc3[cur_enode] == nil || zkfactproof[en[0]] == nil {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("mkw mtazk2 verify fail.")}
			ch <- res
			return false
		}

		rlt112 := signing.DECDSA_Sign_MtAZK3Verify(mkw_mtazk2[en[0]], ukc[cur_enode], mkw[en[0]], ukc3[cur_enode], zkfactproof[en[0]])
		if !rlt112 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("mkw mtazk2 verify fail.")}
			ch <- res
			return false
		}
	}

	return true
}

func GetSelfPrivKey(cointype string, idSign sortableIDSSlice, w *RpcReqWorker, save string, ch chan interface{}) *ec2.PrivateKey {
	if cointype == "" || len(idSign) == 0 || w == nil || save == "" {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil
	}

	// 2.12
	// decrypt c_kGamma to get alpha, MtA(k, gamma)
	// MtA(k, gamma)
	var uid *big.Int
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}
		////////
		if IsCurNode(enodes, cur_enode) {
			uid = id
			break
		}
	}

	u1PaillierSk := signing.GetPaillierSk(save,GetRealByUid(cointype,w,uid)) //get self privkey
	if u1PaillierSk == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get sk fail.")}
		ch <- res
		return nil
	}

	return u1PaillierSk
}

func DecryptCkGamma(cointype string, idSign sortableIDSSlice, w *RpcReqWorker, u1PaillierSk *ec2.PrivateKey, mkg map[string]*big.Int, ch chan interface{}) []*big.Int {
	if cointype == "" || len(idSign) == 0 || w == nil || u1PaillierSk == nil || len(mkg) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil
	}

	alpha1 := make([]*big.Int, w.ThresHold)
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}

		////////
		en := strings.Split(string(enodes[8:]), "@")
		alpha1U1, _ := signing.DECDSA_Sign_Paillier_Decrypt(u1PaillierSk, mkg[en[0]])
		alpha1[k] = alpha1U1
	}

	return alpha1
}

func DecryptCkW(cointype string, idSign sortableIDSSlice, w *RpcReqWorker, u1PaillierSk *ec2.PrivateKey, mkw map[string]*big.Int, ch chan interface{}) []*big.Int {
	if cointype == "" || len(idSign) == 0 || w == nil || u1PaillierSk == nil || len(mkw) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil
	}

	// 2.13
	// decrypt c_kw to get u, MtA(k, w)
	// MtA(k, w)
	uu1 := make([]*big.Int, w.ThresHold)
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}

		////////
		en := strings.Split(string(enodes[8:]), "@")
		u1U1, _ := signing.DECDSA_Sign_Paillier_Decrypt(u1PaillierSk, mkw[en[0]])
		uu1[k] = u1U1
	}

	return uu1
}

func CalcDelta(alpha1 []*big.Int, betaU1 []*big.Int, ch chan interface{}, ThresHold int) *big.Int {
	if len(alpha1) == 0 || len(betaU1) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil
	}

	// 2.14
	// calculate delta, MtA(k, gamma)
	delta1 := alpha1[0]
	for i := 0; i < ThresHold; i++ {
		if i == 0 {
			continue
		}
		delta1 = new(big.Int).Add(delta1, alpha1[i])
	}
	for i := 0; i < ThresHold; i++ {
		delta1 = new(big.Int).Add(delta1, betaU1[i])
	}

	return delta1
}

func CalcSigma(uu1 []*big.Int, vU1 []*big.Int, ch chan interface{}, ThresHold int) *big.Int {
	if len(uu1) == 0 || len(vU1) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil
	}

	// 2.15
	// calculate sigma, MtA(k, w)
	sigma1 := uu1[0]
	for i := 0; i < ThresHold; i++ {
		if i == 0 {
			continue
		}
		sigma1 = new(big.Int).Add(sigma1, uu1[i])
	}
	for i := 0; i < ThresHold; i++ {
		sigma1 = new(big.Int).Add(sigma1, vU1[i])
	}

	return sigma1
}

func DECDSASignRoundFive(msgprex string, cointype string, delta1 *big.Int, idSign sortableIDSSlice, w *RpcReqWorker, ch chan interface{}) *big.Int {
	if cointype == "" || len(idSign) == 0 || w == nil || msgprex == "" || delta1 == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil
	}

	// 3. Broadcast
	// delta: delta1, delta2, delta3
	var s1 string
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "DELTA1"
	zero, _ := new(big.Int).SetString("0", 10)
	if delta1.Cmp(zero) < 0 { //bug
		s1 = "0" + common.SepDel + string(delta1.Bytes())
	} else {
		s1 = string(delta1.Bytes())
	}
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	// 1. Receive Broadcast
	// delta: delta1, delta2, delta3
	common.Info("===================send DELTA1 finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bdelta1)
	common.Info("===================finish get DELTA1, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"DELTA1",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all delta timeout.")}
		ch <- res
		return nil
	}

	var delta1s = make(map[string]*big.Int)
	delta1s[cur_enode] = delta1

	dels := make([]string, w.ThresHold)
	if w.msg_delta1.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all delta fail.")}
		ch <- res
		return nil
	}

	itmp := 0
	iter := w.msg_delta1.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		dels[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}

		////////
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}

		for _, v := range dels {
			mm := strings.Split(v, common.Sep)
			if len(mm) < 3 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_delta1 fail.")}
				ch <- res
				return nil
			}

			prex := mm[0]
			prexs := strings.Split(prex, "-")
			if prexs[len(prexs)-1] == en[0] {
				tmps := strings.Split(mm[2], common.SepDel)
				if len(tmps) == 2 {
					del := new(big.Int).SetBytes([]byte(tmps[1]))
					del = new(big.Int).Sub(zero, del) //bug:-xxxxxxx
					delta1s[en[0]] = del
				} else {
					del := new(big.Int).SetBytes([]byte(mm[2]))
					delta1s[en[0]] = del
				}

				break
			}
		}
	}

	// 2. calculate deltaSum
	var deltaSum *big.Int
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		deltaSum = delta1s[en[0]]
		break
	}

	for k, id := range idSign {
		if k == 0 {
			continue
		}

		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		//bug
		if deltaSum == nil || len(en) < 1 || en[0] == "" || delta1s[en[0]] == nil {
			var ret2 Err
			ret2.Info = "calc deltaSum error"
			res := RpcDcrmRes{Ret: "", Err: ret2}
			ch <- res
			return nil
		}
		deltaSum = new(big.Int).Add(deltaSum, delta1s[en[0]])
	}
	deltaSum = new(big.Int).Mod(deltaSum, secp256k1.S256().N)

	return deltaSum
}

func DECDSASignRoundSix(msgprex string, u1Gamma *big.Int, commitU1GammaG *ec2.Commitment, w *RpcReqWorker, ch chan interface{}) *ec2.ZkUProof {
	if msgprex == "" || u1Gamma == nil || commitU1GammaG == nil || w == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil
	}

	u1GammaZKProof := keygen.DECDSA_Key_ZkUProve(u1Gamma)

	// 3. Broadcast
	// commitU1GammaG.D, commitU2GammaG.D, commitU3GammaG.D
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "D11"
	dlen := len(commitU1GammaG.D)
	s1 := strconv.Itoa(dlen)

	ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep
	for _, d := range commitU1GammaG.D {
		ss += string(d.Bytes())
		ss += common.Sep
	}
	ss += string(u1GammaZKProof.E.Bytes()) + common.Sep + string(u1GammaZKProof.S.Bytes()) + common.Sep
	ss = ss + "NULL"
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	// 1. Receive Broadcast
	// commitU1GammaG.D, commitU2GammaG.D, commitU3GammaG.D
	common.Info("===================send D11 finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bd11_1)
	common.Info("===================finish get D11, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"D11",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all d11 fail.")}
		ch <- res
		return nil
	}

	return u1GammaZKProof
}

func DECDSASignVerifyCommitment(cointype string, w *RpcReqWorker, idSign sortableIDSSlice, commitU1GammaG *ec2.Commitment, u1GammaZKProof *ec2.ZkUProof, ch chan interface{}) map[string][]*big.Int {
	if cointype == "" || w == nil || len(idSign) == 0 || commitU1GammaG == nil || u1GammaZKProof == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil
	}

	d11s := make([]string, w.ThresHold)
	if w.msg_d11_1.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all d11 fail.")}
		ch <- res
		return nil
	}

	itmp := 0
	iter := w.msg_d11_1.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		d11s[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	c11s := make([]string, w.ThresHold)
	if w.msg_c11.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all c11 fail.")}
		ch <- res
		return nil
	}

	itmp = 0
	iter = w.msg_c11.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		c11s[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	// 2. verify and de-commitment to get GammaG

	// for all nodes, construct the commitment by the receiving C and D
	var udecom = make(map[string]*ec2.Commitment)
	for _, v := range c11s {
		mm := strings.Split(v, common.Sep)
		if len(mm) < 3 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_c11 fail.")}
			ch <- res
			return nil
		}

		prex := mm[0]
		prexs := strings.Split(prex, "-")
		for _, vv := range d11s {
			mmm := strings.Split(vv, common.Sep)
			if len(mmm) < 3 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_d11 fail.")}
				ch <- res
				return nil
			}

			prex2 := mmm[0]
			prexs2 := strings.Split(prex2, "-")
			if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
				dlen, _ := strconv.Atoi(mmm[2])
				var gg = make([]*big.Int, 0)
				l := 0
				for j := 0; j < dlen; j++ {
					l++
					if len(mmm) < (3 + l) {
						res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_d11 fail.")}
						ch <- res
						return nil
					}

					gg = append(gg, new(big.Int).SetBytes([]byte(mmm[2+l])))
				}

				deCommit := &ec2.Commitment{C: new(big.Int).SetBytes([]byte(mm[2])), D: gg}
				udecom[prexs[len(prexs)-1]] = deCommit
				break
			}
		}
	}

	deCommit_commitU1GammaG := &ec2.Commitment{C: commitU1GammaG.C, D: commitU1GammaG.D}
	udecom[cur_enode] = deCommit_commitU1GammaG

	var zkuproof = make(map[string]*ec2.ZkUProof)
	zkuproof[cur_enode] = u1GammaZKProof
	for _, vv := range d11s {
		mmm := strings.Split(vv, common.Sep)
		prex2 := mmm[0]
		prexs2 := strings.Split(prex2, "-")
		dlen, _ := strconv.Atoi(mmm[2])
		e := new(big.Int).SetBytes([]byte(mmm[3+dlen]))
		s := new(big.Int).SetBytes([]byte(mmm[4+dlen]))
		zkuf := &ec2.ZkUProof{E: e, S: s}
		zkuproof[prexs2[len(prexs2)-1]] = zkuf
	}

	// for all nodes, verify the commitment
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}
		////////
		en := strings.Split(string(enodes[8:]), "@")
		//bug
		if len(en) <= 0 || en[0] == "" {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			ch <- res
			return nil
		}

		_, exsit := udecom[en[0]]
		if exsit == false {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			ch <- res
			return nil
		}
		//

		if udecom[en[0]] == nil {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			ch <- res
			return nil
		}

		if keygen.DECDSA_Key_Commitment_Verify(udecom[en[0]]) == false {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			ch <- res
			return nil
		}
	}

	// for all nodes, de-commitment
	var ug = make(map[string][]*big.Int)
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		_, u1GammaG := signing.DECDSA_Key_DeCommit(udecom[en[0]])
		ug[en[0]] = u1GammaG
		if keygen.DECDSA_Key_ZkUVerify(u1GammaG, zkuproof[en[0]]) == false {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify zkuproof fail.")}
			ch <- res
			return nil
		}
	}

	return ug
}

func Calc_r(cointype string, w *RpcReqWorker, idSign sortableIDSSlice, ug map[string][]*big.Int, deltaSum *big.Int, ch chan interface{}) (*big.Int, *big.Int) {
	if cointype == "" || w == nil || len(idSign) == 0 || len(ug) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil, nil
	}

	// for all nodes, calculate the GammaGSum
	var GammaGSumx *big.Int
	var GammaGSumy *big.Int
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil, nil
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		GammaGSumx = (ug[en[0]])[0]
		GammaGSumy = (ug[en[0]])[1]
		break
	}

	for k, id := range idSign {
		if k == 0 {
			continue
		}

		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil, nil
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		GammaGSumx, GammaGSumy = secp256k1.S256().Add(GammaGSumx, GammaGSumy, (ug[en[0]])[0], (ug[en[0]])[1])
	}

	r, deltaGammaGy := signing.DECDSA_Sign_Calc_r(deltaSum, GammaGSumx, GammaGSumy)

	zero, _ := new(big.Int).SetString("0", 10)
	if r.Cmp(zero) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("r == 0.")}
		ch <- res
		return nil, nil
	}

	return r, deltaGammaGy
}

func DECDSASignRoundSeven(msgprex string, r *big.Int, deltaGammaGy *big.Int, us1 *big.Int, w *RpcReqWorker, ch chan interface{}) (*ec2.Commitment, []string, *big.Int, *big.Int) {
	if msgprex == "" || r == nil || deltaGammaGy == nil || us1 == nil || w == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil, nil, nil, nil
	}

	commitBigVAB1, rho1, l1 := signing.DECDSA_Sign_Round_Seven(r, deltaGammaGy, us1)

	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "CommitBigVAB"
	s1 := string(commitBigVAB1.C.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	common.Info("===================send CommitBigVAB finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bcommitbigvab)
	common.Info("===================finish get CommitBigVAB, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"CommitBigVAB",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all CommitBigVAB timeout.")}
		ch <- res
		return nil, nil, nil, nil
	}

	commitbigvabs := make([]string, w.ThresHold)
	if w.msg_commitbigvab.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all CommitBigVAB fail.")}
		ch <- res
		return nil, nil, nil, nil
	}

	itmp := 0
	iter := w.msg_commitbigvab.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		commitbigvabs[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	return commitBigVAB1, commitbigvabs, rho1, l1
}

func DECDSASignRoundEight(msgprex string, r *big.Int, deltaGammaGy *big.Int, us1 *big.Int, l1 *big.Int, rho1 *big.Int, w *RpcReqWorker, ch chan interface{}, commitBigVAB1 *ec2.Commitment) (*ec2.ZkABProof, []string) {
	if msgprex == "" || r == nil || deltaGammaGy == nil || us1 == nil || w == nil || l1 == nil || rho1 == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil, nil
	}

	// *** Round 5B
	u1zkABProof := signing.DECDSA_Sign_ZkABProve(rho1, l1, us1, []*big.Int{r, deltaGammaGy})

	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "ZKABPROOF"
	dlen := len(commitBigVAB1.D)
	s1 := strconv.Itoa(dlen)

	ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep
	for _, d := range commitBigVAB1.D {
		ss += string(d.Bytes())
		ss += common.Sep
	}

	dlen = len(u1zkABProof.Alpha)
	s22 := strconv.Itoa(dlen)
	ss += (s22 + common.Sep)
	for _, alp := range u1zkABProof.Alpha {
		ss += string(alp.Bytes())
		ss += common.Sep
	}

	dlen = len(u1zkABProof.Beta)
	s3 := strconv.Itoa(dlen)
	ss += (s3 + common.Sep)
	for _, bet := range u1zkABProof.Beta {
		ss += string(bet.Bytes())
		ss += common.Sep
	}

	//ss = prex-enode:ZKABPROOF:dlen:d1:d2:...:dl:alplen:a1:a2:....aalp:betlen:b1:b2:...bbet:t:u:NULL
	ss += (string(u1zkABProof.T.Bytes()) + common.Sep + string(u1zkABProof.U.Bytes()) + common.Sep)
	ss = ss + "NULL"
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	common.Info("===================send ZKABPROOF finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bzkabproof)
	common.Info("===================finish get ZKABPROOF, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"ZKABPROOF",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all ZKABPROOF timeout.")}
		ch <- res
		return nil, nil
	}

	zkabproofs := make([]string, w.ThresHold)
	if w.msg_zkabproof.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all ZKABPROOF fail.")}
		ch <- res
		return nil, nil
	}

	itmp := 0
	iter := w.msg_zkabproof.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		zkabproofs[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	return u1zkABProof, zkabproofs
}

func DECDSASignVerifyBigVAB(cointype string, w *RpcReqWorker, commitbigvabs []string, zkabproofs []string, commitBigVAB1 *ec2.Commitment, u1zkABProof *ec2.ZkABProof, idSign sortableIDSSlice, r *big.Int, deltaGammaGy *big.Int, ch chan interface{}) (map[string]*ec2.Commitment, *big.Int, *big.Int) {
	if len(commitbigvabs) == 0 || len(zkabproofs) == 0 || commitBigVAB1 == nil || u1zkABProof == nil || cointype == "" || w == nil || len(idSign) == 0 || r == nil || deltaGammaGy == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return nil, nil, nil
	}

	var commitbigcom = make(map[string]*ec2.Commitment)
	for _, v := range commitbigvabs {
		mm := strings.Split(v, common.Sep)
		if len(mm) < 3 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_commitbigvab fail.")}
			ch <- res
			return nil, nil, nil
		}

		prex := mm[0]
		prexs := strings.Split(prex, "-")
		for _, vv := range zkabproofs {
			mmm := strings.Split(vv, common.Sep)
			if len(mmm) < 3 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_zkabproof fail.")}
				ch <- res
				return nil, nil, nil
			}

			prex2 := mmm[0]
			prexs2 := strings.Split(prex2, "-")
			if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
				dlen, _ := strconv.Atoi(mmm[2])
				var gg = make([]*big.Int, 0)
				l := 0
				for j := 0; j < dlen; j++ {
					l++
					if len(mmm) < (3 + l) {
						res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_zkabproof fail.")}
						ch <- res
						return nil, nil, nil
					}

					gg = append(gg, new(big.Int).SetBytes([]byte(mmm[2+l])))
				}

				deCommit := &ec2.Commitment{C: new(big.Int).SetBytes([]byte(mm[2])), D: gg}
				commitbigcom[prexs[len(prexs)-1]] = deCommit
				break
			}
		}
	}

	commitbigcom[cur_enode] = commitBigVAB1

	var zkabproofmap = make(map[string]*ec2.ZkABProof)
	zkabproofmap[cur_enode] = u1zkABProof

	for _, vv := range zkabproofs {
		mmm := strings.Split(vv, common.Sep)
		prex2 := mmm[0]
		prexs2 := strings.Split(prex2, "-")

		//alpha
		dlen, _ := strconv.Atoi(mmm[2])
		alplen, _ := strconv.Atoi(mmm[3+dlen])
		var alp = make([]*big.Int, 0)
		l := 0
		for j := 0; j < alplen; j++ {
			l++
			if len(mmm) < (4 + dlen + l) {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_zkabproof fail.")}
				ch <- res
				return nil, nil, nil
			}

			alp = append(alp, new(big.Int).SetBytes([]byte(mmm[3+dlen+l])))
		}

		//beta
		betlen, _ := strconv.Atoi(mmm[3+dlen+1+alplen])
		var bet = make([]*big.Int, 0)
		l = 0
		for j := 0; j < betlen; j++ {
			l++
			if len(mmm) < (5 + dlen + alplen + l) {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_zkabproof fail.")}
				ch <- res
				return nil, nil, nil
			}

			bet = append(bet, new(big.Int).SetBytes([]byte(mmm[3+dlen+1+alplen+l])))
		}

		t := new(big.Int).SetBytes([]byte(mmm[3+dlen+1+alplen+1+betlen]))
		u := new(big.Int).SetBytes([]byte(mmm[3+dlen+1+alplen+1+betlen+1]))

		zkABProof := &ec2.ZkABProof{Alpha: alp, Beta: bet, T: t, U: u}
		zkabproofmap[prexs2[len(prexs2)-1]] = zkABProof
	}

	var BigVx, BigVy *big.Int
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil, nil, nil
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		if keygen.DECDSA_Key_Commitment_Verify(commitbigcom[en[0]]) == false {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commitbigvab fail.")}
			ch <- res
			return nil, nil, nil
		}

		_, BigVAB1 := signing.DECDSA_Key_DeCommit(commitbigcom[en[0]])
		if signing.DECDSA_Sign_ZkABVerify([]*big.Int{BigVAB1[2], BigVAB1[3]}, []*big.Int{BigVAB1[4], BigVAB1[5]}, []*big.Int{BigVAB1[0], BigVAB1[1]}, []*big.Int{r, deltaGammaGy}, zkabproofmap[en[0]]) == false {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify zkabproof fail.")}
			ch <- res
			return nil, nil, nil
		}

		if k == 0 {
			BigVx = BigVAB1[0]
			BigVy = BigVAB1[1]
			continue
		}

		BigVx, BigVy = secp256k1.S256().Add(BigVx, BigVy, BigVAB1[0], BigVAB1[1])
	}

	return commitbigcom, BigVx, BigVy
}

func DECDSASignRoundNine(msgprex string, cointype string, w *RpcReqWorker, idSign sortableIDSSlice, mMtA *big.Int, r *big.Int, pkx *big.Int, pky *big.Int, BigVx *big.Int, BigVy *big.Int, rho1 *big.Int, commitbigcom map[string]*ec2.Commitment, l1 *big.Int, ch chan interface{}) ([]string, *ec2.Commitment) {
	//if len(idSign) == 0 || len(commitbigcom) == 0 || msgprex == "" || w == nil || cointype == "" || mMtA == nil || r == nil || pkx == nil || pky == nil || l1 == nil || rho1 == nil {
	//	res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error.")}
	//	ch <- res
	//	return nil, nil
	//}

	bigU1x, bigU1y := signing.DECDSA_Sign_Round_Nine(mMtA, r, pkx, pky, BigVx, BigVy, rho1)

	// bigA23 = bigA2 + bigA3
	var bigT1x, bigT1y *big.Int
	var ind int
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil, nil
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}

		_, BigVAB1 := signing.DECDSA_Key_DeCommit(commitbigcom[en[0]])
		bigT1x = BigVAB1[2]
		bigT1y = BigVAB1[3]
		ind = k
		break
	}

	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil, nil
		}
		////////
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}

		if k == ind {
			continue
		}

		_, BigVAB1 := signing.DECDSA_Key_DeCommit(commitbigcom[en[0]])
		bigT1x, bigT1y = secp256k1.S256().Add(bigT1x, bigT1y, BigVAB1[2], BigVAB1[3])
	}

	commitBigUT1 := signing.DECDSA_Sign_Round_Nine_Commitment(bigT1x, bigT1y, l1, bigU1x, bigU1y)

	// Broadcast commitBigUT1.C
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "CommitBigUT"
	s1 := string(commitBigUT1.C.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	common.Info("===================send CommitBigUT finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bcommitbigut)
	common.Info("===================finish get CommitBigUT, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"CommitBigUT",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all CommitBigUT timeout.")}
		ch <- res
		return nil, nil
	}

	commitbiguts := make([]string, w.ThresHold)
	if w.msg_commitbigut.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all CommitBigUT fail.")}
		ch <- res
		return nil, nil
	}

	itmp := 0
	iter := w.msg_commitbigut.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		commitbiguts[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	return commitbiguts, commitBigUT1
}

func DECDSASignRoundTen(msgprex string, commitBigUT1 *ec2.Commitment, w *RpcReqWorker, ch chan interface{}) []string {
	if msgprex == "" || commitBigUT1 == nil || w == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return nil
	}

	// *** Round 5D
	// Broadcast
	// commitBigUT1.D,  commitBigUT2.D,  commitBigUT3.D
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "CommitBigUTD11"
	dlen := len(commitBigUT1.D)
	s1 := strconv.Itoa(dlen)

	ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep
	for _, d := range commitBigUT1.D {
		ss += string(d.Bytes())
		ss += common.Sep
	}
	ss = ss + "NULL"
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	common.Info("===================send CommitBigUTD11 finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bcommitbigutd11)
	common.Info("===================finish get CommitBigUTD11, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"CommitBigUTD11",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all CommitBigUTD11 fail.")}
		ch <- res
		return nil
	}

	commitbigutd11s := make([]string, w.ThresHold)
	if w.msg_commitbigutd11.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all CommitBigUTD11 fail.")}
		ch <- res
		return nil
	}

	itmp := 0
	iter := w.msg_commitbigutd11.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		commitbigutd11s[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	return commitbigutd11s
}

func DECDSASignVerifyBigUTCommitment(cointype string, commitbiguts []string, commitbigutd11s []string, commitBigUT1 *ec2.Commitment, w *RpcReqWorker, idSign sortableIDSSlice, ch chan interface{}, commitbigcom map[string]*ec2.Commitment) bool {
	if cointype == "" || len(commitbiguts) == 0 || len(commitbigutd11s) == 0 || commitBigUT1 == nil || w == nil || len(idSign) == 0 || commitbigcom == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return false
	}

	var commitbigutmap = make(map[string]*ec2.Commitment)
	for _, v := range commitbiguts {
		mm := strings.Split(v, common.Sep)
		if len(mm) < 3 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_commitbigut fail.")}
			ch <- res
			return false
		}

		prex := mm[0]
		prexs := strings.Split(prex, "-")
		for _, vv := range commitbigutd11s {
			mmm := strings.Split(vv, common.Sep)
			if len(mmm) < 3 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_commitbigutd11 fail.")}
				ch <- res
				return false
			}

			prex2 := mmm[0]
			prexs2 := strings.Split(prex2, "-")
			if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
				dlen, _ := strconv.Atoi(mmm[2])
				var gg = make([]*big.Int, 0)
				l := 0
				for j := 0; j < dlen; j++ {
					l++
					if len(mmm) < (3 + l) {
						res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_commitbigutd11 fail.")}
						ch <- res
						return false
					}

					gg = append(gg, new(big.Int).SetBytes([]byte(mmm[2+l])))
				}

				deCommit := &ec2.Commitment{C: new(big.Int).SetBytes([]byte(mm[2])), D: gg}
				commitbigutmap[prexs[len(prexs)-1]] = deCommit
				break
			}
		}
	}

	commitbigutmap[cur_enode] = commitBigUT1

	var bigTBx, bigTBy *big.Int
	var bigUx, bigUy *big.Int
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return false
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		if keygen.DECDSA_Key_Commitment_Verify(commitbigutmap[en[0]]) == false {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit big ut fail.")}
			ch <- res
			return false
		}

		_, BigUT1 := signing.DECDSA_Key_DeCommit(commitbigutmap[en[0]])
		_, BigVAB1 := signing.DECDSA_Key_DeCommit(commitbigcom[en[0]])
		if k == 0 {
			bigTBx = BigUT1[2]
			bigTBy = BigUT1[3]
			bigUx = BigUT1[0]
			bigUy = BigUT1[1]
			bigTBx, bigTBy = secp256k1.S256().Add(bigTBx, bigTBy, BigVAB1[4], BigVAB1[5])
			continue
		}

		bigTBx, bigTBy = secp256k1.S256().Add(bigTBx, bigTBy, BigUT1[2], BigUT1[3])
		bigTBx, bigTBy = secp256k1.S256().Add(bigTBx, bigTBy, BigVAB1[4], BigVAB1[5])
		bigUx, bigUy = secp256k1.S256().Add(bigUx, bigUy, BigUT1[0], BigUT1[1])
	}

	if bigTBx.Cmp(bigUx) != 0 || bigTBy.Cmp(bigUy) != 0 {
		fmt.Println("verify bigTB = BigU fails.")
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify bigTB = BigU fails.")}
		ch <- res
		return false
	}

	return true
}

func DECDSASignRoundEleven(msgprex string, cointype string, w *RpcReqWorker, idSign sortableIDSSlice, ch chan interface{}, us1 *big.Int) map[string]*big.Int {
	if cointype == "" || msgprex == "" || w == nil || len(idSign) == 0 || us1 == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return nil
	}

	// 4. Broadcast
	// s: s1, s2, s3
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "SS1"
	s1 := string(us1.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	// 1. Receive Broadcast
	// s: s1, s2, s3
	common.Info("===================send SS1 finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bss1)
	common.Info("===================finish get SS1, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"SS1",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ss1 timeout.")}
		ch <- res
		return nil
	}

	var ss1s = make(map[string]*big.Int)
	ss1s[cur_enode] = us1

	uss1s := make([]string, w.ThresHold)
	if w.msg_ss1.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get ss1 fail.")}
		ch <- res
		return nil
	}

	itmp := 0
	iter := w.msg_ss1.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		uss1s[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}
		////////
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}

		for _, v := range uss1s {
			mm := strings.Split(v, common.Sep)
			if len(mm) < 3 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get ss1 fail.")}
				ch <- res
				return nil
			}

			prex := mm[0]
			prexs := strings.Split(prex, "-")
			if prexs[len(prexs)-1] == en[0] {
				tmp := new(big.Int).SetBytes([]byte(mm[2]))
				ss1s[en[0]] = tmp
				break
			}
		}
	}

	return ss1s
}

func Calc_s(cointype string, w *RpcReqWorker, idSign sortableIDSSlice, ss1s map[string]*big.Int, ch chan interface{}) *big.Int {
	if cointype == "" || len(idSign) == 0 || w == nil || len(ss1s) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return nil
	}

	// 2. calculate s
	var s *big.Int
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		s = ss1s[en[0]]
		break
	}

	for k, id := range idSign {
		if k == 0 {
			continue
		}

		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}
		////////
		en := strings.Split(string(enodes[8:]), "@")

		//bug
		if s == nil || len(en) == 0 || en[0] == "" || len(ss1s) == 0 || ss1s[en[0]] == nil {
			fmt.Println("=================================== !!!Sign_ec2,calc s error. !!! =======================================")
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("calculate s error.")}
			ch <- res
			return nil
		}
		//
		s = new(big.Int).Add(s, ss1s[en[0]])
	}

	s = new(big.Int).Mod(s, secp256k1.S256().N)

	return s
}

func GetPaillierPk2(cointype string,w *RpcReqWorker,uid *big.Int) *ec2.PublicKey {
	if cointype == "" || w == nil || uid == nil {
		return nil
	}

	key := Keccak256Hash([]byte(strings.ToLower(w.DcrmFrom))).Hex()
	exsit,da := GetValueFromPubKeyData(key)
	if exsit == false {
	    return nil 
	}

	pubs,ok := da.(*PubKeyData)
	if ok == false {
	    return nil
	}

	_, nodes := GetGroup(pubs.GroupId)
	others := strings.Split(nodes, common.Sep2)
	for _, v := range others {
		node2 := ParseNode(v) //bug??
		uid2 := DoubleHash(node2, cointype)
		if uid2.Cmp(uid) == 0 {
		    iter := w.msg_paillierkey.Front() //////by type
		    for iter != nil {
			if iter.Value == nil {
			    iter = iter.Next()
			    continue
			}

			mdss,ok := iter.Value.(string)
			if ok == false {
			    iter = iter.Next()
			    continue
			}

			ms := strings.Split(mdss, common.Sep)
			prexs := strings.Split(ms[0], "-")
			if len(prexs) < 2 {
			    iter = iter.Next()
			    continue
			}

			node3 := prexs[1]
			if strings.EqualFold(node3,node2) {
			    l := ms[2]
			    n := new(big.Int).SetBytes([]byte(ms[3]))
			    g := new(big.Int).SetBytes([]byte(ms[4]))
			    n2 := new(big.Int).SetBytes([]byte(ms[5]))
			    publicKey := &ec2.PublicKey{Length: l, N: n, G: g, N2: n2}
			    return publicKey
			}

			iter = iter.Next()
		    }

		    break
		}
	}

	return nil
}

func GetRealByUid(cointype string,w *RpcReqWorker,uid *big.Int) int {
    if cointype == "ED25519" || cointype == "ECDSA" {
	return GetRealByUid2(cointype,w,uid)
    }

    if cointype == "" || w == nil || w.DcrmFrom == "" || uid == nil {
	return -1
    }

    key := Keccak256Hash([]byte(strings.ToLower(w.DcrmFrom))).Hex()
    exsit,da := GetValueFromPubKeyData(key)
    if exsit == false {
	return -1
    }

    pubs,ok := da.(*PubKeyData)
    if ok == false {
	return -1
    }

    ids := GetIds(cointype, pubs.GroupId)
    for k,v := range ids {
	if v.Cmp(uid) == 0 {
	    return k
	}
    }

    return -1
}

func GetRealByUid2(keytype string,w *RpcReqWorker,uid *big.Int) int {
    if keytype == "" || w == nil || w.DcrmFrom == "" || uid == nil {
	return -1
    }

    dcrmpks, _ := hex.DecodeString(w.DcrmFrom)
    exsit,da := GetValueFromPubKeyData(string(dcrmpks[:]))
    if exsit == false {
	return -1
    }

    pubs,ok := da.(*PubKeyData)
    if ok == false {
	return -1
    }

    ids := GetIds2(keytype, pubs.GroupId)
    for k,v := range ids {
	if v.Cmp(uid) == 0 {
	    return k
	}
    }

    return -1
}

//msgprex = hash
//return value is the backup for the dcrm sig
func Sign_ec2(msgprex string, save string, message string, cointype string, pkx *big.Int, pky *big.Int, ch chan interface{}, id int) string {
	if id < 0 || id >= len(workers) {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("no find worker.")}
		ch <- res
		return ""
	}
	w := workers[id]
	if w.groupid == "" {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get group id fail.")}
		ch <- res
		return ""
	}

	hashBytes, err2 := hex.DecodeString(message)
	if err2 != nil {
		res := RpcDcrmRes{Ret: "", Err: err2}
		ch <- res
		return ""
	}

	mm := strings.Split(save, common.SepSave)
	if len(mm) == 0 {
		fmt.Printf("%v =============Sign_ec2,get save data fail. save = %v,key = %v ================\n", common.CurrentTime(), save, msgprex)
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get save data fail")}
		ch <- res
		return ""
	}

	// [Notes]
	// 1. assume the nodes who take part in the signature generation as follows
	ids := GetIds(cointype, w.groupid)
	idSign := ids[:w.ThresHold]
	mMtA, _ := new(big.Int).SetString(message, 16)
	//fmt.Printf("%v =============Sign_ec2, w.ThresHold = %v, key = %v ================\n", common.CurrentTime(), w.ThresHold, msgprex)

	//*******************!!!Distributed ECDSA Sign Start!!!**********************************

	skU1, w1 := MapPrivKeyShare(cointype, w, idSign, mm[0])
	if skU1 == nil || w1 == nil {
	    ////////test reshare///////////////////////
	    /*fmt.Printf("%v =============Sign_ec2,cur node not take part in reshare,key = %v ================\n", common.CurrentTime(), msgprex)
	    key := Keccak256Hash([]byte(strings.ToLower(w.DcrmFrom))).Hex()
	    exsit,da := GetValueFromPubKeyData(key)
	    if exsit == false {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get save data fail")}
		ch <- res
		return ""
	    }

	    pubs,ok := da.(*PubKeyData)
	    if ok == false {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get save data fail")}
		ch <- res
		return ""
	    }

	    ids = GetIds(cointype, pubs.GroupId)
	    
	    _, tip, cherr := GetChannelValue(ch_t, w.bc11)
	    suss := false
	    if cherr != nil {
		suss = ReqDataFromGroup(msgprex,w.id,"C11",reqdata_trytimes,reqdata_timeout)
	    } else {
		suss = true
	    }
	    if !suss {
		    res := RpcDcrmRes{Ret: "", Tip: tip, Err: GetRetErr(ErrGetC11Timeout)}
		    ch <- res
		    return ""
	    }

	    _, tip, cherr = GetChannelValue(ch_t, w.bss1)
	    suss = false
	    if cherr != nil {
		suss = ReqDataFromGroup(msgprex,w.id,"SS1",reqdata_trytimes,reqdata_timeout)
	    } else {
		suss = true
	    }
	    if !suss {
		    res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ss1 timeout")}
		    ch <- res
		    return ""
	    }

	    _, tip, cherr = GetChannelValue(ch_t, w.bd11_1)
	    suss = false
	    if cherr != nil {
		suss = ReqDataFromGroup(msgprex,w.id,"D11",reqdata_trytimes,reqdata_timeout)
	    } else {
		suss = true
	    }
	    if !suss {
		    res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get d11 timeout")}
		    ch <- res
		    return "" 
	    }

	    ss1s2 := make([]string, w.ThresHold)
	    if w.msg_ss1.Len() != w.ThresHold {
		    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all ss1 fail.")}
		    ch <- res
		    return ""
	    }

	    itmp := 0
	    iter := w.msg_ss1.Front()
	    for iter != nil {
		    mdss := iter.Value.(string)
		    ss1s2[itmp] = mdss
		    iter = iter.Next()
		    itmp++
	    }

	    c11s := make([]string, w.ThresHold)
	    if w.msg_c11.Len() != w.ThresHold {
		    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all c11 fail.")}
		    ch <- res
		    return ""
	    }

	    itmp = 0
	    iter = w.msg_c11.Front()
	    for iter != nil {
		    mdss := iter.Value.(string)
		    c11s[itmp] = mdss
		    iter = iter.Next()
		    itmp++
	    }

	    // for all nodes, construct the commitment by the receiving C and D
	    var udecom = make(map[string]*ec2.Commitment)
	    for _, v := range c11s {
		    mm := strings.Split(v, common.Sep)
		    if len(mm) < 3 {
			    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_c11 fail.")}
			    ch <- res
			    return ""
		    }

		    prex := mm[0]
		    prexs := strings.Split(prex, "-")
		    for _, vv := range ss1s2 {
			    mmm := strings.Split(vv, common.Sep)
			    if len(mmm) < 3 {
				    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_ss1 fail.")}
				    ch <- res
				    return ""
			    }

			    prex2 := mmm[0]
			    prexs2 := strings.Split(prex2, "-")
			    if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
				    dlen, _ := strconv.Atoi(mmm[2])
				    var gg = make([]*big.Int, 0)
				    l := 0
				    for j := 0; j < dlen; j++ {
					    l++
					    if len(mmm) < (3 + l) {
						    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_ss1 fail.")}
						    ch <- res
						    return ""
					    }

					    gg = append(gg, new(big.Int).SetBytes([]byte(mmm[2+l])))
				    }

				    deCommit := &ec2.Commitment{C: new(big.Int).SetBytes([]byte(mm[2])), D: gg}
				    udecom[prexs[len(prexs)-1]] = deCommit
				    break
			    }
		    }
	    }

	    // for all nodes, verify the commitment
	    for _, id := range idSign {
		    enodes := GetEnodesByUid(id, cointype, w.groupid)
		    ////////bug
		    if len(enodes) < 9 {
			    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			    ch <- res
			    return ""
		    }
		    ////////
		    en := strings.Split(string(enodes[8:]), "@")
		    //bug
		    if len(en) <= 0 || en[0] == "" {
			    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			    ch <- res
			    return ""
		    }

		    _, exsit := udecom[en[0]]
		    if exsit == false {
			    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			    ch <- res
			    return ""
		    }
		    //

		    if udecom[en[0]] == nil {
			    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			    ch <- res
			    return ""
		    }

		    if keygen.DECDSA_Key_Commitment_Verify(udecom[en[0]]) == false {
			    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			    ch <- res
			    return ""
		    }
	    }

	    var sstruct = make(map[string]*ec2.ShareStruct2)
	    shares := make([]string, w.ThresHold)
	    if w.msg_d11_1.Len() != w.ThresHold {
		    res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetAllSHARE1Fail)}
		    ch <- res
		    return ""
	    }

	    itmp = 0
	    iter = w.msg_d11_1.Front()
	    for iter != nil {
		    mdss := iter.Value.(string)
		    shares[itmp] = mdss
		    iter = iter.Next()
		    itmp++
	    }

	    for _, v := range shares {
		    mm := strings.Split(v, common.Sep)
		    //bug
		    if len(mm) < 4 {
			    fmt.Println("===================!!! KeyGenerate_ECDSA,fill ec2.ShareStruct map error. !!!,Nonce =%s ==================", msgprex)
			    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("fill ec2.ShareStruct map error.")}
			    ch <- res
			    return ""
		    }
		    //
		    ushare := &ec2.ShareStruct2{Id: new(big.Int).SetBytes([]byte(mm[2])), Share: new(big.Int).SetBytes([]byte(mm[3]))}
		    prex := mm[0]
		    prexs := strings.Split(prex, "-")
		    sstruct[prexs[len(prexs)-1]] = ushare
		    fmt.Printf("%v==============resharing, get share, share = %v, v = %v =============\n",common.CurrentTime(),ushare.Share,v)
	    }

	    var upg = make(map[string]*ec2.PolyGStruct2)
	    for _, v := range ss1s2 {
		    mm := strings.Split(v, common.Sep)
		    dlen, _ := strconv.Atoi(mm[2])
		    if len(mm) < (4 + dlen) {
			    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_ss1 data error")}
			    ch <- res
			    return ""
		    }

		    pglen, _ := strconv.Atoi(mm[3+dlen])
		    pglen = (pglen / 2)
		    var pgss = make([][]*big.Int, 0)
		    l := 0
		    for j := 0; j < pglen; j++ {
			    l++
			    var gg = make([]*big.Int, 0)
			    if len(mm) < (4 + dlen + l) {
				    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_ss1 data error")}
				    ch <- res
				    return ""
			    }

			    gg = append(gg, new(big.Int).SetBytes([]byte(mm[3+dlen+l])))
			    l++
			    if len(mm) < (4 + dlen + l) {
				    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_ss1 data error")}
				    ch <- res
				    return ""
			    }
			    gg = append(gg, new(big.Int).SetBytes([]byte(mm[3+dlen+l])))
			    pgss = append(pgss, gg)
		    }

		    ps := &ec2.PolyGStruct2{PolyG: pgss}
		    prex := mm[0]
		    prexs := strings.Split(prex, "-")
		    upg[prexs[len(prexs)-1]] = ps
	    }

	    // 3. verify the share
	    for _, id := range idSign {
		    enodes := GetEnodesByUid(id, cointype, w.groupid)
		    en := strings.Split(string(enodes[8:]), "@")
		    //bug
		    if len(en) == 0 || en[0] == "" || sstruct[en[0]] == nil || upg[en[0]] == nil {
			    res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifySHARE1Fail)}
			    ch <- res
			    return ""
		    }
		    //
		    if keygen.DECDSA_Key_Verify_Share(sstruct[en[0]], upg[en[0]]) == false {
			    res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifySHARE1Fail)}
			    ch <- res
			    return ""
		    }
	    }

	    var newskU1 *big.Int
	    for _, id := range idSign {
		    enodes := GetEnodesByUid(id, cointype, w.groupid)
		    en := strings.Split(string(enodes[8:]), "@")
		    newskU1 = sstruct[en[0]].Share
		    break
	    }

	    for k, id := range idSign {
		    if k == 0 {
			    continue
		    }

		    enodes := GetEnodesByUid(id, cointype, w.groupid)
		    en := strings.Split(string(enodes[8:]), "@")
		    newskU1 = new(big.Int).Add(newskU1, sstruct[en[0]].Share)
	    }
	    newskU1 = new(big.Int).Mod(newskU1, secp256k1.S256().N)

	    //var sharesNewSkU = make([]*vss.ShareStruct2,0)
	    for _,id := range ids {
		fmt.Printf("%v=================resharing, id = %v, key = %v ===================\n",common.CurrentTime(),id,msgprex)
	    }
	    fmt.Printf("%v=================resharing, newskU1 = %v, key = %v ===================\n",common.CurrentTime(),newskU1,msgprex)*/
	    ////////////////////////////////////////////

		return ""
	}

	/////////test reshare //////////
	/*skP1Poly, skP1PolyG, _ := ec2.Vss2Init(w1, w.ThresHold)
	skP1Gx, skP1Gy := secp256k1.S256().ScalarBaseMult(w1.Bytes())
	u1CommitValues := make([]*big.Int, 0)
	u1CommitValues = append(u1CommitValues, skP1Gx)
	u1CommitValues = append(u1CommitValues, skP1Gy)
	for i := 1; i < len(skP1PolyG.PolyG); i++ {
		u1CommitValues = append(u1CommitValues, skP1PolyG.PolyG[i][0])
		u1CommitValues = append(u1CommitValues, skP1PolyG.PolyG[i][1])
	}
	commitSkP1G := new(ec2.Commitment).Commit(u1CommitValues...)

	key := Keccak256Hash([]byte(strings.ToLower(w.DcrmFrom))).Hex()
	exsit,da := GetValueFromPubKeyData(key)
	if exsit == false {
	    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get save data fail")}
	    ch <- res
	    return ""
	}

	pubs,ok := da.(*PubKeyData)
	if ok == false {
	    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get save data fail")}
	    ch <- res
	    return ""
	}

	ids = GetIds(cointype, pubs.GroupId)

	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "C11"
	s1 := string(commitSkP1G.C.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToDcrmGroup(ss, pubs.GroupId)
	DisMsg(ss)

	_, tip, cherr := GetChannelValue(ch_t, w.bc11)
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"C11",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: GetRetErr(ErrGetC11Timeout)}
		ch <- res
		return ""
	}

	skP1Shares, err := keygen.DECDSA_Key_Vss(skP1Poly, ids)
	if err != nil {
		res := RpcDcrmRes{Ret: "", Err: err}
		ch <- res
		return "" 
	}

	for k, id := range ids {
		enodes := GetEnodesByUid(id, cointype, pubs.GroupId)

		if enodes == "" {
			res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetEnodeByUIdFail)}
			ch <- res
			return ""
		}

		if IsCurNode(enodes, cur_enode) {
			continue
		}

		for _, v := range skP1Shares {
			uid := keygen.DECDSA_Key_GetSharesId(v)
			if uid != nil && uid.Cmp(id) == 0 {
				mp := []string{msgprex, cur_enode}
				enode := strings.Join(mp, "-")
				s0 := "D11"
				s2 := string(v.Id.Bytes())
				s3 := string(v.Share.Bytes())
				ss := enode + common.Sep + s0 + common.Sep + s2 + common.Sep + s3
				SendMsgToPeer(enodes, ss)
				fmt.Printf("%v==============resharing, send to k = %v, v = %v =============\n",common.CurrentTime(),k,v)
				break
			}
		}
	}

	for _, v := range skP1Shares {
		uid := keygen.DECDSA_Key_GetSharesId(v)
		if uid == nil {
			continue
		}

		enodes := GetEnodesByUid(uid, cointype, pubs.GroupId)
		if IsCurNode(enodes, cur_enode) {
			mp := []string{msgprex, cur_enode}
			enode := strings.Join(mp, "-")
			s0 := "D11"
			s2 := string(v.Id.Bytes())
			s3 := string(v.Share.Bytes())
			ss := enode + common.Sep + s0 + common.Sep + s2 + common.Sep + s3
			DisMsg(ss)
			fmt.Printf("%v==============resharing, send to self, uid = %v, v = %v =============\n",common.CurrentTime(),uid,v)
			break
		}
	}

	mp = []string{msgprex, cur_enode}
	enode = strings.Join(mp, "-")
	s0 = "SS1"
	dlen := len(commitSkP1G.D)
	s1 = strconv.Itoa(dlen)

	ss = enode + common.Sep + s0 + common.Sep + s1 + common.Sep
	for _, d := range commitSkP1G.D {
		ss += string(d.Bytes())
		ss += common.Sep
	}

	pglen := 2 * (len(skP1PolyG.PolyG))
	s4 := strconv.Itoa(pglen)

	ss = ss + s4 + common.Sep

	for _, p := range skP1PolyG.PolyG {
		for _, d := range p {
			ss += string(d.Bytes())
			ss += common.Sep
		}
	}
	ss = ss + "NULL"
	SendMsgToDcrmGroup(ss, pubs.GroupId)
	DisMsg(ss)
	
	_, tip, cherr = GetChannelValue(ch_t, w.bss1)
	suss = false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"SS1",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ss1 timeout")}
		ch <- res
		return ""
	}

	_, tip, cherr = GetChannelValue(ch_t, w.bd11_1)
	suss = false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"D11",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get d11 timeout")}
		ch <- res
		return "" 
	}

	ss1s2 := make([]string, w.ThresHold)
	if w.msg_ss1.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all ss1 fail.")}
		ch <- res
		return ""
	}

	itmp := 0
	iter := w.msg_ss1.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		ss1s2[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	c11s := make([]string, w.ThresHold)
	if w.msg_c11.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all c11 fail.")}
		ch <- res
		return ""
	}

	itmp = 0
	iter = w.msg_c11.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		c11s[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	// for all nodes, construct the commitment by the receiving C and D
	var udecom = make(map[string]*ec2.Commitment)
	for _, v := range c11s {
		mm := strings.Split(v, common.Sep)
		if len(mm) < 3 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_c11 fail.")}
			ch <- res
			return ""
		}

		prex := mm[0]
		prexs := strings.Split(prex, "-")
		for _, vv := range ss1s2 {
			mmm := strings.Split(vv, common.Sep)
			if len(mmm) < 3 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_ss1 fail.")}
				ch <- res
				return ""
			}

			prex2 := mmm[0]
			prexs2 := strings.Split(prex2, "-")
			if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
				dlen, _ := strconv.Atoi(mmm[2])
				var gg = make([]*big.Int, 0)
				l := 0
				for j := 0; j < dlen; j++ {
					l++
					if len(mmm) < (3 + l) {
						res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_ss1 fail.")}
						ch <- res
						return ""
					}

					gg = append(gg, new(big.Int).SetBytes([]byte(mmm[2+l])))
				}

				deCommit := &ec2.Commitment{C: new(big.Int).SetBytes([]byte(mm[2])), D: gg}
				udecom[prexs[len(prexs)-1]] = deCommit
				break
			}
		}
	}

	// for all nodes, verify the commitment
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return ""
		}
		////////
		en := strings.Split(string(enodes[8:]), "@")
		//bug
		if len(en) <= 0 || en[0] == "" {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			ch <- res
			return ""
		}

		_, exsit := udecom[en[0]]
		if exsit == false {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			ch <- res
			return ""
		}
		//

		if udecom[en[0]] == nil {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			ch <- res
			return ""
		}

		if keygen.DECDSA_Key_Commitment_Verify(udecom[en[0]]) == false {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			ch <- res
			return ""
		}
	}

	var sstruct = make(map[string]*ec2.ShareStruct2)
	shares := make([]string, w.ThresHold)
	if w.msg_d11_1.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetAllSHARE1Fail)}
		ch <- res
		return ""
	}

	itmp = 0
	iter = w.msg_d11_1.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		shares[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	for _, v := range shares {
		mm := strings.Split(v, common.Sep)
		//bug
		if len(mm) < 4 {
			fmt.Println("===================!!! KeyGenerate_ECDSA,fill ec2.ShareStruct map error. !!!,Nonce =%s ==================", msgprex)
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("fill ec2.ShareStruct map error.")}
			ch <- res
			return ""
		}
		//
		ushare := &ec2.ShareStruct2{Id: new(big.Int).SetBytes([]byte(mm[2])), Share: new(big.Int).SetBytes([]byte(mm[3]))}
		prex := mm[0]
		prexs := strings.Split(prex, "-")
		sstruct[prexs[len(prexs)-1]] = ushare
		fmt.Printf("%v==============resharing, get share, share = %v, v = %v =============\n",common.CurrentTime(),ushare.Share,v)
	}

	var upg = make(map[string]*ec2.PolyGStruct2)
	for _, v := range ss1s2 {
		mm := strings.Split(v, common.Sep)
		dlen, _ := strconv.Atoi(mm[2])
		if len(mm) < (4 + dlen) {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_ss1 data error")}
			ch <- res
			return ""
		}

		pglen, _ := strconv.Atoi(mm[3+dlen])
		pglen = (pglen / 2)
		var pgss = make([][]*big.Int, 0)
		l := 0
		for j := 0; j < pglen; j++ {
			l++
			var gg = make([]*big.Int, 0)
			if len(mm) < (4 + dlen + l) {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_ss1 data error")}
				ch <- res
				return ""
			}

			gg = append(gg, new(big.Int).SetBytes([]byte(mm[3+dlen+l])))
			l++
			if len(mm) < (4 + dlen + l) {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_ss1 data error")}
				ch <- res
				return ""
			}
			gg = append(gg, new(big.Int).SetBytes([]byte(mm[3+dlen+l])))
			pgss = append(pgss, gg)
		}

		ps := &ec2.PolyGStruct2{PolyG: pgss}
		prex := mm[0]
		prexs := strings.Split(prex, "-")
		upg[prexs[len(prexs)-1]] = ps
	}

	// 3. verify the share
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		//bug
		if len(en) == 0 || en[0] == "" || sstruct[en[0]] == nil || upg[en[0]] == nil {
			res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifySHARE1Fail)}
			ch <- res
			return ""
		}
		//
		if keygen.DECDSA_Key_Verify_Share(sstruct[en[0]], upg[en[0]]) == false {
			res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifySHARE1Fail)}
			ch <- res
			return ""
		}
	}

	var newskU1 *big.Int
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		newskU1 = sstruct[en[0]].Share
		break
	}

	for k, id := range idSign {
		if k == 0 {
			continue
		}

		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		newskU1 = new(big.Int).Add(newskU1, sstruct[en[0]].Share)
	}
	newskU1 = new(big.Int).Mod(newskU1, secp256k1.S256().N)

	//var sharesNewSkU = make([]*vss.ShareStruct2,0)
	for _,id := range ids {
	    fmt.Printf("%v=================resharing, id = %v, key = %v ===================\n",common.CurrentTime(),id,msgprex)
	}
	fmt.Printf("%v=================resharing, newskU1 = %v, key = %v ===================\n",common.CurrentTime(),newskU1,msgprex)
	return ""*/
	////////////////////////////////

	//fmt.Printf("%v===================sign,map privkey finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	///////gen paillier key
	/*u1PaillierPk, u1PaillierSk := ec2.GenerateKeyPair(PaillierKeyLength)
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "PaillierKey"
	s1 := u1PaillierPk.Length
	s2 := string(u1PaillierPk.N.Bytes())
	s3 := string(u1PaillierPk.G.Bytes())
	s4 := string(u1PaillierPk.N2.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2 + common.Sep + s3 + common.Sep + s4
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	_, _, cherr := GetChannelValue(ch_t, w.bpaillierkey)
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"PaillierKey",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}

	if !suss {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get paillier key fail")}
		ch <- res
		return ""
	}
*/
	///////

	u1K, u1Gamma, commitU1GammaG := DECDSASignRoundOne(msgprex, w, idSign, ch)
	if u1K == nil || u1Gamma == nil || commitU1GammaG == nil {
		return ""
	}
	//fmt.Printf("%v===================sign,round one finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	ukc, ukc2, ukc3 := DECDSASignPaillierEncrypt(cointype, save, w, idSign, u1K, ch)
	if ukc == nil || ukc2 == nil || ukc3 == nil {
		return ""
	}
	//fmt.Printf("%v===================sign,paillier encrypt finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	zk1proof, zkfactproof := DECDSASignRoundTwo(msgprex, cointype, save, w, idSign, ch, u1K, ukc2, ukc3)
	if zk1proof == nil || zkfactproof == nil {
		return ""
	}
	//fmt.Printf("%v===================sign,round two finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	if DECDSASignRoundThree(msgprex, cointype, save, w, idSign, ch, ukc) == false {
		return ""
	}
	//fmt.Printf("%v===================sign,round three finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	if DECDSASignVerifyZKNtilde(msgprex, cointype, save, w, idSign, ch, ukc, ukc3, zk1proof, zkfactproof) == false {
		return ""
	}
	//fmt.Printf("%v===================sign,verify zk ntilde finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	betaU1Star, betaU1, vU1Star, vU1 := signing.GetRandomBetaV(PaillierKeyLength, w.ThresHold)
	//fmt.Printf("%v===================sign,get random betaU1Star/vU1Star finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	mkg, mkg_mtazk2, mkw, mkw_mtazk2, status := DECDSASignRoundFour(msgprex, cointype, save, w, idSign, ukc, ukc3, zkfactproof, u1Gamma, w1, betaU1Star, vU1Star,ch)
	if status != true {
		return ""
	}
	//fmt.Printf("%v===================sign,round four finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	if DECDSASignVerifyZKGammaW(msgprex,cointype, save, w, idSign, ukc, ukc3, zkfactproof, mkg, mkg_mtazk2, mkw, mkw_mtazk2, ch) != true {
		return ""
	}
	//fmt.Printf("%v===================sign,verify zk gamma/w finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	u1PaillierSk := GetSelfPrivKey(cointype, idSign, w, save, ch)
	if u1PaillierSk == nil {
		return ""
	}
	//fmt.Printf("%v===================sign,get self privkey finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	alpha1 := DecryptCkGamma(cointype, idSign, w, u1PaillierSk, mkg, ch)
	if alpha1 == nil {
		return ""
	}
	//fmt.Printf("%v===================sign,decrypt paillier(k)XGamma finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	uu1 := DecryptCkW(cointype, idSign, w, u1PaillierSk, mkw, ch)
	if uu1 == nil {
		return ""
	}
	//fmt.Printf("%v===================sign,decrypt paillier(k)Xw1 finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	delta1 := CalcDelta(alpha1, betaU1, ch, w.ThresHold)
	if delta1 == nil {
		return ""
	}
	//fmt.Printf("%v===================sign,calc delta finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	sigma1 := CalcSigma(uu1, vU1, ch, w.ThresHold)
	if sigma1 == nil {
		return ""
	}
	//fmt.Printf("%v===================sign,calc sigma finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	deltaSum := DECDSASignRoundFive(msgprex, cointype, delta1, idSign, w, ch)
	if deltaSum == nil {
		return ""
	}
	//fmt.Printf("%v===================sign,round five finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	u1GammaZKProof := DECDSASignRoundSix(msgprex, u1Gamma, commitU1GammaG, w, ch)
	if u1GammaZKProof == nil {
		return ""
	}
	//fmt.Printf("%v===================sign,round six finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	ug := DECDSASignVerifyCommitment(cointype, w, idSign, commitU1GammaG, u1GammaZKProof, ch)
	if ug == nil {
		return ""
	}
	//fmt.Printf("%v===================sign,verify commitment finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	r, deltaGammaGy := Calc_r(cointype, w, idSign, ug, deltaSum, ch)
	if r == nil || deltaGammaGy == nil {
		return ""
	}
	//fmt.Printf("%v===================sign,calc r finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	// 5. calculate s
	us1 := signing.CalcUs(mMtA, u1K, r, sigma1)
	//fmt.Printf("%v===================sign,calc self s finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	commitBigVAB1, commitbigvabs, rho1, l1 := DECDSASignRoundSeven(msgprex, r, deltaGammaGy, us1, w, ch)
	if commitBigVAB1 == nil || commitbigvabs == nil || rho1 == nil || l1 == nil {
		return ""
	}
	//fmt.Printf("%v===================sign,round seven finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	u1zkABProof, zkabproofs := DECDSASignRoundEight(msgprex, r, deltaGammaGy, us1, l1, rho1, w, ch, commitBigVAB1)
	if u1zkABProof == nil || zkabproofs == nil {
		return ""
	}
	//fmt.Printf("%v===================sign,round eight finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	commitbigcom, BigVx, BigVy := DECDSASignVerifyBigVAB(cointype, w, commitbigvabs, zkabproofs, commitBigVAB1, u1zkABProof, idSign, r, deltaGammaGy, ch)
	if commitbigcom == nil || BigVx == nil || BigVy == nil {
		return ""
	}
	//fmt.Printf("%v===================sign,verify BigVAB finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	commitbiguts, commitBigUT1 := DECDSASignRoundNine(msgprex, cointype, w, idSign, mMtA, r, pkx, pky, BigVx, BigVy, rho1, commitbigcom, l1, ch)
	if commitbiguts == nil || commitBigUT1 == nil {
		return ""
	}
	//fmt.Printf("%v===================sign,round nine finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	commitbigutd11s := DECDSASignRoundTen(msgprex, commitBigUT1, w, ch)
	if commitbigutd11s == nil {
		return ""
	}
	//fmt.Printf("%v===================sign,round ten finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	if DECDSASignVerifyBigUTCommitment(cointype, commitbiguts, commitbigutd11s, commitBigUT1, w, idSign, ch, commitbigcom) != true {
		return ""
	}
	//fmt.Printf("%v===================sign,verify BigUT commitment finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	ss1s := DECDSASignRoundEleven(msgprex, cointype, w, idSign, ch, us1)
	if ss1s == nil {
		return ""
	}
	//fmt.Printf("%v===================sign,round eleven finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	s := Calc_s(cointype, w, idSign, ss1s, ch)
	if s == nil {
		return ""
	}
	//fmt.Printf("%v===================sign,calc s finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	// 3. justify the s
	bb := false
	halfN := new(big.Int).Div(secp256k1.S256().N, big.NewInt(2))
	if s.Cmp(halfN) > 0 {
		bb = true
		s = new(big.Int).Sub(secp256k1.S256().N, s)
	}

	zero, _ := new(big.Int).SetString("0", 10)
	if s.Cmp(zero) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("s == 0.")}
		ch <- res
		return ""
	}
	//fmt.Printf("%v===================sign,justify s finish, key = %v =====================\n",common.CurrentTime(),msgprex)

	// **[End-Test]  verify signature with MtA
	signature := new(ECDSASignature)
	signature.New()
	signature.SetR(r)
	signature.SetS(s)

	invert := false
	if cointype == "ETH" && bb {
		//recid ^=1
		invert = true
	}
	if cointype == "BTC" && bb {
		//recid ^= 1
		invert = true
	}

	recid := signing.DECDSA_Sign_Calc_v(r, deltaGammaGy, pkx, pky, signature.GetR(), signature.GetS(), hashBytes, invert)
	////check v
	ys := secp256k1.S256().Marshal(pkx,pky)
	pubkeyhex := hex.EncodeToString(ys)
	pbhs := []rune(pubkeyhex)
	if string(pbhs[0:2]) == "0x" {
	    pubkeyhex = string(pbhs[2:])
	}

	rsvBytes1 := append(signature.GetR().Bytes(), signature.GetS().Bytes()...)
	for j := 0; j < 4; j++ {
	    rsvBytes2 := append(rsvBytes1, byte(j))
	    pkr, e := secp256k1.RecoverPubkey(hashBytes,rsvBytes2)
	    pkr2 := hex.EncodeToString(pkr)
	    pbhs2 := []rune(pkr2)
	    if string(pbhs2[0:2]) == "0x" {
		pkr2 = string(pbhs2[2:])
	    }
	    if e == nil && strings.EqualFold(pkr2,pubkeyhex) {
		recid = j
		break
	    }
	}
	/////
	signature.SetRecoveryParam(int32(recid))

	if DECDSA_Sign_Verify_RSV(signature.GetR(), signature.GetS(), signature.GetRecoveryParam(), message, pkx, pky) == false {
		fmt.Printf("%v ===================dcrm sign,verify is false,key = %v=================\n", common.CurrentTime(), msgprex)
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("sign verify fail.")}
		ch <- res
		return ""
	}
	fmt.Printf("%v ===================dcrm sign,verify (r,s) pass,key = %v=================\n", common.CurrentTime(), msgprex)

	signature2 := GetSignString(signature.GetR(), signature.GetS(), signature.GetRecoveryParam(), int(signature.GetRecoveryParam()))
	rstring := "========================== r = " + fmt.Sprintf("%v", signature.GetR()) + " ========================="
	sstring := "========================== s = " + fmt.Sprintf("%v", signature.GetS()) + " =========================="
	fmt.Println(rstring)
	fmt.Println(sstring)
	sigstring := common.CurrentTime() + " ========================== rsv str = " + signature2 + " ===========================\n"
	fmt.Printf(sigstring)
	res := RpcDcrmRes{Ret: signature2, Err: nil}
	ch <- res

	fmt.Printf("%v ===================end dcrm sign,rsv pass, key = %v=================\n", common.CurrentTime(), msgprex)
	//*******************!!!Distributed ECDSA Sign End!!!**********************************

	return ""
}

func SendMsgToDcrmGroup(msg string, groupid string) {
	test := Keccak256Hash([]byte(strings.ToLower(msg))).Hex()
	fmt.Printf("%v =========SendMsgToDcrmGroup,msg = %v,msg hash = %v,send to group id = %v =================\n", common.CurrentTime(), msg, test, groupid)
	BroadcastInGroupOthers(groupid, msg)
}

///
func EncryptMsg(msg string, enodeID string) (string, error) {
	//fmt.Println("=============EncryptMsg,KeyFile = %s,enodeID = %s ================",KeyFile,enodeID)
	hprv, err1 := hex.DecodeString(enodeID)
	if err1 != nil {
		return "", err1
	}

	//fmt.Println("=============EncryptMsg,hprv len = %v ================",len(hprv))
	p := &ecdsa.PublicKey{Curve: crypto.S256(), X: new(big.Int), Y: new(big.Int)}
	half := len(hprv) / 2
	p.X.SetBytes(hprv[:half])
	p.Y.SetBytes(hprv[half:])
	if !p.Curve.IsOnCurve(p.X, p.Y) {
		return "", fmt.Errorf("id is invalid secp256k1 curve point")
	}

	var cm []byte
	pub := ecies.ImportECDSAPublic(p)
	cm, err := ecies.Encrypt(crand.Reader, pub, []byte(msg), nil, nil)
	if err != nil {
		return "", err
	}

	return string(cm), nil
}

func DecryptMsg(cm string) (string, error) {
	//test := Keccak256Hash([]byte(strings.ToLower(cm))).Hex()
	nodeKey, errkey := crypto.LoadECDSA(KeyFile)
	if errkey != nil {
		//fmt.Printf("%v =========DecryptMsg finish crypto.LoadECDSA,err = %v,keyfile = %v,msg hash = %v =================\n", common.CurrentTime(), errkey, KeyFile, test)
		return "", errkey
	}

	prv := ecies.ImportECDSA(nodeKey)
	var m []byte
	m, err := prv.Decrypt([]byte(cm), nil, nil)
	if err != nil {
		//fmt.Printf("%v =========DecryptMsg finish prv.Decrypt,err = %v,keyfile = %v,msg hash = %v =================\n", common.CurrentTime(), err, KeyFile, test)
		return "", err
	}

	return string(m), nil
}

///

func SendMsgToPeer(enodes string, msg string) {
	test := Keccak256Hash([]byte(strings.ToLower(msg))).Hex()
	fmt.Printf("%v =========SendMsgToPeer,msg = %v,msg hash = %v,send to peer = %v =================\n", common.CurrentTime(), msg, test, enodes)
	en := strings.Split(string(enodes[8:]), "@")
	cm, err := EncryptMsg(msg, en[0])
	if err != nil {
		//fmt.Printf("%v =========SendMsgToPeer,encrypt msg fail,err = %v =================\n", common.CurrentTime(), err)
		return
	}

	SendToPeer(enodes, cm)
}

////ed
//msgprex = hash
//return value is the backup for dcrm sig.
func dcrm_sign_ed(msgprex string, txhash string, save string, pk string, cointype string, ch chan interface{}) string {

	txhashs := []rune(txhash)
	if string(txhashs[0:2]) == "0x" {
		txhash = string(txhashs[2:])
	}

	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		logs.Debug("===========get worker fail.=============")
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker", Err: GetRetErr(ErrNoFindWorker)}
		ch <- res
		return ""
	}
	id := w.id

	cur_enode = GetSelfEnode()

	logs.Debug("===================!!!Start!!!====================")

	var ch1 = make(chan interface{}, 1)
	var bak_sig string
	for i:=0;i < recalc_times;i++ {
	    fmt.Printf("%v===============dcrm_sign_ed, recalc i = %v, key = %v ================\n",common.CurrentTime(),i,msgprex)
	    if len(ch1) != 0 {
		<-ch1
	    }

	    w := workers[id]
	    w.Clear2()
	    //fmt.Printf("%v=====================dcrm_sign_ed, i = %v, key = %v ====================\n",common.CurrentTime(),i,msgprex)
	    bak_sig = Sign_ed(msgprex, save, txhash, cointype, pk, ch1, id)
	    ret, _, cherr := GetChannelValue(ch_t, ch1)
	    //fmt.Printf("%v=====================dcrm_sign_ed,ret = %v, cherr = %v, key = %v ====================\n",common.CurrentTime(),ret,cherr,msgprex)
	    if ret != "" && cherr == nil {
		//fmt.Printf("%v=====================dcrm_sign_ed,success sign, ret = %v, cherr = %v, key = %v ====================\n",common.CurrentTime(),ret,cherr,msgprex)
		    res := RpcDcrmRes{Ret: ret, Tip: "", Err: cherr}
		    ch <- res
		    break
	    }
	    
	    time.Sleep(time.Duration(3) * time.Second) //1000 == 1s
	}
	return bak_sig
}

func sign_ed(msgprex string,txhash string,save string, pk string, keytype string, ch chan interface{}) string {

	txhashs := []rune(txhash)
	if string(txhashs[0:2]) == "0x" {
		txhash = string(txhashs[2:])
	}

	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		logs.Debug("===========get worker fail.=============")
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker", Err: GetRetErr(ErrNoFindWorker)}
		ch <- res
		return ""
	}
	id := w.id

	cur_enode = GetSelfEnode()

	logs.Debug("===================!!!Start!!!====================")

	var ch1 = make(chan interface{}, 1)
	var bak_sig string
	for i:=0;i < recalc_times;i++ {
	    fmt.Printf("%v===============sign_ed, recalc i = %v, key = %v ================\n",common.CurrentTime(),i,msgprex)
	    if len(ch1) != 0 {
		<-ch1
	    }

	    w := workers[id]
	    w.Clear2()
	    //fmt.Printf("%v=====================sign_ed, i = %v, key = %v ====================\n",common.CurrentTime(),i,msgprex)
	    bak_sig = Sign_ed(msgprex, save, txhash, keytype, pk, ch1, id)
	    ret, _, cherr := GetChannelValue(ch_t, ch1)
	    //fmt.Printf("%v=====================sign_ed,ret = %v, cherr = %v, key = %v ====================\n",common.CurrentTime(),ret,cherr,msgprex)
	    if ret != "" && cherr == nil {
		//fmt.Printf("%v=====================sign_ed,success sign, ret = %v, cherr = %v, key = %v ====================\n",common.CurrentTime(),ret,cherr,msgprex)
		    res := RpcDcrmRes{Ret: ret, Tip: "", Err: cherr}
		    ch <- res
		    break
	    }
	    
	    time.Sleep(time.Duration(3) * time.Second) //1000 == 1s
	}
	return bak_sig
}

//msgprex = hash
//return value is the backup for the dcrm sig
func Sign_ed(msgprex string, save string, message string, cointype string, pk string, ch chan interface{}, id int) string {
	defer func() {
		if e := recover(); e != nil {
			fmt.Errorf("Sign_ed,Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	}()

	logs.Debug("===================Sign_ed====================")
	if id < 0 || id >= len(workers) || id >= RpcMaxWorker {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get worker id fail", Err: GetRetErr(ErrGetWorkerIdError)}
		ch <- res
		return ""
	}

	w := workers[id]
	GroupId := w.groupid
	fmt.Println("========Sign_ed============", "GroupId", GroupId)
	if GroupId == "" {
		res := RpcDcrmRes{Ret: "", Tip: "get group id fail", Err: fmt.Errorf("get group id fail.")}
		ch <- res
		return ""
	}

	ns, _ := GetGroup(GroupId)
	if ns != w.NodeCnt {
		logs.Debug("Sign_ed,get nodes info error.")
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:the group is not ready", Err: GetRetErr(ErrGroupNotReady)}
		ch <- res
		return ""
	}

	logs.Debug("===========Sign_ed============", "save len", len(save), "save", save)

	ids := GetIds(cointype, GroupId)
	idSign := ids[:w.ThresHold]

	m := strings.Split(save, common.Sep11)

	var sk [64]byte
	va := []byte(m[0])
	copy(sk[:], va[:64])
	//pk := ([]byte(m[1]))[:]
	var tsk [32]byte
	va = []byte(m[2])
	copy(tsk[:], va[:32])
	var pkfinal [32]byte
	va = []byte(m[3])
	copy(pkfinal[:], va[:32])

	//fixid := []string{"36550725515126069209815254769857063254012795400127087205878074620099758462980","86773132036836319561089192108022254523765345393585629030875522375234841566222","80065533669343563706948463591465947300529465448793304408098904839998265250318"}
	var uids = make(map[string][32]byte)
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		//num,_ := new(big.Int).SetString(fixid[k],10)
		var t [32]byte
		//copy(t[:], num.Bytes())
		copy(t[:], id.Bytes())
		if len(id.Bytes()) < 32 {
			l := len(id.Bytes())
			for j := l; j < 32; j++ {
				t[j] = byte(0x00)
			}
		}
		uids[en[0]] = t
	}

	// [Notes]
	// 1. calculate R
	var r [32]byte
	var RBytes [32]byte
	var rDigest [64]byte

	h := sha512.New()
	h.Write(sk[32:])
	h.Write([]byte(message))
	h.Sum(rDigest[:0])
	ed.ScReduce(&r, &rDigest)

	var R ed.ExtendedGroupElement
	ed.GeScalarMultBase(&R, &r)

	// 2. commit(R)
	R.ToBytes(&RBytes)
	CR, DR := ed.Commit(RBytes)

	// 3. zkSchnorr(rU1)
	zkR := ed.Prove(r)

	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "EDC21"
	s1 := string(CR[:])

	ss := enode + common.Sep + s0 + common.Sep + s1
	logs.Debug("================sign ed round one,send msg,code is EDC21==================")
	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr := GetChannelValue(ch_t, w.bedc21)
	if cherr != nil {
		logs.Debug("get w.bedc21 timeout.")
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ed c21 timeout.")}
		ch <- res
		return ""
	}

	if w.msg_edc21.Len() != w.NodeCnt {
		logs.Debug("get w.msg_edc21 fail.")
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get msg_edc21 fail", Err: fmt.Errorf("get all ed c21 fail.")}
		ch <- res
		return ""
	}
	var crs = make(map[string][32]byte)
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			crs[cur_enode] = CR
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edc21.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
				var t [32]byte
				va := []byte(m[2])
				copy(t[:], va[:32])
				crs[en[0]] = t
				break
			}
			iter = iter.Next()
		}
	}

	s0 = "EDZKR"
	s1 = string(zkR[:])
	ss = enode + common.Sep + s0 + common.Sep + s1
	logs.Debug("================sign ed round one,send msg,code is EDZKR==================")
	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr = GetChannelValue(ch_t, w.bedzkr)
	if cherr != nil {
		logs.Debug("get w.bedzkr timeout.")
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ed zkr timeout.")}
		ch <- res
		return ""
	}

	if w.msg_edzkr.Len() != w.NodeCnt {
		logs.Debug("get w.msg_edzkr fail.")
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get all msg_edzkr fail", Err: fmt.Errorf("get all ed zkr fail.")}
		ch <- res
		return ""
	}

	var zkrs = make(map[string][64]byte)
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			zkrs[cur_enode] = zkR
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edzkr.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
				var t [64]byte
				va := []byte(m[2])
				copy(t[:], va[:64])
				zkrs[en[0]] = t
				break
			}
			iter = iter.Next()
		}
	}

	s0 = "EDD21"
	s1 = string(DR[:])
	ss = enode + common.Sep + s0 + common.Sep + s1
	logs.Debug("================sign ed round one,send msg,code is EDD21==================")
	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr = GetChannelValue(ch_t, w.bedd21)
	if cherr != nil {
		logs.Debug("get w.bedd21 timeout.")
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ed d21 timeout.")}
		ch <- res
		return ""
	}

	if w.msg_edd21.Len() != w.NodeCnt {
		logs.Debug("get w.msg_edd21 fail.")
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get all msg_edd21 fail", Err: fmt.Errorf("get all ed d21 fail.")}
		ch <- res
		return ""
	}
	var drs = make(map[string][64]byte)
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			drs[cur_enode] = DR
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edd21.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
				var t [64]byte
				va := []byte(m[2])
				copy(t[:], va[:64])
				drs[en[0]] = t
				break
			}
			iter = iter.Next()
		}
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		CRFlag := ed.Verify(crs[en[0]], drs[en[0]])
		if !CRFlag {
			fmt.Println("Error: Commitment(R) Not Pass at User: %s", en[0])
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:commitment verification fail in ed sign", Err: fmt.Errorf("Commitment(R) Not Pass.")}
			ch <- res
			return ""
		}
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		var temR [32]byte
		t := drs[en[0]]
		copy(temR[:], t[32:])

		zkRFlag := ed.Verify_zk(zkrs[en[0]], temR)
		if !zkRFlag {
			fmt.Println("Error: ZeroKnowledge Proof (R) Not Pass at User: %s", en[0])
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:zeroknowledge verification fail in ed sign", Err: fmt.Errorf("ZeroKnowledge Proof (R) Not Pass.")}
			ch <- res
			return ""
		}
	}

	var FinalR, temR ed.ExtendedGroupElement
	var FinalRBytes [32]byte
	for index, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		var temRBytes [32]byte
		t := drs[en[0]]
		copy(temRBytes[:], t[32:])
		temR.FromBytes(&temRBytes)
		if index == 0 {
			FinalR = temR
		} else {
			ed.GeAdd(&FinalR, &FinalR, &temR)
		}
	}
	FinalR.ToBytes(&FinalRBytes)

	// 2.6 calculate k=H(FinalRBytes||pk||M)
	var k [32]byte
	var kDigest [64]byte

	h = sha512.New()
	h.Write(FinalRBytes[:])
	h.Write(pkfinal[:])
	h.Write(([]byte(message))[:])
	h.Sum(kDigest[:0])

	ed.ScReduce(&k, &kDigest)

	// 2.7 calculate lambda1
	var lambda [32]byte
	lambda[0] = 1
	order := ed.GetBytesOrder()

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}

		var time [32]byte
		t := uids[en[0]]
		tt := uids[cur_enode]
		ed.ScSub(&time, &t, &tt)
		time = ed.ScModInverse(time, order)
		ed.ScMul(&time, &time, &t)
		ed.ScMul(&lambda, &lambda, &time)
	}

	var s [32]byte
	ed.ScMul(&s, &lambda, &tsk)
	ed.ScMul(&s, &s, &k)
	ed.ScAdd(&s, &s, &r)

	// 2.9 calculate sBBytes
	var sBBytes [32]byte
	var sB ed.ExtendedGroupElement
	ed.GeScalarMultBase(&sB, &s)
	sB.ToBytes(&sBBytes)

	// 2.10 commit(sBBytes)
	CSB, DSB := ed.Commit(sBBytes)

	s0 = "EDC31"
	s1 = string(CSB[:])
	ss = enode + common.Sep + s0 + common.Sep + s1
	logs.Debug("================sign ed round one,send msg,code is EDC31==================")
	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr = GetChannelValue(ch_t, w.bedc31)
	if cherr != nil {
		logs.Debug("get w.bedc31 timeout.")
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ed c31 timeout.")}
		ch <- res
		return ""
	}

	if w.msg_edc31.Len() != w.NodeCnt {
		logs.Debug("get w.msg_edc31 fail.")
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get msg_edc31 fail", Err: fmt.Errorf("get all ed c31 fail.")}
		ch <- res
		return ""
	}
	var csbs = make(map[string][32]byte)
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			csbs[cur_enode] = CSB
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edc31.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
				var t [32]byte
				va := []byte(m[2])
				copy(t[:], va[:32])
				csbs[en[0]] = t
				break
			}
			iter = iter.Next()
		}
	}

	s0 = "EDD31"
	s1 = string(DSB[:])
	ss = enode + common.Sep + s0 + common.Sep + s1
	logs.Debug("================sign ed round one,send msg,code is EDD31==================")
	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr = GetChannelValue(ch_t, w.bedd31)
	if cherr != nil {
		logs.Debug("get w.bedd31 timeout.")
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ed d31 timeout.")}
		ch <- res
		return ""
	}

	if w.msg_edd31.Len() != w.NodeCnt {
		logs.Debug("get w.msg_edd31 fail.")
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get all msg_edd31 fail", Err: fmt.Errorf("get all ed d31 fail.")}
		ch <- res
		return ""
	}
	var dsbs = make(map[string][64]byte)
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			dsbs[cur_enode] = DSB
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edd31.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
				var t [64]byte
				va := []byte(m[2])
				copy(t[:], va[:64])
				dsbs[en[0]] = t
				break
			}
			iter = iter.Next()
		}
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		CSBFlag := ed.Verify(csbs[en[0]], dsbs[en[0]])
		if !CSBFlag {
			fmt.Println("Error: Commitment(SB) Not Pass at User: %s", en[0])
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:commitment(CSB) not pass", Err: fmt.Errorf("Commitment(SB) Not Pass.")}
			ch <- res
			return ""
		}
	}

	var sB2, temSB ed.ExtendedGroupElement
	for index, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		var temSBBytes [32]byte
		t := dsbs[en[0]]
		copy(temSBBytes[:], t[32:])
		temSB.FromBytes(&temSBBytes)

		if index == 0 {
			sB2 = temSB
		} else {
			ed.GeAdd(&sB2, &sB2, &temSB)
		}
	}

	var k2 [32]byte
	var kDigest2 [64]byte

	h = sha512.New()
	h.Write(FinalRBytes[:])
	h.Write(pkfinal[:])
	h.Write(([]byte(message))[:])
	h.Sum(kDigest2[:0])

	ed.ScReduce(&k2, &kDigest2)

	// 3.6 calculate sBCal
	var FinalR2, sBCal, FinalPkB ed.ExtendedGroupElement
	FinalR2.FromBytes(&FinalRBytes)
	FinalPkB.FromBytes(&pkfinal)
	ed.GeScalarMult(&sBCal, &k2, &FinalPkB)
	ed.GeAdd(&sBCal, &sBCal, &FinalR2)

	// 3.7 verify equation
	var sBBytes2, sBCalBytes [32]byte
	sB2.ToBytes(&sBBytes2)
	sBCal.ToBytes(&sBCalBytes)

	if !bytes.Equal(sBBytes2[:], sBCalBytes[:]) {
		fmt.Println("Error: Not Pass Verification (SB = SBCal) at User: %s", cur_enode)
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:not pass verification (CSB == SBCal)", Err: fmt.Errorf("Error: Not Pass Verification (SB = SBCal).")}
		ch <- res
		return ""
	}

	s0 = "EDS"
	s1 = string(s[:])
	ss = enode + common.Sep + s0 + common.Sep + s1
	logs.Debug("================sign ed round one,send msg,code is EDS==================")
	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr = GetChannelValue(ch_t, w.beds)
	if cherr != nil {
		logs.Debug("get w.beds timeout.")
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ed s timeout.")}
		ch <- res
		return ""
	}

	if w.msg_eds.Len() != w.NodeCnt {
		logs.Debug("get w.msg_eds fail.")
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get msg_eds fail", Err: fmt.Errorf("get all ed s fail.")}
		ch <- res
		return ""
	}
	var eds = make(map[string][32]byte)
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			eds[cur_enode] = s
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_eds.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
				var t [32]byte
				va := []byte(m[2])
				copy(t[:], va[:32])
				eds[en[0]] = t
				break
			}
			iter = iter.Next()
		}
	}

	var FinalS [32]byte
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		t := eds[en[0]]
		ed.ScAdd(&FinalS, &FinalS, &t)
	}

	inputVerify := InputVerify{FinalR: FinalRBytes, FinalS: FinalS, Message: []byte(message), FinalPk: pkfinal}

	var pass = EdVerify(inputVerify)
	fmt.Println("===========ed verify pass=%v===============", pass)

	//r
	rx := hex.EncodeToString(FinalRBytes[:])
	sx := hex.EncodeToString(FinalS[:])
	logs.Debug("========sign_ed========", "rx", rx, "sx", sx, "FinalRBytes", FinalRBytes, "FinalS", FinalS)

	//////test
	signature := new([64]byte)
	copy(signature[:], FinalRBytes[:])
	copy(signature[32:], FinalS[:])
	suss := ed25519.Verify(&pkfinal, []byte(message), signature)
	fmt.Println("===========ed verify pass again=%v===============", suss)
	//////

	res := RpcDcrmRes{Ret: rx + ":" + sx, Tip: "", Err: nil}
	ch <- res
	return ""
}

type InputVerify struct {
	FinalR  [32]byte
	FinalS  [32]byte
	Message []byte
	FinalPk [32]byte
}

func EdVerify(input InputVerify) bool {
	// 1. calculate k
	var k [32]byte
	var kDigest [64]byte

	h := sha512.New()
	h.Write(input.FinalR[:])
	h.Write(input.FinalPk[:])
	h.Write(input.Message[:])
	h.Sum(kDigest[:0])

	ed.ScReduce(&k, &kDigest)

	// 2. verify the equation
	var R, pkB, sB, sBCal ed.ExtendedGroupElement
	pkB.FromBytes(&(input.FinalPk))
	R.FromBytes(&(input.FinalR))

	ed.GeScalarMult(&sBCal, &k, &pkB)
	ed.GeAdd(&sBCal, &R, &sBCal)

	ed.GeScalarMultBase(&sB, &(input.FinalS))

	var sBBytes, sBCalBytes [32]byte
	sB.ToBytes(&sBBytes)
	sBCal.ToBytes(&sBCalBytes)

	pass := bytes.Equal(sBBytes[:], sBCalBytes[:])

	return pass
}

//////

func IsCurNode(enodes string, cur string) bool {
	if enodes == "" || cur == "" {
		return false
	}

	s := []rune(enodes)
	en := strings.Split(string(s[8:]), "@")
	if en[0] == cur {
		return true
	}

	return false
}

func DoubleHash(id string, cointype string) *big.Int {
	
    	if cointype == "ED25519" || cointype == "ECDSA" {
	    return DoubleHash2(id,cointype)
	}

    	// Generate the random num

	// First, hash with the keccak256
	keccak256 := sha3.NewKeccak256()
	//keccak256.Write(rnd.Bytes())

	keccak256.Write([]byte(id))

	digestKeccak256 := keccak256.Sum(nil)

	//second, hash with the SHA3-256
	sha3256 := sha3.New256()

	sha3256.Write(digestKeccak256)

	if types.IsDefaultED25519(cointype) {
		var digest [32]byte
		copy(digest[:], sha3256.Sum(nil))

		//////
		var zero [32]byte
		var one [32]byte
		one[0] = 1
		ed.ScMulAdd(&digest, &digest, &one, &zero)
		//////
		digestBigInt := new(big.Int).SetBytes(digest[:])
		return digestBigInt
	}

	digest := sha3256.Sum(nil)
	// convert the hash ([]byte) to big.Int
	digestBigInt := new(big.Int).SetBytes(digest)
	return digestBigInt
}

func GetEnodesByUid(uid *big.Int, cointype string, groupid string) string {
	_, nodes := GetGroup(groupid)
	others := strings.Split(nodes, common.Sep2)
	for _, v := range others {
		node2 := ParseNode(v) //bug??
		id := DoubleHash(node2, cointype)
		if id.Cmp(uid) == 0 {
			return v
		}
	}

	return ""
}

type sortableIDSSlice []*big.Int

func (s sortableIDSSlice) Len() int {
	return len(s)
}

func (s sortableIDSSlice) Less(i, j int) bool {
	return s[i].Cmp(s[j]) <= 0
}

func (s sortableIDSSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func GetIds(cointype string, groupid string) sortableIDSSlice {
	var ids sortableIDSSlice
	_, nodes := GetGroup(groupid)
	others := strings.Split(nodes, common.Sep2)
	for _, v := range others {
		node2 := ParseNode(v) //bug??
		uid := DoubleHash(node2, cointype)
		ids = append(ids, uid)
	}
	sort.Sort(ids)
	return ids
}

func GetIds2(keytype string, groupid string) sortableIDSSlice {
	var ids sortableIDSSlice
	_, nodes := GetGroup(groupid)
	others := strings.Split(nodes, common.Sep2)
	for _, v := range others {
		node2 := ParseNode(v) //bug??
		uid := DoubleHash2(node2, keytype)
		ids = append(ids, uid)
	}
	sort.Sort(ids)
	return ids
}

func DoubleHash2(id string, keytype string) *big.Int {
	// Generate the random num

	// First, hash with the keccak256
	keccak256 := sha3.NewKeccak256()
	//keccak256.Write(rnd.Bytes())

	keccak256.Write([]byte(id))

	digestKeccak256 := keccak256.Sum(nil)

	//second, hash with the SHA3-256
	sha3256 := sha3.New256()

	sha3256.Write(digestKeccak256)

	if keytype == "ED25519" {
	    var digest [32]byte
	    copy(digest[:], sha3256.Sum(nil))

	    //////
	    var zero [32]byte
	    var one [32]byte
	    one[0] = 1
	    ed.ScMulAdd(&digest, &digest, &one, &zero)
	    //////
	    digestBigInt := new(big.Int).SetBytes(digest[:])
	    return digestBigInt
	}

	digest := sha3256.Sum(nil)
	// convert the hash ([]byte) to big.Int
	digestBigInt := new(big.Int).SetBytes(digest)
	return digestBigInt
}

type ECDSASignature struct {
	r               *big.Int
	s               *big.Int
	recoveryParam   int32
	roudFiveAborted bool
}

func (this *ECDSASignature) New() {
}

func (this *ECDSASignature) New2(r *big.Int, s *big.Int) {
	this.r = r
	this.s = s
}

func (this *ECDSASignature) New3(r *big.Int, s *big.Int, recoveryParam int32) {
	this.r = r
	this.s = s
	this.recoveryParam = recoveryParam
}

func (this *ECDSASignature) GetRoudFiveAborted() bool {
	return this.roudFiveAborted
}

func (this *ECDSASignature) SetRoudFiveAborted(roudFiveAborted bool) {
	this.roudFiveAborted = roudFiveAborted
}

func (this *ECDSASignature) GetR() *big.Int {
	return this.r
}

func (this *ECDSASignature) SetR(r *big.Int) {
	this.r = r
}

func (this *ECDSASignature) GetS() *big.Int {
	return this.s
}

func (this *ECDSASignature) SetS(s *big.Int) {
	this.s = s
}

func (this *ECDSASignature) GetRecoveryParam() int32 {
	return this.recoveryParam
}

func (this *ECDSASignature) SetRecoveryParam(recoveryParam int32) {
	this.recoveryParam = recoveryParam
}

func Tool_DecimalByteSlice2HexString(DecimalSlice []byte) string {
	var sa = make([]string, 0)
	for _, v := range DecimalSlice {
		sa = append(sa, fmt.Sprintf("%02X", v))
	}
	ss := strings.Join(sa, "")
	return ss
}

func GetSignString(r *big.Int, s *big.Int, v int32, i int) string {
	rr := r.Bytes()
	sss := s.Bytes()

	//bug
	if len(rr) == 31 && len(sss) == 32 {
		sigs := make([]byte, 65)
		sigs[0] = byte(0)
		signing.ReadBits(r, sigs[1:32])
		signing.ReadBits(s, sigs[32:64])
		sigs[64] = byte(i)
		ret := Tool_DecimalByteSlice2HexString(sigs)
		return ret
	}
	if len(rr) == 31 && len(sss) == 31 {
		sigs := make([]byte, 65)
		sigs[0] = byte(0)
		sigs[32] = byte(0)
		signing.ReadBits(r, sigs[1:32])
		signing.ReadBits(s, sigs[33:64])
		sigs[64] = byte(i)
		ret := Tool_DecimalByteSlice2HexString(sigs)
		return ret
	}
	if len(rr) == 32 && len(sss) == 31 {
		sigs := make([]byte, 65)
		sigs[32] = byte(0)
		signing.ReadBits(r, sigs[0:32])
		signing.ReadBits(s, sigs[33:64])
		sigs[64] = byte(i)
		ret := Tool_DecimalByteSlice2HexString(sigs)
		return ret
	}
	//

	n := len(rr) + len(sss) + 1
	sigs := make([]byte, n)
	signing.ReadBits(r, sigs[0:len(rr)])
	signing.ReadBits(s, sigs[len(rr):len(rr)+len(sss)])

	sigs[len(rr)+len(sss)] = byte(i)
	ret := Tool_DecimalByteSlice2HexString(sigs)

	return ret
}

func DECDSA_Sign_Verify_RSV(r *big.Int, s *big.Int, v int32, message string, pkx *big.Int, pky *big.Int) bool {
	return signing.Verify2(r, s, v, message, pkx, pky)
}

