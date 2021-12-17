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
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
	"encoding/json"

	"github.com/fsn-dev/dcrm-walletService/mpcdsa/ecdsa/signing"
	"github.com/fsn-dev/dcrm-walletService/crypto/secp256k1"

	"sync"
	"github.com/astaxie/beego/logs"
	"github.com/fsn-dev/cryptoCoins/coins"
	"github.com/fsn-dev/cryptoCoins/coins/eos"
	"github.com/fsn-dev/cryptoCoins/coins/types"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	"github.com/fsn-dev/dcrm-walletService/log"
)

type LockOutReply struct {
	Enode string
	Reply string
}

type LockOutReplys struct {
	Replys []LockOutReply
}

type TxDataLockOut struct {
    TxType string
    DcrmAddr string
    DcrmTo string
    Value string
    Cointype string
    GroupId string
    ThresHold string
    Mode string
    TimeStamp string
    Memo string
}

func GetLockOutNonce(account string) (string, string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + "LOCKOUT"))).Hex()
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if !exsit {
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

func RpcAcceptLockOut(raw string) (string, string, error) {
    log.Debug("=====================RpcAcceptLockOut call CheckRaw ================","raw",raw)
    _,_,_,txdata,err := CheckRaw(raw)
    if err != nil {
	log.Debug("=====================RpcAcceptLockOut,CheckRaw ================","raw",raw,"err",err)
	return "Failure",err.Error(),err
    }

    acceptlo,ok := txdata.(*TxDataAcceptLockOut)
    if !ok {
	return "Failure","check raw fail,it is not *TxDataAcceptLockOut",fmt.Errorf("check raw fail,it is not *TxDataAcceptLockOut")
    }

    exsit,da := GetValueFromPubKeyData(acceptlo.Key)
    if exsit {
	ac,ok := da.(*AcceptLockOutData)
	if ok && ac != nil {
	    log.Debug("=====================RpcAcceptLockOut, SendMsgToDcrmGroup ================","raw",raw,"gid",ac.GroupId,"key",acceptlo.Key)
	    SendMsgToDcrmGroup(raw, ac.GroupId)
	    SetUpMsgList(raw,cur_enode)
	    return "Success", "", nil
	}
    }

    return "Failure","accept fail",fmt.Errorf("accept fail")
}

func LockOut(raw string) (string, string, error) {
    log.Debug("=====================LockOut call CheckRaw ================","raw",raw)
    key,_,_,txdata,err := CheckRaw(raw)
    if err != nil {
	log.Debug("=====================LockOut,CheckRaw ================","raw",raw,"err",err)
	return "",err.Error(),err
    }

    lo,ok := txdata.(*TxDataLockOut)
    if !ok {
	return "","check raw fail,it is not *TxDataLockOut",fmt.Errorf("check raw fail,it is not *TxDataLockOut")
    }

    log.Debug("=====================LockOut, SendMsgToDcrmGroup ================","raw",raw,"gid",lo.GroupId,"key",key)
    SendMsgToDcrmGroup(raw, lo.GroupId)
    SetUpMsgList(raw,cur_enode)
    return key, "", nil
}

type LockOutStatus struct {
	Status    string
	OutTxHash string
	Tip       string
	Error     string
	AllReply  []NodeReply 
	TimeStamp string
}

func GetLockOutStatus(key string) (string, string, error) {
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if !exsit || da == nil {
		return "", "dcrm back-end internal error:get lockout accept data fail from db when GetLockOutStatus", fmt.Errorf("dcrm back-end internal error:get lockout accept data fail from db when GetLockOutStatus")
	}

	ac,ok := da.(*AcceptLockOutData)
	if !ok {
		return "", "dcrm back-end internal error:get lockout accept data error from db when GetLockOutStatus", fmt.Errorf("dcrm back-end internal error:get lockout accept data error from db when GetLockOutStatus")
	}
	los := &LockOutStatus{Status: ac.Status, OutTxHash: ac.OutTxHash, Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
	ret,_ := json.Marshal(los)
	return string(ret), "",nil 
}

type LockOutCurNodeInfo struct {
	Key       string
	Account   string
	GroupId   string
	Nonce     string
	DcrmFrom  string
	DcrmTo    string
	Value     string
	Cointype  string
	ThresHold  string
	Mode      string
	TimeStamp string
}

func GetCurNodeLockOutInfo(geter_acc string) ([]*LockOutCurNodeInfo, string, error) {

	var ret []*LockOutCurNodeInfo
	var wg sync.WaitGroup
	LdbPubKeyData.RLock()
	for k, v := range LdbPubKeyData.Map {
	    wg.Add(1)
	    go func(key string,value interface{}) {
		defer wg.Done()

		vv,ok := value.(*AcceptLockOutData)
		if vv == nil || !ok {
		    return
		}

		log.Debug("================GetCurNodeLockOutInfo, it is *AcceptLockOutData===================","vv",vv,"vv.Deal",vv.Deal,"vv.Status",vv.Status,"key",key)
		if vv.Deal == "true" || vv.Status == "Success" {
		    return
		}

		if vv.Status != "Pending" {
		    return
		}

		dcrmaddr,_,err := GetAddr(vv.PubKey,vv.Cointype)
		if err != nil {
		    return
		}

		if !CheckAccept(vv.PubKey,vv.Mode,geter_acc) {
			return
		}
		
		los := &LockOutCurNodeInfo{Key: key, Account: vv.Account, GroupId: vv.GroupId, Nonce: vv.Nonce, DcrmFrom: dcrmaddr, DcrmTo: vv.DcrmTo, Value: vv.Value, Cointype: vv.Cointype, ThresHold: vv.LimitNum, Mode: vv.Mode, TimeStamp: vv.TimeStamp}
		ret = append(ret, los)
		log.Debug("================GetCurNodeLockOutInfo success return===================","key",key)
	    }(k,v)
	}
	LdbPubKeyData.RUnlock()
	wg.Wait()
	return ret, "", nil
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
	//exsit,da := GetValueFromPubKeyData(key2)
	exsit,da := GetPubKeyDataFromLocalDb(key2)
	if !exsit {
	    time.Sleep(time.Duration(5000000000))
	    exsit,da = GetPubKeyDataFromLocalDb(key2)
	}
	///////
	if !exsit {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get lockout data from db fail", Err: fmt.Errorf("get lockout data from db fail")}
		ch <- res
		return
	}

	_,ok := da.(*PubKeyData)
	if !ok {
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

	///sku1
	da2 := GetSkU1FromLocalDb(key2)
	if da2 == nil {
		res := RpcDcrmRes{Ret: "", Tip: "lockout get sku1 fail", Err: fmt.Errorf("lockout get sku1 fail")}
		ch <- res
		return
	}
	sku1 := new(big.Int).SetBytes(da2)
	if sku1 == nil {
		res := RpcDcrmRes{Ret: "", Tip: "lockout get sku1 fail", Err: fmt.Errorf("lockout get sku1 fail")}
		ch <- res
		return
	}
	//

	amount, ok := new(big.Int).SetString(value, 10)
	if !ok {
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
			bak_sig := dcrm_sign_ed(wsid, digest, save, sku1,dcrmpub, cointype, rch)
			ret, tip, cherr := GetChannelValue(waitall, rch)
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

		bak_sig := dcrm_sign(wsid, digest, save, sku1,dcrmpkx, dcrmpky, cointype, rch)
		ret, tip, cherr := GetChannelValue(waitall, rch)
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
	/////////add for bak sig
	if err != nil && len(bak_sigs) != 0 {
		signedTx, err = chandler.MakeSignedTransaction(bak_sigs, lockouttx)
		if err != nil {
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:new sign transaction fail", Err: err}
			ch <- res
			return
		}

		lockout_tx_hash, err = chandler.SubmitTransaction(signedTx)
	}
	/////////

	if lockout_tx_hash != "" {
		w, err := FindWorker(wsid)
		if w == nil || err != nil {
			log.Debug("==========validate_lockout,no find worker================","nonce",nonce,"err",err,"key",w.sid)
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

		log.Debug("================validate_lockout,the terminal lockout res is success===============","nonce",nonce,"key",w.sid)
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
}

//ec2
//msgprex = hash
//return value is the backup for dcrm sig.
func dcrm_sign(msgprex string, txhash string, save string, sku1 *big.Int, dcrmpkx *big.Int, dcrmpky *big.Int, cointype string, ch chan interface{}) string {

	if strings.EqualFold(cointype, "EOS") {

		var eosstr string
		key := string([]byte("eossettings"))
		exsit,da := GetValueFromPubKeyData(key)
		if exsit {
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
		log.Debug("======== get eos settings========","eosstr",eosstr,"key",msgprex)
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
		log.Debug("======== dcrm_sign eos========","pkx",dcrmpkx2,"pky",dcrmpky2,"key",msgprex)
		txhashs := []rune(txhash)
		if string(txhashs[0:2]) == "0x" {
			txhash = string(txhashs[2:])
		}

		w, err := FindWorker(msgprex)
		if w == nil || err != nil {
			log.Debug("==========dcrm_sign,no find worker==============","key",msgprex,"err",err)
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
			if len(ch1) != 0 {
			    <-ch1
			}

			w := workers[id]
			w.Clear2()
			bak_sig = Sign_ec2(msgprex, save, sku1, txhash, cointype, dcrmpkx2, dcrmpky2, ch1, id)
			ret, tip, _ = GetChannelValue(ch_t, ch1)
			//if ret != "" && eos.IsCanonical([]byte(ret)) == true
			if ret == "" {
				time.Sleep(time.Duration(1) * time.Second) //1000 == 1s
				continue
			}
			b, _ := hex.DecodeString(ret)
			if eos.IsCanonical(b) {
				flag = true
				break
			}
			time.Sleep(time.Duration(3) * time.Second) //1000 == 1s
		}
		if !flag {
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
		log.Debug("==========dcrm_sign,no find worker============","key",msgprex,"err",err)
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker", Err: fmt.Errorf("no find worker.")}
		ch <- res
		return ""
	}
	id := w.id

	cur_enode = GetSelfEnode()

	///////
	if strings.EqualFold(cointype, "EVT1") {
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
			if len(ch1) != 0 {
			    <-ch1
			}

			w := workers[id]
			w.Clear2()
			bak_sig = Sign_ec2(msgprex, save, sku1,txhash, cointype, dcrmpkx, dcrmpky, ch1, id)
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
			if eos.IsCanonical(b) {
				log.Debug("ret is a canonical signature","key",msgprex)
				flag = true
				break
			}
			time.Sleep(time.Duration(3) * time.Second) //1000 == 1s
		}
		if !flag {
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:dcrm sign fail", Err: GetRetErr(ErrDcrmSigFail)}
			ch <- res
			return ""
		}
		//ch <- ret
		res := RpcDcrmRes{Ret: ret, Tip: tip, Err: cherr}
		ch <- res
		return bak_sig
	} 
	
	var ch1 = make(chan interface{}, 1)
	var bak_sig string
	for i:=0;i < recalc_times;i++ {
	    if len(ch1) != 0 {
		<-ch1
	    }

	    w := workers[id]
	    w.Clear2()
	    bak_sig = Sign_ec2(msgprex, save, sku1,txhash, cointype, dcrmpkx, dcrmpky, ch1, id)
	    ret, _, cherr := GetChannelValue(ch_t, ch1)
	    if ret != "" && cherr == nil {
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
func Sign_ec2(msgprex string, save string, sku1 *big.Int, message string, cointype string, pkx *big.Int, pky *big.Int, ch chan interface{}, id int) string {
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
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get save data fail")}
		ch <- res
		return ""
	}

	// [Notes]
	// 1. assume the nodes who take part in the signature generation as follows
	ids := GetIds(cointype, w.groupid)
	idSign := ids[:w.ThresHold]
	mMtA, _ := new(big.Int).SetString(message, 16)
	log.Debug("=============Sign_ec2=============","w.ThresHold",w.ThresHold,"key",msgprex)

	//*******************!!!Distributed ECDSA Sign Start!!!**********************************

	skU1, w1 := MapPrivKeyShare(cointype, w, idSign, string(sku1.Bytes()))
	if skU1 == nil || w1 == nil {
	    return ""
	}

	log.Debug("=============Sign_ec2, map privkey finish =============","key",msgprex)

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
	log.Debug("===================Sign_ec2,round one finish=================","key",msgprex)

	ukc, ukc2, ukc3 := DECDSASignPaillierEncrypt(cointype, save, w, idSign, u1K, ch)
	if ukc == nil || ukc2 == nil || ukc3 == nil {
		return ""
	}
	log.Debug("===================Sign_ec2,paillier encrypt finish=================","key",msgprex)

	zk1proof, zkfactproof := DECDSASignRoundTwo(msgprex, cointype, save, w, idSign, ch, u1K, ukc2, ukc3)
	if zk1proof == nil || zkfactproof == nil {
		return ""
	}
	log.Debug("===================Sign_ec2,round two finish================","key",msgprex)

	if !DECDSASignRoundThree(msgprex, cointype, save, w, idSign, ch, ukc) {
		return ""
	}
	log.Debug("===================Sign_ec2,round three finish================","key",msgprex)

	if !DECDSASignVerifyZKNtilde(msgprex, cointype, save, w, idSign, ch, ukc, ukc3, zk1proof, zkfactproof) {
		return ""
	}
	log.Debug("===================Sign_ec2,verify zk ntilde finish==================","key",msgprex)

	betaU1Star, betaU1, vU1Star, vU1 := signing.GetRandomBetaV(PaillierKeyLength, w.ThresHold)
	log.Debug("===================Sign_ec2,get random betaU1Star/vU1Star finish================","key",msgprex)

	mkg, mkg_mtazk2, mkw, mkw_mtazk2, status := DECDSASignRoundFour(msgprex, cointype, save, w, idSign, ukc, ukc3, zkfactproof, u1Gamma, w1, betaU1Star, vU1Star,ch)
	if !status {
		return ""
	}
	log.Debug("===================Sign_ec2,round four finish================","key",msgprex)

	if !DECDSASignVerifyZKGammaW(msgprex,cointype, save, w, idSign, ukc, ukc3, zkfactproof, mkg, mkg_mtazk2, mkw, mkw_mtazk2, ch) {
		return ""
	}
	log.Debug("===================Sign_ec2,verify zk gamma/w finish===================","key",msgprex)

	u1PaillierSk := GetSelfPrivKey(cointype, idSign, w, save, ch)
	if u1PaillierSk == nil {
		return ""
	}
	log.Debug("===================Sign_ec2,get self privkey finish====================","key",msgprex)

	alpha1 := DecryptCkGamma(cointype, idSign, w, u1PaillierSk, mkg, ch)
	if alpha1 == nil {
		return ""
	}
	log.Debug("=====================Sign_ec2,decrypt paillier(k)XGamma finish=================","key",msgprex)

	uu1 := DecryptCkW(cointype, idSign, w, u1PaillierSk, mkw, ch)
	if uu1 == nil {
		return ""
	}
	log.Debug("=====================Sign_ec2, decrypt paillier(k)Xw1 finish=================","key",msgprex)

	delta1 := CalcDelta(alpha1, betaU1, ch, w.ThresHold)
	if delta1 == nil {
		return ""
	}
	log.Debug("=====================Sign_ec2, calc delta finish=================","key",msgprex)

	sigma1 := CalcSigma(uu1, vU1, ch, w.ThresHold)
	if sigma1 == nil {
		return ""
	}
	log.Debug("=====================Sign_ec2, calc sigma finish=================","key",msgprex)

	deltaSum := DECDSASignRoundFive(msgprex, cointype, delta1, idSign, w, ch)
	if deltaSum == nil {
		return ""
	}
	log.Debug("=====================Sign_ec2, round five finish=================","key",msgprex)

	u1GammaZKProof := DECDSASignRoundSix(msgprex, u1Gamma, commitU1GammaG, w, ch)
	if u1GammaZKProof == nil {
		return ""
	}
	log.Debug("=====================Sign_ec2, round six finish=================","key",msgprex)

	ug := DECDSASignVerifyCommitment(cointype, w, idSign, commitU1GammaG, u1GammaZKProof, ch)
	if ug == nil {
		return ""
	}
	log.Debug("=====================Sign_ec2, verify commitment finish=================","key",msgprex)

	r, deltaGammaGy := Calc_r(cointype, w, idSign, ug, deltaSum, ch)
	if r == nil || deltaGammaGy == nil {
		return ""
	}
	log.Debug("=====================Sign_ec2, calc r finish=================","key",msgprex)

	// 5. calculate s
	us1 := signing.CalcUs(mMtA, u1K, r, sigma1)
	log.Debug("=====================Sign_ec2, calc self s finish=================","key",msgprex)

	commitBigVAB1, commitbigvabs, rho1, l1 := DECDSASignRoundSeven(msgprex, r, deltaGammaGy, us1, w, ch)
	if commitBigVAB1 == nil || commitbigvabs == nil || rho1 == nil || l1 == nil {
		return ""
	}
	log.Debug("=====================Sign_ec2, round seven finish=================","key",msgprex)

	u1zkABProof, zkabproofs := DECDSASignRoundEight(msgprex, r, deltaGammaGy, us1, l1, rho1, w, ch, commitBigVAB1)
	if u1zkABProof == nil || zkabproofs == nil {
		return ""
	}
	log.Debug("=====================Sign_ec2, round eight finish=================","key",msgprex)

	commitbigcom, BigVx, BigVy := DECDSASignVerifyBigVAB(cointype, w, commitbigvabs, zkabproofs, commitBigVAB1, u1zkABProof, idSign, r, deltaGammaGy, ch)
	if commitbigcom == nil || BigVx == nil || BigVy == nil {
		return ""
	}
	log.Debug("=====================Sign_ec2, verify BigVAB finish=================","key",msgprex)

	commitbiguts, commitBigUT1 := DECDSASignRoundNine(msgprex, cointype, w, idSign, mMtA, r, pkx, pky, BigVx, BigVy, rho1, commitbigcom, l1, ch)
	if commitbiguts == nil || commitBigUT1 == nil {
		return ""
	}
	log.Debug("=====================Sign_ec2, round nine finish=================","key",msgprex)

	commitbigutd11s := DECDSASignRoundTen(msgprex, commitBigUT1, w, ch)
	if commitbigutd11s == nil {
		return ""
	}
	log.Debug("=====================Sign_ec2, round ten finish=================","key",msgprex)

	if !DECDSASignVerifyBigUTCommitment(msgprex,cointype, commitbiguts, commitbigutd11s, commitBigUT1, w, idSign, ch, commitbigcom) {
		return ""
	}
	log.Debug("=====================Sign_ec2, verify BigUT commitment finish=================","key",msgprex)

	ss1s := DECDSASignRoundEleven(msgprex, cointype, w, idSign, ch, us1)
	if ss1s == nil {
		return ""
	}
	log.Debug("=====================Sign_ec2,round eleven finish=================","key",msgprex)

	s := Calc_s(msgprex,cointype, w, idSign, ss1s, ch)
	if s == nil {
		return ""
	}
	log.Debug("=====================Sign_ec2,calc s finish=================","key",msgprex)

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
	log.Debug("=====================Sign_ec2,justify s finish=================","key",msgprex)

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

	if !DECDSA_Sign_Verify_RSV(signature.GetR(), signature.GetS(), signature.GetRecoveryParam(), message, pkx, pky) {
		log.Debug("=================Sign_ec2,verify is false==============","key",msgprex)
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("sign verify fail.")}
		ch <- res
		return ""
	}
	log.Debug("=================Sign_ec2,verify (r,s) pass==============","key",msgprex)

	signature2 := GetSignString(signature.GetR(), signature.GetS(), signature.GetRecoveryParam(), int(signature.GetRecoveryParam()))
	rstring := "========================== r = " + fmt.Sprintf("%v", signature.GetR()) + " ========================="
	sstring := "========================== s = " + fmt.Sprintf("%v", signature.GetS()) + " =========================="
	fmt.Println(rstring)
	fmt.Println(sstring)
	log.Debug("=================Sign_ec2==============","rsv str",signature2,"key",msgprex)
	res := RpcDcrmRes{Ret: signature2, Err: nil}
	ch <- res

	log.Debug("=================Sign_ec2, rsv pass==============","key",msgprex)
	//*******************!!!Distributed ECDSA Sign End!!!**********************************

	return ""
}

////ed
//msgprex = hash
//return value is the backup for dcrm sig.
func dcrm_sign_ed(msgprex string, txhash string, save string, sku1 *big.Int,pk string, cointype string, ch chan interface{}) string {

	txhashs := []rune(txhash)
	if string(txhashs[0:2]) == "0x" {
		txhash = string(txhashs[2:])
	}

	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker", Err: GetRetErr(ErrNoFindWorker)}
		ch <- res
		return ""
	}
	id := w.id

	cur_enode = GetSelfEnode()

	var ch1 = make(chan interface{}, 1)
	var bak_sig string
	for i:=0;i < recalc_times;i++ {
	    //fmt.Printf("%v===============dcrm_sign_ed, recalc i = %v, key = %v ================\n",common.CurrentTime(),i,msgprex)
	    if len(ch1) != 0 {
		<-ch1
	    }

	    w := workers[id]
	    w.Clear2()
	    //fmt.Printf("%v=====================dcrm_sign_ed, i = %v, key = %v ====================\n",common.CurrentTime(),i,msgprex)
	    bak_sig = Sign_ed(msgprex, save, sku1,txhash, cointype, pk, ch1, id)
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

