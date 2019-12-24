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

package dev

import (
    "github.com/fsn-dev/dcrm-walletService/crypto/dcrm/dev/lib/ec2"
    "github.com/fsn-dev/dcrm-walletService/crypto/dcrm/dev/lib/ed"
    "math/big"
    "github.com/fsn-dev/dcrm-walletService/crypto/secp256k1"
    "github.com/fsn-dev/dcrm-walletService/crypto/sha3"
    "time"
    "sort"
    "bytes"
    "crypto/rand"
    "strconv"
    "strings"
    "crypto/sha512"
    "fmt"
    "encoding/hex"
    //"github.com/syndtr/goleveldb/leveldb"
    "github.com/fsn-dev/dcrm-walletService/ethdb"
    "github.com/fsn-dev/dcrm-walletService/crypto/dcrm/cryptocoins"
    "github.com/fsn-dev/dcrm-walletService/internal/common"
    "github.com/fsn-dev/dcrm-walletService/crypto/dcrm/cryptocoins/types"
    "github.com/fsn-dev/dcrm-walletService/crypto/dcrm/cryptocoins/eos"
    "github.com/astaxie/beego/logs"
    "github.com/agl/ed25519"
    "runtime/debug"
    "github.com/fsn-dev/dcrm-walletService/crypto/ecies"
    "github.com/fsn-dev/dcrm-walletService/crypto"
    crand "crypto/rand"
    "crypto/ecdsa"
)

func GetReqAddrNonce(account string) (string,string,error) {

     //db
    lock.Lock()
    dir := GetDbDir()
    fmt.Println("=========GetReqAddrNonce,dir = %v ============",dir)
    ////////
    db,err := ethdb.NewLDBDatabase(dir, 0, 0)
    //bug
    if err != nil {
	for i:=0;i<1000;i++ {
	    db,err = ethdb.NewLDBDatabase(dir, 0, 0)
	    if err == nil {
		break
	    }
	    
	    time.Sleep(time.Duration(1000000))
	}
    }
    //
    if db == nil {
        lock.Unlock()
	fmt.Println("=========GetReqAddrNonce,err = %v ============",err)
	return "","dcrm back-end internal error:open level db fail in func GetReqAddrNonce",err
    }
    
    key2 := Keccak256Hash([]byte(strings.ToLower(account))).Hex()
    da,err := db.Get([]byte(key2))
    ///////
    if err != nil {
	db.Close()
	lock.Unlock()
	return "","dcrm back-end internal error:get req addr nonce from db fail",fmt.Errorf("leveldb not found, account = %s",account)
    }

    nonce,_ := new(big.Int).SetString(string(da),10)
    one,_ := new(big.Int).SetString("1",10)
    nonce = new(big.Int).Add(nonce,one)

    fmt.Println("=========GetReqAddrNonce,nonce = %v ============",nonce)
    db.Close()
    lock.Unlock()
    return fmt.Sprintf("%v",nonce),"",nil
}

func GetNonce(account string,cointype string,dcrmaddr string) (string,string,error) {

     //db
    lock5.Lock()
    dir := GetDbDir()
    ////////
    db,err := ethdb.NewLDBDatabase(dir, 0, 0)
    //bug
    if err != nil {
	for i:=0;i<1000;i++ {
	    db,err = ethdb.NewLDBDatabase(dir, 0, 0)
	    if err == nil {
		break
	    }
	    
	    time.Sleep(time.Duration(1000000))
	}
    }
    //
    if db == nil {
        lock5.Unlock()
	fmt.Println("=========GetNonce,err = %v ============",err)
	return "","dcrm back-end internal error:open level db fail in func GetNonce",err
    }
    
    key2 := Keccak256Hash([]byte(strings.ToLower(dcrmaddr))).Hex()
    da,err := db.Get([]byte(key2))
    ///////
    if err != nil {
	db.Close()
	lock5.Unlock()
	return "","dcrm back-end internal error:get nonce from db fail",fmt.Errorf("leveldb not found account = %s,cointype = %s",account,cointype)
    }

    ss,err := UnCompress(string(da))
    if err != nil {
	db.Close()
	lock5.Unlock()
	return "","dcrm back-end internal error:uncompress nonce data from db fail",err
    }
    
    pubs,err := Decode2(ss,"PubKeyData")
    if err != nil {
	db.Close()
	lock5.Unlock()
	return "","dcrm back-end internal error:decode nonce data from db fail",err
    }
   
    ////check account?? //TODO
    ////

    nonce2 := (pubs.(*PubKeyData)).Nonce
    nonce,_ := new(big.Int).SetString(string(nonce2),10)
    one,_ := new(big.Int).SetString("1",10)
    nonce = new(big.Int).Add(nonce,one)
    fmt.Println("=========GetNonce,nonce = %v ============",nonce)
    db.Close()
    lock5.Unlock()
    return fmt.Sprintf("%v",nonce),"",nil
}

func SetReqAddrNonce(account string,nonce string) (string,error) {
    key := Keccak256Hash([]byte(strings.ToLower(account))).Hex()
    kd := KeyData{Key:[]byte(key),Data:nonce}
    PubKeyDataChan <-kd
    return "",nil
}

func SetNonce(account string,cointype string,dcrmaddr string,nonce string) (string,error) {
     //db
    lock5.Lock()
    dir := GetDbDir()
    ////////
    db,err := ethdb.NewLDBDatabase(dir, 0, 0)
    //bug
    if err != nil {
	for i:=0;i<1000;i++ {
	    db,err = ethdb.NewLDBDatabase(dir, 0, 0)
	    if err == nil {
		break
	    }
	    
	    time.Sleep(time.Duration(1000000))
	}
    }
    //
    if db == nil {
        lock5.Unlock()
	fmt.Println("=========SetNonce,err = %v ============",err)
	return "dcrm back-end internal error:open level db fail",err
    }
    
    key2 := Keccak256Hash([]byte(strings.ToLower(dcrmaddr))).Hex()
    da,err := db.Get([]byte(key2))
    ///////
    if err != nil {
	db.Close()
	lock5.Unlock()
	return "dcrm back-end internal error:get nonce data from db fail",fmt.Errorf("leveldb not found account = %s,cointype = %s",account,cointype)
    }

    ss,err := UnCompress(string(da))
    if err != nil {
	db.Close()
	lock5.Unlock()
	return "dcrm back-end internal error:uncompress nonce data from db fail",err
    }
    
    pubs,err := Decode2(ss,"PubKeyData")
    if err != nil {
	db.Close()
	lock5.Unlock()
	return "dcrm back-end internal error:decode nonce data from db fail",err
    }
   
    ////check account?? //TODO
    ////
    (pubs.(*PubKeyData)).Nonce = nonce

    epubs,err := Encode2(pubs.(*PubKeyData))
    if err != nil {
	db.Close()
	lock5.Unlock()
	return "dcrm back-end internal error:encode nonce data fail",err
    }
    
    ss,err = Compress([]byte(epubs))
    if err != nil {
	db.Close()
	lock5.Unlock()
	return "dcrm back-end internal error:compress nonce data fail",err
    }

    ///update db
    pubkeyhex := hex.EncodeToString([]byte((pubs.(*PubKeyData)).Pub))

    if !strings.EqualFold(cointype, "ALL") {

	h := cryptocoins.NewCryptocoinHandler(cointype)
	if h == nil {
	    db.Close()
	    lock5.Unlock()
	    return "cointype is not supported in lockout",fmt.Errorf("set nonce fail.cointype is not supported.")
	}

	ctaddr, err := h.PublicKeyToAddress(pubkeyhex)
	if err != nil {
	    db.Close()
	    lock5.Unlock()
	    return "dcrm back-end internal error:get dcrm addr fail from pubkey:"+pubkeyhex,err
	}

	db.Put([]byte((pubs.(*PubKeyData)).Pub),[]byte(ss))
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype))).Hex()
	db.Put([]byte(key),[]byte(ss))
	db.Put([]byte(ctaddr),[]byte(ss))
    } else {
	db.Put([]byte((pubs.(*PubKeyData)).Pub),[]byte(ss))
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype))).Hex()
	db.Put([]byte(key),[]byte(ss))
	for _, ct := range cryptocoins.Cointypes {
	    if strings.EqualFold(ct, "ALL") {
		continue
	    }

	    h := cryptocoins.NewCryptocoinHandler(ct)
	    if h == nil {
		continue
	    }
	    ctaddr, err := h.PublicKeyToAddress(pubkeyhex)
	    if err != nil {
		continue
	    }
	    
	    db.Put([]byte(ctaddr),[]byte(ss))
	}
    }
    //
    db.Close()
    lock5.Unlock()
    return "",nil
}

func validate_lockout(wsid string,account string,dcrmaddr string,cointype string,value string,to string,nonce string,ch chan interface{}) {
    fmt.Println("========validate_lockout============")
    var ret2 Err
    chandler := cryptocoins.NewCryptocoinHandler(cointype)
    if chandler == nil {
	    res := RpcDcrmRes{Ret:"",Tip:"cointype is not supported",Err:GetRetErr(ErrCoinTypeNotSupported)}
	    ch <- res
	    return
    }

    Nonce,_ := new(big.Int).SetString(nonce,10)

    //nonce check
    cur_nonce_str,tip,err := GetNonce(account,cointype,dcrmaddr)
    if err != nil {
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:err}
	ch <- res
	return
    }

    cur_nonce,_ := new(big.Int).SetString(cur_nonce_str,10)
    if Nonce.Cmp(cur_nonce) != 0 {
	res := RpcDcrmRes{Ret:"",Tip:"lockout tx nonce error",Err:fmt.Errorf("nonce error.")}
	ch <- res
	return
    }
    //
    
    lock5.Lock()

    //db
    dir := GetDbDir()
    ////////
    db,_ := ethdb.NewLDBDatabase(dir, 0, 0)
    //bug
    if err != nil {
	for i:=0;i<1000;i++ {
	    db,err = ethdb.NewLDBDatabase(dir, 0, 0)
	    if err == nil {
		break
	    }
	    
	    time.Sleep(time.Duration(1000000))
	}
    }
    //
    if db == nil {
        fmt.Println("===========validate_lockout,open db fail.=============")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:open level db fail",Err:fmt.Errorf("open db fail.")}
        ch <- res
        lock5.Unlock()
        return
    } 
    
    key2 := Keccak256Hash([]byte(strings.ToLower(dcrmaddr))).Hex()
    da,err := db.Get([]byte(key2))
    ///////
    if err != nil {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get lockout data from db fail",Err:err}
        ch <- res
	db.Close()
	lock5.Unlock()
	return 
    }

    ss,err := UnCompress(string(da))
    if err != nil {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:uncompress lockout data from db fail",Err:err}
        ch <- res
	db.Close()
	lock5.Unlock()
	return
    }
    
    pubs,err := Decode2(ss,"PubKeyData")
    if err != nil {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:decode lockout data from db fail",Err:err}
        ch <- res
	db.Close()
	lock5.Unlock()
	return
    }
   
    save := (pubs.(*PubKeyData)).Save
    dcrmpub := (pubs.(*PubKeyData)).Pub

    var dcrmpkx *big.Int
    var dcrmpky *big.Int
    if !types.IsDefaultED25519(cointype) {
	dcrmpks := []byte(dcrmpub)
	dcrmpkx,dcrmpky = secp256k1.S256().Unmarshal(dcrmpks[:])
    }

    db.Close()
    lock5.Unlock()

    pubkey := hex.EncodeToString([]byte(dcrmpub))
    realdcrmfrom, err := chandler.PublicKeyToAddress(pubkey)
    if err != nil {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get dcrm addr error from pubkey:"+pubkey,Err:fmt.Errorf("get dcrm addr fail")}
        ch <- res
        return
    }
    
    if !strings.EqualFold(dcrmaddr,realdcrmfrom) {
	res := RpcDcrmRes{Ret:"",Tip:"verify lockout dcrm addr fail,maybe input parameter error",Err:fmt.Errorf("check dcrm addr fail.")}
        ch <- res
        return
    }
    
    amount, _ := new(big.Int).SetString(value,10)
    jsonstring := "" // TODO erc20
    // For EOS, realdcrmpubkey is needed to calculate userkey,
    // but is not used as real transaction maker.
    // The real transaction maker is eospubkey.
    var eosaccount string
    if strings.EqualFold(cointype,"EOS") {
	eosaccount, _, _ = GetEosAccount()
	if eosaccount == "" {
	    res := RpcDcrmRes{Ret:"",Tip:"get real eos user fail",Err:GetRetErr(ErrGetRealEosUserFail)}
	    ch <- res
	    return
	}
    }
    
    var lockouttx interface{}
    var digests []string
    var buildTxErr error
    if strings.EqualFold(cointype,"EOS") {
    	lockouttx, digests, buildTxErr = chandler.BuildUnsignedTransaction(eosaccount,pubkey,to,amount,jsonstring)
    } else {
	lockouttx, digests, buildTxErr = chandler.BuildUnsignedTransaction(realdcrmfrom,pubkey,to,amount,jsonstring)
    }
    
    if buildTxErr != nil {
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:build unsign transaction fail",Err:buildTxErr}
	    ch <- res
	    return
    }
    
    rch := make(chan interface{}, 1)
    var sigs []string
    var bak_sigs []string
    for k, digest := range digests {
	    fmt.Printf("============validate_lockout,call dcrm_sign times = %+v,cointype = %+v ==============\n",k,cointype)

	    if types.IsDefaultED25519(cointype) {
		bak_sig := dcrm_sign_ed(wsid,digest,save,dcrmpub,cointype,rch)
		ret,tip,cherr := GetChannelValue(ch_t,rch)
		if cherr != nil {
		    res := RpcDcrmRes{Ret:"",Tip:tip,Err:cherr}
			ch <- res
			return
		}
		
		sigs = append(sigs, ret)
		if bak_sig != "" {
		    bak_sigs = append(bak_sigs, bak_sig)
		}

		continue
	    }

	    bak_sig := dcrm_sign(wsid,digest,save,dcrmpkx,dcrmpky,cointype,rch)
	    ret,tip,cherr := GetChannelValue(ch_t,rch)
	    if cherr != nil {
		    res := RpcDcrmRes{Ret:"",Tip:tip,Err:cherr}
		    ch <- res
		    return
	    }
	    
	    //bug
	    rets := []rune(ret)
	    if len(rets) != 130 {
		res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:wrong rsv size",Err:GetRetErr(ErrDcrmSigWrongSize)}
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
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:new sign transaction fail",Err:ret2}
	    ch <- res
	    return
    }

    lockout_tx_hash, err := chandler.SubmitTransaction(signedTx)
    fmt.Println("==========validate_lockout,send to outside net,err = %+v================",err)
    /////////add for bak sig
    if err != nil && len(bak_sigs) != 0 {

	signedTx, err = chandler.MakeSignedTransaction(bak_sigs, lockouttx)
	if err != nil {
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:new sign transaction fail",Err:err}
		ch <- res
		return
	}
	
	lockout_tx_hash, err = chandler.SubmitTransaction(signedTx)
	fmt.Println("==========validate_lockout,send to outside net,err = %+v================",err)
    }
    /////////
    
    if lockout_tx_hash != "" {
	w,err := FindWorker(wsid)
	if w == nil || err != nil {
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:no find worker",Err:fmt.Errorf("get worker error.")}
	    ch <- res
	    return
	}

	tip,err = SetNonce(account,cointype,dcrmaddr,nonce)
	if err != nil {
	    res := RpcDcrmRes{Ret:"",Tip:tip,Err:fmt.Errorf("update nonce error.")}
	    ch <- res
	    return
	}
	
	tip,reply := AcceptLockOut(account,w.groupid,nonce,dcrmaddr,w.limitnum,true,"true","Success",lockout_tx_hash,"","","") 
	if reply != nil {
	    res := RpcDcrmRes{Ret:"",Tip:tip,Err:fmt.Errorf("update lockout status error.")}
	    ch <- res
	    return
	}

	res := RpcDcrmRes{Ret:lockout_tx_hash,Tip:tip,Err:err}
	ch <- res
	return
    }

    if err != nil {
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:send lockout tx to network fail",Err:err}
	    ch <- res
	    return
    }
    
    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:lockout fail",Err:GetRetErr(ErrSendTxToNetFail)}
    ch <- res
    return
}

//ec2
//msgprex = hash 
//return value is the backup for dcrm sig.
func dcrm_sign(msgprex string,txhash string,save string,dcrmpkx *big.Int,dcrmpky *big.Int,cointype string,ch chan interface{}) string {

    if strings.EqualFold(cointype,"EOS") == true {
	lock5.Lock()
	//db
	dir := GetEosDbDir()
	db,err := ethdb.NewLDBDatabase(dir, 0, 0)
	//bug
	if err != nil {
	    for i:=0;i<1000;i++ {
		db,err = ethdb.NewLDBDatabase(dir, 0, 0)
		if err == nil {
		    break
		}
		
		time.Sleep(time.Duration(1000000))
	    }
	}
	//
	if db == nil {
	    fmt.Println("===========open db fail.=============")
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:open level db fail in func dcrm_sign",Err:GetRetErr(ErrCreateDbFail)}
	    ch <- res
	    lock5.Unlock()
	    return ""
	}
	
	var eosstr string
	var b bytes.Buffer 
	b.WriteString("") 
	b.WriteByte(0) 
	b.WriteString("") 
	iter := db.NewIterator() 
	for iter.Next() { 
	    key := string(iter.Key())
	    value := string(iter.Value())
	    if strings.EqualFold(key,string([]byte("eossettings"))) {
		eosstr = value
		break
	    }
	}
	iter.Release()
	///////
	if eosstr == "" {
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get eos setting data from db fail",Err:fmt.Errorf("get save date fail.")}
	    ch <- res
	    db.Close()
	    lock5.Unlock()
	    return ""
	}

	// Retrieve eospubkey
	eosstrs := strings.Split(string(eosstr),":")
	fmt.Println("======== get eos settings,eosstr = %s ========",eosstr)
	if len(eosstrs) != 5 {
	    var ret2 Err
	    ret2.Info = "get eos settings error: "+string(eosstr)
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:eos setting data error",Err:ret2}
	    ch <- res
	    return ""
	}
	pubhex := eosstrs[3]
	dcrmpks, _ := hex.DecodeString(pubhex)
	dcrmpkx2,dcrmpky2 := secp256k1.S256().Unmarshal(dcrmpks[:])
	//dcrmaddr := pubhex
	db.Close()
	lock5.Unlock()
	fmt.Println("======== dcrm_sign eos,pkx = %+v,pky = %+v,==========",dcrmpkx2,dcrmpky2)
	txhashs := []rune(txhash)
	if string(txhashs[0:2]) == "0x" {
	    txhash = string(txhashs[2:])
	}

	w,err := FindWorker(msgprex)
	if w == nil || err != nil {
	    logs.Debug("===========get worker fail.=============")
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:no find worker",Err:GetRetErr(ErrNoFindWorker)}
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
	for i := 0; i < 1; i++ {
		bak_sig = Sign_ec2(msgprex,save,txhash,cointype,dcrmpkx2,dcrmpky2,ch1,id)
		ret,tip,_ = GetChannelValue(ch_t,ch1)
		//if ret != "" && eos.IsCanonical([]byte(ret)) == true 
		if ret == "" {
			w := workers[id]
			w.Clear2()
			continue
		}
		b, _ := hex.DecodeString(ret)
		if eos.IsCanonical(b) == true {
			flag = true
			break
		}
		w := workers[id]
		w.Clear2()
	}
	if flag == false {
		res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:eos dcrm sign fail",Err:GetRetErr(ErrDcrmSigFail)}
		ch <- res
		return ""
	}

	res := RpcDcrmRes{Ret:ret,Tip:tip,Err:nil}
	ch <- res
	return bak_sig
    }
    
    /////////////
    txhashs := []rune(txhash)
    if string(txhashs[0:2]) == "0x" {
	txhash = string(txhashs[2:])
    }

    w,err := FindWorker(msgprex)
    if w == nil || err != nil {
	fmt.Println("===========get worker fail.=============")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:no find worker",Err:fmt.Errorf("no find worker.")}
	ch <- res
	return ""
    }
    id := w.id

    GetEnodesInfo(w.groupid) 
    
    if int32(Enode_cnts) != int32(NodeCnt) {
	fmt.Println("============the net group is not ready.please try again.================")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:the group is not ready",Err:fmt.Errorf("group not ready.")}
	ch <- res
	return ""
    }

    fmt.Println("===================!!!Start!!!====================")

    ///////
     if strings.EqualFold(cointype,"EVT1") == true {
	logs.Debug("======== dcrm_sign ready to call Sign_ec2","msgprex",msgprex,"save",save,"txhash",txhash,"cointype",cointype,"pkx",dcrmpkx,"pky",dcrmpky,"id",id)
	logs.Debug("!!! token type is EVT1 !!!")
	var ch1 = make(chan interface{}, 1)
	var flag = false
	var ret string
	var tip string
	var cherr error
	var bak_sig string
	//25-->1
	for i := 0; i < 1; i++ {
		bak_sig = Sign_ec2(msgprex,save,txhash,cointype,dcrmpkx,dcrmpky,ch1,id)
		ret, tip,cherr = GetChannelValue(ch_t,ch1)
		if cherr != nil {
			logs.Debug("======== dcrm_sign evt","cherr",cherr)
			time.Sleep(time.Duration(1)*time.Second) //1000 == 1s
			w := workers[id]
			w.Clear2()
			continue
		}
		logs.Debug("======== dcrm_sign evt","signature",ret,"","========")
		//if ret != "" && eos.IsCanonical([]byte(ret)) == true 
		if ret == "" {
			w := workers[id]
			w.Clear2()
			continue
		}
		b, _ := hex.DecodeString(ret)
		if eos.IsCanonical(b) == true {
			fmt.Printf("\nret is a canonical signature\n")
			flag = true
			break
		}
		w := workers[id]
		w.Clear2()
	}
	logs.Debug("======== dcrm_sign evt","got rsv flag",flag,"ret",ret,"","========")
	if flag == false {
		res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:dcrm sign fail",Err:GetRetErr(ErrDcrmSigFail)}
		ch <- res
		return ""
	}
	//ch <- ret
	res := RpcDcrmRes{Ret:ret,Tip:tip,Err:cherr}
	ch <- res
	return bak_sig
    } else {
	bak_sig := Sign_ec2(msgprex,save,txhash,cointype,dcrmpkx,dcrmpky,ch,id)
	return bak_sig
    }

    return ""
}

//msgprex = hash
//return value is the backup for the dcrm sig
func Sign_ec2(msgprex string,save string,message string,cointype string,pkx *big.Int,pky *big.Int,ch chan interface{},id int) string {
    if id < 0 || id >= len(workers) || id >= RpcMaxWorker {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:no find worker",Err:fmt.Errorf("no find worker.")}
	ch <- res
	return ""
    }
    
    w := workers[id]
    GroupId := w.groupid
    fmt.Println("========Sign_ec2============","GroupId",GroupId)
    if GroupId == "" {
	res := RpcDcrmRes{Ret:"",Tip:"get group id fail",Err:fmt.Errorf("get group id fail.")}
	ch <- res
	return ""
    }
    
    hashBytes, err2 := hex.DecodeString(message)
    if err2 != nil {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:decode message fail",Err:err2}
	ch <- res
	return ""
    }

    // [Notes]
    // 1. assume the nodes who take part in the signature generation as follows
    ids := GetIds(cointype,GroupId)
    idSign := ids[:ThresHold]
	
    // 1. map the share of private key to no-threshold share of private key
    var self *big.Int
    lambda1 := big.NewInt(1)
    for _,uid := range idSign {
	enodes := GetEnodesByUid(uid,cointype,GroupId)
	if IsCurNode(enodes,cur_enode) {
	    self = uid
	    break
	}
    }

    if self == nil {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get self uid fail in dcrm ec2 sign",Err:err2}
	ch <- res
	return ""
    }

    for i,uid := range idSign {
	enodes := GetEnodesByUid(uid,cointype,GroupId)
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	
	sub := new(big.Int).Sub(idSign[i], self)
	subInverse := new(big.Int).ModInverse(sub,secp256k1.S256().N)
	times := new(big.Int).Mul(subInverse, idSign[i])
	lambda1 = new(big.Int).Mul(lambda1, times)
	lambda1 = new(big.Int).Mod(lambda1, secp256k1.S256().N)
    }
    mm := strings.Split(save, SepSave)
    skU1 := new(big.Int).SetBytes([]byte(mm[0]))
    w1 := new(big.Int).Mul(lambda1, skU1)
    w1 = new(big.Int).Mod(w1,secp256k1.S256().N)
    
    // 2. select k and gamma randomly
    u1K := GetRandomIntFromZn(secp256k1.S256().N)
    if u1K == nil {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get random u1K fail",Err:fmt.Errorf("get random u1K fail.")}
	ch <- res
	return ""
    }

    u1Gamma := GetRandomIntFromZn(secp256k1.S256().N)
    if u1Gamma == nil {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get random u1Gamma fail",Err:fmt.Errorf("get random u1Gamma fail.")}
	ch <- res
	return ""
    }
    
    // 3. make gamma*G commitment to get (C, D)
    u1GammaGx,u1GammaGy := secp256k1.S256().ScalarBaseMult(u1Gamma.Bytes())
    commitU1GammaG := new(ec2.Commitment).Commit(u1GammaGx, u1GammaGy)

    // 4. Broadcast
    //	commitU1GammaG.C, commitU2GammaG.C, commitU3GammaG.C
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "C11"
    s1 := string(commitU1GammaG.C.Bytes())
    ss := enode + Sep + s0 + Sep + s1
    SendMsgToDcrmGroup(ss,GroupId)

    // 1. Receive Broadcast
    //	commitU1GammaG.C, commitU2GammaG.C, commitU3GammaG.C
     _,tip,cherr := GetChannelValue(ch_t,w.bc11)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:GetRetErr(ErrGetC11Timeout)}
	ch <- res
	return ""
    }
    
    // 2. MtA(k, gamma) and MtA(k, w)
    // 2.1 encrypt c_k = E_paillier(k)
    var ukc = make(map[string]*big.Int)
    var ukc2 = make(map[string]*big.Int)
    var ukc3 = make(map[string]*ec2.PublicKey)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1PaillierPk := GetPaillierPk(save,k)
	    u1KCipher,u1R,_ := u1PaillierPk.Encrypt(u1K)
	    ukc[en[0]] = u1KCipher
	    ukc2[en[0]] = u1R
	    ukc3[en[0]] = u1PaillierPk
	    break
	}
    }

    // 2.2 calculate zk(k)
    var zk1proof = make(map[string]*ec2.MtAZK1Proof)
    var zkfactproof = make(map[string]*ec2.ZkFactProof)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	u1zkFactProof := GetZkFactProof(save,k)
	zkfactproof[en[0]] = u1zkFactProof
	if IsCurNode(enodes,cur_enode) {
	    u1u1MtAZK1Proof := ec2.MtAZK1Prove(u1K,ukc2[en[0]], ukc3[en[0]], u1zkFactProof)
	    zk1proof[en[0]] = u1u1MtAZK1Proof
	} else {
	    u1u1MtAZK1Proof := ec2.MtAZK1Prove(u1K,ukc2[cur_enode], ukc3[cur_enode], u1zkFactProof)
	    mp := []string{msgprex,cur_enode}
	    enode := strings.Join(mp,"-")
	    s0 := "MTAZK1PROOF"
	    s1 := string(u1u1MtAZK1Proof.Z.Bytes()) 
	    s2 := string(u1u1MtAZK1Proof.U.Bytes()) 
	    s3 := string(u1u1MtAZK1Proof.W.Bytes()) 
	    s4 := string(u1u1MtAZK1Proof.S.Bytes()) 
	    s5 := string(u1u1MtAZK1Proof.S1.Bytes()) 
	    s6 := string(u1u1MtAZK1Proof.S2.Bytes()) 
	    ss := enode + Sep + s0 + Sep + s1 + Sep + s2 + Sep + s3 + Sep + s4 + Sep + s5 + Sep + s6
	    SendMsgToPeer(enodes,ss)
	}
    }

    _,tip,cherr = GetChannelValue(ch_t,w.bmtazk1proof)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:GetRetErr(ErrGetMTAZK1PROOFTimeout)}
	ch <- res
	return ""
    }

    // 2.3 Broadcast c_k, zk(k)
    // u1KCipher, u2KCipher, u3KCipher
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "KC"
    s1 = string(ukc[cur_enode].Bytes())
    ss = enode + Sep + s0 + Sep + s1
    SendMsgToDcrmGroup(ss,GroupId)

    // 2.4 Receive Broadcast c_k, zk(k)
    // u1KCipher, u2KCipher, u3KCipher
     _,tip,cherr = GetChannelValue(ch_t,w.bkc)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:GetRetErr(ErrGetKCTimeout)}
	ch <- res
	return ""
    }

    var i int
    kcs := make([]string,ThresHold-1)
    if w.msg_kc.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get all msg_kc fail",Err:GetRetErr(ErrGetAllKCFail)}
	ch <- res
	return ""
    }
    itmp := 0
    iter := w.msg_kc.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	kcs[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range kcs {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		kc := new(big.Int).SetBytes([]byte(mm[2]))
		ukc[en[0]] = kc
		break
	    }
	}
    }
   
    // example for u1, receive: u1u1MtAZK1Proof from u1, u2u1MtAZK1Proof from u2, u3u1MtAZK1Proof from u3
    mtazk1s := make([]string,ThresHold-1)
    if w.msg_mtazk1proof.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get all msg_mtazk1proof fail",Err:GetRetErr(ErrGetAllMTAZK1PROOFFail)}
	ch <- res
	return ""
    }
    itmp = 0
    iter = w.msg_mtazk1proof.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	mtazk1s[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range mtazk1s {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		z := new(big.Int).SetBytes([]byte(mm[2]))
		u := new(big.Int).SetBytes([]byte(mm[3]))
		w := new(big.Int).SetBytes([]byte(mm[4]))
		s := new(big.Int).SetBytes([]byte(mm[5]))
		s1 := new(big.Int).SetBytes([]byte(mm[6]))
		s2 := new(big.Int).SetBytes([]byte(mm[7]))
		mtAZK1Proof := &ec2.MtAZK1Proof{Z: z, U: u, W: w, S: s, S1: s1, S2: s2}
		zk1proof[en[0]] = mtAZK1Proof
		break
	    }
	}
    }

    // 2.5 verify zk(k)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1rlt1 := zk1proof[cur_enode].MtAZK1Verify(ukc[cur_enode],ukc3[cur_enode],zkfactproof[cur_enode])
	    if !u1rlt1 {
		res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:mtazk1proof verification fail",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }
	} else {
	    if len(en) <= 0 {
		res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:mtazk1proof verification fail",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }

	    _,exsit := zk1proof[en[0]]
	    if exsit == false {
		res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:mtazk1proof verification fail",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }

	    _,exsit = ukc[en[0]]
	    if exsit == false {
		res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:mtazk1proof not pass",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }
	    
	    u1PaillierPk := GetPaillierPk(save,k)
	    if u1PaillierPk == nil {
		res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:no find paillier pk data",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }

	    _,exsit = zkfactproof[cur_enode]
	    if exsit == false {
		res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:no find zkfactproof data",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }

	    u1rlt1 := zk1proof[en[0]].MtAZK1Verify(ukc[en[0]],u1PaillierPk,zkfactproof[cur_enode])
	    if !u1rlt1 {
		res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:mtazk1 verification fail",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }
	}
    }

    // 2.6
    // select betaStar randomly, and calculate beta, MtA(k, gamma)
    // select betaStar randomly, and calculate beta, MtA(k, w)
    
    // [Notes]
    // 1. betaStar is in [1, paillier.N - secp256k1.N^2]
    NSalt := new(big.Int).Lsh(big.NewInt(1), uint(PaillierKeyLength-PaillierKeyLength/10))
    NSubN2 := new(big.Int).Mul(secp256k1.S256().N, secp256k1.S256().N)
    NSubN2 = new(big.Int).Sub(NSalt, NSubN2)
    // 2. MinusOne
    MinusOne := big.NewInt(-1)
    
    betaU1Star := make([]*big.Int,ThresHold)
    betaU1 := make([]*big.Int,ThresHold)
    for i=0;i<ThresHold;i++ {
	beta1U1Star := GetRandomIntFromZn(NSubN2)
	if beta1U1Star == nil {
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get random beta1U1Star fail",Err:fmt.Errorf("get random beta1U1Star fail.")}
	    ch <- res
	    return ""
	}
	beta1U1 := new(big.Int).Mul(MinusOne, beta1U1Star)
	betaU1Star[i] = beta1U1Star
	betaU1[i] = beta1U1
    }

    vU1Star := make([]*big.Int,ThresHold)
    vU1 := make([]*big.Int,ThresHold)
    for i=0;i<ThresHold;i++ {
	v1U1Star := GetRandomIntFromZn(NSubN2)
	if v1U1Star == nil {
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get random v1U1Star fail",Err:fmt.Errorf("get random v1U1Star fail.")}
	    ch <- res
	    return ""
	}
	v1U1 := new(big.Int).Mul(MinusOne, v1U1Star)
	vU1Star[i] = v1U1Star
	vU1[i] = v1U1
    }

    // 2.7
    // send c_kGamma to proper node, MtA(k, gamma)   zk
    var mkg = make(map[string]*big.Int)
    var mkg_mtazk2 = make(map[string]*ec2.MtAZK2Proof)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1PaillierPk := GetPaillierPk(save,k)
	    u1KGamma1Cipher := u1PaillierPk.HomoMul(ukc[en[0]], u1Gamma)
	    beta1U1StarCipher, u1BetaR1,_ := u1PaillierPk.Encrypt(betaU1Star[k])
	    u1KGamma1Cipher = u1PaillierPk.HomoAdd(u1KGamma1Cipher, beta1U1StarCipher) // send to u1
	    u1u1MtAZK2Proof := ec2.MtAZK2Prove(u1Gamma, betaU1Star[k], u1BetaR1, ukc[cur_enode],ukc3[cur_enode], zkfactproof[cur_enode])
	    mkg[en[0]] = u1KGamma1Cipher
	    mkg_mtazk2[en[0]] = u1u1MtAZK2Proof
	    continue
	}
	
	u2PaillierPk := GetPaillierPk(save,k)
	u2KGamma1Cipher := u2PaillierPk.HomoMul(ukc[en[0]], u1Gamma)
	beta2U1StarCipher, u2BetaR1,_ := u2PaillierPk.Encrypt(betaU1Star[k])
	u2KGamma1Cipher = u2PaillierPk.HomoAdd(u2KGamma1Cipher, beta2U1StarCipher) // send to u2
	u2u1MtAZK2Proof := ec2.MtAZK2Prove(u1Gamma, betaU1Star[k], u2BetaR1, ukc[en[0]],u2PaillierPk,zkfactproof[cur_enode])
	mp = []string{msgprex,cur_enode}
	enode = strings.Join(mp,"-")
	s0 = "MKG"
	s1 = string(u2KGamma1Cipher.Bytes()) 
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
	ss = enode + Sep + s0 + Sep + s1 + Sep + s2 + Sep + s3 + Sep + s4 + Sep + s5 + Sep + s6 + Sep + s7 + Sep + s8 + Sep + s9 + Sep + s10 + Sep + s11
	SendMsgToPeer(enodes,ss)
    }
    
    // 2.8
    // send c_kw to proper node, MtA(k, w)   zk
    var mkw = make(map[string]*big.Int)
    var mkw_mtazk2 = make(map[string]*ec2.MtAZK2Proof)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1PaillierPk := GetPaillierPk(save,k)
	    u1Kw1Cipher := u1PaillierPk.HomoMul(ukc[en[0]], w1)
	    v1U1StarCipher, u1VR1,_ := u1PaillierPk.Encrypt(vU1Star[k])
	    u1Kw1Cipher = u1PaillierPk.HomoAdd(u1Kw1Cipher, v1U1StarCipher) // send to u1
	    u1u1MtAZK2Proof2 := ec2.MtAZK2Prove(w1, vU1Star[k], u1VR1, ukc[cur_enode], ukc3[cur_enode], zkfactproof[cur_enode])
	    mkw[en[0]] = u1Kw1Cipher
	    mkw_mtazk2[en[0]] = u1u1MtAZK2Proof2
	    continue
	}
	
	u2PaillierPk := GetPaillierPk(save,k)
	u2Kw1Cipher := u2PaillierPk.HomoMul(ukc[en[0]], w1)
	v2U1StarCipher, u2VR1,_ := u2PaillierPk.Encrypt(vU1Star[k])
	u2Kw1Cipher = u2PaillierPk.HomoAdd(u2Kw1Cipher,v2U1StarCipher) // send to u2
	u2u1MtAZK2Proof2 := ec2.MtAZK2Prove(w1, vU1Star[k], u2VR1, ukc[en[0]], u2PaillierPk, zkfactproof[cur_enode])

	mp = []string{msgprex,cur_enode}
	enode = strings.Join(mp,"-")
	s0 = "MKW"
	s1 = string(u2Kw1Cipher.Bytes()) 
	//////
	s2 := string(u2u1MtAZK2Proof2.Z.Bytes())
	s3 := string(u2u1MtAZK2Proof2.ZBar.Bytes())
	s4 := string(u2u1MtAZK2Proof2.T.Bytes())
	s5 := string(u2u1MtAZK2Proof2.V.Bytes())
	s6 := string(u2u1MtAZK2Proof2.W.Bytes())
	s7 := string(u2u1MtAZK2Proof2.S.Bytes())
	s8 := string(u2u1MtAZK2Proof2.S1.Bytes())
	s9 := string(u2u1MtAZK2Proof2.S2.Bytes())
	s10 := string(u2u1MtAZK2Proof2.T1.Bytes())
	s11 := string(u2u1MtAZK2Proof2.T2.Bytes())
	///////

	ss = enode + Sep + s0 + Sep + s1 + Sep + s2 + Sep + s3 + Sep + s4 + Sep + s5 + Sep + s6 + Sep + s7 + Sep + s8 + Sep + s9 + Sep + s10 + Sep + s11
	SendMsgToPeer(enodes,ss)
    }

    // 2.9
    // receive c_kGamma from proper node, MtA(k, gamma)   zk
     _,tip,cherr = GetChannelValue(ch_t,w.bmkg)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:GetRetErr(ErrGetMKGTimeout)}
	ch <- res
	return ""
    }

    mkgs := make([]string,ThresHold-1)
    if w.msg_mkg.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get all msg_mkg fail",Err:GetRetErr(ErrGetAllMKGFail)}
	ch <- res
	return ""
    }
    itmp = 0
    iter = w.msg_mkg.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	mkgs[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range mkgs {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
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
		mtAZK2Proof := &ec2.MtAZK2Proof{Z: z, ZBar: zbar, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}
		mkg_mtazk2[en[0]] = mtAZK2Proof
		break
	    }
	}
    }

    // 2.10
    // receive c_kw from proper node, MtA(k, w)    zk
    _,tip,cherr = GetChannelValue(ch_t,w.bmkw)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:GetRetErr(ErrGetMKWTimeout)}
	ch <- res
	return ""
    }

    mkws := make([]string,ThresHold-1)
    if w.msg_mkw.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get all msg_mkw fail",Err:GetRetErr(ErrGetAllMKWFail)}
	ch <- res
	return ""
    }
    itmp = 0
    iter = w.msg_mkw.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	mkws[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range mkws {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		kw := new(big.Int).SetBytes([]byte(mm[2]))
		mkw[en[0]] = kw

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
		mtAZK2Proof := &ec2.MtAZK2Proof{Z: z, ZBar: zbar, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}
		mkw_mtazk2[en[0]] = mtAZK2Proof
		break
	    }
	}
    }
    
    // 2.11 verify zk
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	rlt111 := mkg_mtazk2[en[0]].MtAZK2Verify(ukc[cur_enode], mkg[en[0]],ukc3[cur_enode], zkfactproof[en[0]])
	if !rlt111 {
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:mtazk2 verification fail",Err:GetRetErr(ErrVerifyMKGFail)}
	    ch <- res
	    return ""
	}

	rlt112 := mkw_mtazk2[en[0]].MtAZK2Verify(ukc[cur_enode], mkw[en[0]], ukc3[cur_enode], zkfactproof[en[0]])
	if !rlt112 {
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:mkw mtazk2 verify fail",Err:fmt.Errorf("mkw mtazk2 verify fail.")}
	    ch <- res
	    return ""
	}
    }
    
    // 2.12
    // decrypt c_kGamma to get alpha, MtA(k, gamma)
    // MtA(k, gamma)
    var index int
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	if IsCurNode(enodes,cur_enode) {
	    index = k
	    break
	}
    }

    u1PaillierSk := GetPaillierSk(save,index)
    if u1PaillierSk == nil {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get sk fail",Err:fmt.Errorf("get sk fail.")}
	ch <- res
	return ""
    }

    alpha1 := make([]*big.Int,ThresHold)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	alpha1U1, _ := u1PaillierSk.Decrypt(mkg[en[0]])
	alpha1[k] = alpha1U1
    }

    // 2.13
    // decrypt c_kw to get u, MtA(k, w)
    // MtA(k, w)
    uu1 := make([]*big.Int,ThresHold)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	u1U1, _ := u1PaillierSk.Decrypt(mkw[en[0]])
	uu1[k] = u1U1
    }

    // 2.14
    // calculate delta, MtA(k, gamma)
    delta1 := alpha1[0]
    for i=0;i<ThresHold;i++ {
	if i == 0 {
	    continue
	}
	delta1 = new(big.Int).Add(delta1,alpha1[i])
    }
    for i=0;i<ThresHold;i++ {
	delta1 = new(big.Int).Add(delta1, betaU1[i])
    }

    // 2.15
    // calculate sigma, MtA(k, w)
    sigma1 := uu1[0]
    for i=0;i<ThresHold;i++ {
	if i == 0 {
	    continue
	}
	sigma1 = new(big.Int).Add(sigma1,uu1[i])
    }
    for i=0;i<ThresHold;i++ {
	sigma1 = new(big.Int).Add(sigma1, vU1[i])
    }

    // 3. Broadcast
    // delta: delta1, delta2, delta3
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "DELTA1"
    zero,_ := new(big.Int).SetString("0",10)
    if delta1.Cmp(zero) < 0 { //bug
	s1 = "0" + SepDel + string(delta1.Bytes())
    } else {
	s1 = string(delta1.Bytes())
    }
    ss = enode + Sep + s0 + Sep + s1
    SendMsgToDcrmGroup(ss,GroupId)

    // 1. Receive Broadcast
    // delta: delta1, delta2, delta3
     _,tip,cherr = GetChannelValue(ch_t,w.bdelta1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:fmt.Errorf("get all delta timeout.")}
	ch <- res
	return ""
    }
    
    var delta1s = make(map[string]*big.Int)
    delta1s[cur_enode] = delta1

    dels := make([]string,ThresHold-1)
    if w.msg_delta1.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get all msg_delta1 fail",Err:fmt.Errorf("get all delta fail.")}
	ch <- res
	return ""
    }
    itmp = 0
    iter = w.msg_delta1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	dels[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range dels {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		tmps := strings.Split(mm[2], SepDel)
		if len(tmps) == 2 {
		    del := new(big.Int).SetBytes([]byte(tmps[1]))
		    del = new(big.Int).Sub(zero,del) //bug:-xxxxxxx
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
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	deltaSum = delta1s[en[0]]
	break
    }
    for k,id := range idSign {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	//bug
	if deltaSum == nil || len(en) < 1 || delta1s[en[0]] == nil {
	    var ret2 Err
	    ret2.Info = "calc deltaSum error"
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:calc deltasum error",Err:ret2}
	    ch <- res
	    return ""
	}
	deltaSum = new(big.Int).Add(deltaSum,delta1s[en[0]])
    }
    deltaSum = new(big.Int).Mod(deltaSum, secp256k1.S256().N)

    // 3. Broadcast
    // commitU1GammaG.D, commitU2GammaG.D, commitU3GammaG.D
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "D11"
    dlen := len(commitU1GammaG.D)
    s1 = strconv.Itoa(dlen)

    ss = enode + Sep + s0 + Sep + s1 + Sep
    for _,d := range commitU1GammaG.D {
	ss += string(d.Bytes())
	ss += Sep
    }
    ss = ss + "NULL"
    SendMsgToDcrmGroup(ss,GroupId)

    // 1. Receive Broadcast
    // commitU1GammaG.D, commitU2GammaG.D, commitU3GammaG.D
    _,tip,cherr = GetChannelValue(ch_t,w.bd11_1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:fmt.Errorf("get all c11 fail.")}
	ch <- res
	return ""
    }

    d11s := make([]string,ThresHold-1)
    if w.msg_d11_1.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get msg_d11_1 fail",Err:fmt.Errorf("get all c11 fail.")}
	ch <- res
	return ""
    }
    itmp = 0
    iter = w.msg_d11_1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	d11s[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    c11s := make([]string,ThresHold-1)
    if w.msg_c11.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get all msg_c11 fail",Err:fmt.Errorf("get all c11 fail.")}
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

    // 2. verify and de-commitment to get GammaG
    
    // for all nodes, construct the commitment by the receiving C and D
    var udecom = make(map[string]*ec2.Commitment)
    for _,v := range c11s {
	mm := strings.Split(v, Sep)
	prex := mm[0]
	prexs := strings.Split(prex,"-")
	for _,vv := range d11s {
	    mmm := strings.Split(vv, Sep)
	    prex2 := mmm[0]
	    prexs2 := strings.Split(prex2,"-")
	    if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
		dlen,_ := strconv.Atoi(mmm[2])
		var gg = make([]*big.Int,0)
		l := 0
		for j:=0;j<dlen;j++ {
		    l++
		    gg = append(gg,new(big.Int).SetBytes([]byte(mmm[2+l])))
		}
		deCommit := &ec2.Commitment{C:new(big.Int).SetBytes([]byte(mm[2])), D:gg}
		udecom[prexs[len(prexs)-1]] = deCommit
		break
	    }
	}
    }
    deCommit_commitU1GammaG := &ec2.Commitment{C: commitU1GammaG.C, D: commitU1GammaG.D}
    udecom[cur_enode] = deCommit_commitU1GammaG

    // for all nodes, verify the commitment
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	//bug
	if len(en) <= 0 {
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:verify commit fail",Err:fmt.Errorf("verify commit fail.")}
	    ch <- res
	    return ""
	}
	_,exsit := udecom[en[0]]
	if exsit == false {
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:verify commit fail",Err:fmt.Errorf("verify commit fail.")}
	    ch <- res
	    return ""
	}
	//

	if udecom[en[0]].Verify() == false {
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:verify commit fail",Err:fmt.Errorf("verify commit fail.")}
	    ch <- res
	    return ""
	}
    }

    // for all nodes, de-commitment
    var ug = make(map[string][]*big.Int)
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	_, u1GammaG := udecom[en[0]].DeCommit()
	ug[en[0]] = u1GammaG
    }

    // for all nodes, calculate the GammaGSum
    var GammaGSumx *big.Int
    var GammaGSumy *big.Int
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	GammaGSumx = (ug[en[0]])[0]
	GammaGSumy = (ug[en[0]])[1]
	break
    }

    for k,id := range idSign {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	GammaGSumx, GammaGSumy = secp256k1.S256().Add(GammaGSumx, GammaGSumy, (ug[en[0]])[0],(ug[en[0]])[1])
    }
	
    // 3. calculate deltaSum^-1 * GammaGSum
    deltaSumInverse := new(big.Int).ModInverse(deltaSum, secp256k1.S256().N)
    deltaGammaGx, deltaGammaGy := secp256k1.S256().ScalarMult(GammaGSumx, GammaGSumy, deltaSumInverse.Bytes())

    // 4. get r = deltaGammaGx
    r := deltaGammaGx

    if r.Cmp(zero) == 0 {
//	log.Debug("sign error: r equal zero.")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:r = 0",Err:fmt.Errorf("r == 0.")}
	ch <- res
	return ""
    }
    
    // 5. calculate s
    mMtA,_ := new(big.Int).SetString(message,16)
    
    mk1 := new(big.Int).Mul(mMtA, u1K)
    rSigma1 := new(big.Int).Mul(deltaGammaGx, sigma1)
    us1 := new(big.Int).Add(mk1, rSigma1)
    us1 = new(big.Int).Mod(us1, secp256k1.S256().N)
    
    // 6. calculate S = s * R
    S1x, S1y := secp256k1.S256().ScalarMult(deltaGammaGx, deltaGammaGy, us1.Bytes())
    
    // 7. Broadcast
    // S: S1, S2, S3
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "S1"
    s1 = string(S1x.Bytes())
    s2 := string(S1y.Bytes())
    ss = enode + Sep + s0 + Sep + s1 + Sep + s2
    SendMsgToDcrmGroup(ss,GroupId)

    // 1. Receive Broadcast
    // S: S1, S2, S3
    _,tip,cherr = GetChannelValue(ch_t,w.bs1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:fmt.Errorf("get s1 timeout.")}
	ch <- res
	return ""
    }

    var s1s = make(map[string][]*big.Int)
    s1ss := []*big.Int{S1x,S1y}
    s1s[cur_enode] = s1ss

    us1s := make([]string,ThresHold-1)
    if w.msg_s1.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get all msg_s1 fail",Err:fmt.Errorf("get s1 fail.")}
	ch <- res
	return ""
    }
    itmp = 0
    iter = w.msg_s1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	us1s[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range us1s {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		x := new(big.Int).SetBytes([]byte(mm[2]))
		y := new(big.Int).SetBytes([]byte(mm[3]))
		tmp := []*big.Int{x,y}
		s1s[en[0]] = tmp
		break
	    }
	}
    }

    // 2. calculate SAll
    var SAllx *big.Int
    var SAlly *big.Int
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	SAllx = (s1s[en[0]])[0]
	SAlly = (s1s[en[0]])[1]
	break
    }

    for k,id := range idSign {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	SAllx, SAlly = secp256k1.S256().Add(SAllx, SAlly, (s1s[en[0]])[0],(s1s[en[0]])[1])
    }
	
    // 3. verify SAll ?= m*G + r*PK
    mMtAGx, mMtAGy := secp256k1.S256().ScalarBaseMult(mMtA.Bytes())
    rMtAPKx, rMtAPKy := secp256k1.S256().ScalarMult(pkx, pky, deltaGammaGx.Bytes())
    SAllComputex, SAllComputey := secp256k1.S256().Add(mMtAGx, mMtAGy, rMtAPKx, rMtAPKy)

    if SAllx.Cmp(SAllComputex) != 0 || SAlly.Cmp(SAllComputey) != 0 {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:SAll != m*G + r*PK",Err:fmt.Errorf("verify SAll != m*G + r*PK in sign ec2.")}
	ch <- res
	return ""
    }

    // 4. Broadcast
    // s: s1, s2, s3
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "SS1"
    s1 = string(us1.Bytes())
    ss = enode + Sep + s0 + Sep + s1
    SendMsgToDcrmGroup(ss,GroupId)

    // 1. Receive Broadcast
    // s: s1, s2, s3
    _,tip,cherr = GetChannelValue(ch_t,w.bss1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:fmt.Errorf("get ss1 timeout.")}
	ch <- res
	return ""
    }

    var ss1s = make(map[string]*big.Int)
    ss1s[cur_enode] = us1

    uss1s := make([]string,ThresHold-1)
    if w.msg_ss1.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get all msg_ss1 fail",Err:fmt.Errorf("get ss1 fail.")}
	ch <- res
	return ""
    }
    itmp = 0
    iter = w.msg_ss1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	uss1s[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range uss1s {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		tmp := new(big.Int).SetBytes([]byte(mm[2]))
		ss1s[en[0]] = tmp
		break
	    }
	}
    }

    // 2. calculate s
    var sSum *big.Int
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	sSum = ss1s[en[0]]
	break
    }

    for k,id := range idSign {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	//bug
	if sSum == nil || len(en) == 0 || en[0] == "" || len(ss1s) == 0 || ss1s[en[0]] == nil {
	fmt.Println("=================================== !!!Sign_ec2,calc s error. !!! =======================================",)
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("calculate s error.")}
	ch <- res
	return ""
	}
	//
	sSum = new(big.Int).Add(sSum,ss1s[en[0]])
    }
    sSum = new(big.Int).Mod(sSum, secp256k1.S256().N) 
   
    // 3. justify the s
    bb := false
    halfN := new(big.Int).Div(secp256k1.S256().N, big.NewInt(2))
    if sSum.Cmp(halfN) > 0 {
	bb = true
	sSum = new(big.Int).Sub(secp256k1.S256().N, sSum)
    }

    s := sSum
    if s.Cmp(zero) == 0 {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:s = 0",Err:fmt.Errorf("s == 0.")}
	ch <- res
	return ""
    }

    // **[End-Test]  verify signature with MtA
    signature := new(ECDSASignature)
    signature.New()
    signature.SetR(r)
    signature.SetS(s)

    //v
    recid := secp256k1.Get_ecdsa_sign_v(deltaGammaGx, deltaGammaGy)
    if cointype == "ETH" && bb {
	recid ^=1
    }
    if cointype == "BTC" && bb {
	recid ^= 1
    }

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

    if Verify(signature.GetR(),signature.GetS(),signature.GetRecoveryParam(),message,pkx,pky) == false {
	fmt.Println("===================dcrm sign,verify is false=================")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:sign verify fail",Err:fmt.Errorf("sign verify fail.")}
	ch <- res
	return ""
    }

    signature2 := GetSignString(signature.GetR(),signature.GetS(),signature.GetRecoveryParam(),int(signature.GetRecoveryParam()))
    rstring := "========================== r = " + fmt.Sprintf("%v",signature.GetR()) + " ========================="
    sstring := "========================== s = " + fmt.Sprintf("%v",signature.GetS()) + " =========================="
    fmt.Println(rstring)
    fmt.Println(sstring)
    sigstring := "========================== rsv str = " + signature2 + " ==========================="
    fmt.Println(sigstring)
    res := RpcDcrmRes{Ret:signature2,Err:nil}
    ch <- res
    
    return "" 
}

func GetPaillierPk(save string,index int) *ec2.PublicKey {
    if save == "" || index < 0 {
	return nil
    }

    mm := strings.Split(save, SepSave)
    s := 4 + 4*index
    l := mm[s]
    n := new(big.Int).SetBytes([]byte(mm[s+1]))
    g := new(big.Int).SetBytes([]byte(mm[s+2]))
    n2 := new(big.Int).SetBytes([]byte(mm[s+3]))
    publicKey := &ec2.PublicKey{Length: l, N: n, G: g, N2: n2}
    return publicKey
}

func GetPaillierSk(save string,index int) *ec2.PrivateKey {
    publicKey := GetPaillierPk(save,index)
    if publicKey != nil {
	mm := strings.Split(save, SepSave)
	l := mm[1]
	ll := new(big.Int).SetBytes([]byte(mm[2]))
	uu := new(big.Int).SetBytes([]byte(mm[3]))
	privateKey := &ec2.PrivateKey{Length: l, PublicKey: *publicKey, L: ll, U: uu}
	return privateKey
    }

    return nil
}

func GetZkFactProof(save string,index int) *ec2.ZkFactProof {
    if save == "" || index < 0 {
	return nil
    }

    mm := strings.Split(save, SepSave)
    s := 4 + 4*NodeCnt + 5*index////????? TODO
    h1 := new(big.Int).SetBytes([]byte(mm[s]))
    h2 := new(big.Int).SetBytes([]byte(mm[s+1]))
    y := new(big.Int).SetBytes([]byte(mm[s+2]))
    e := new(big.Int).SetBytes([]byte(mm[s+3]))
    n := new(big.Int).SetBytes([]byte(mm[s+4]))
    zkFactProof := &ec2.ZkFactProof{H1: h1, H2: h2, Y: y, E: e,N: n}
    return zkFactProof
}

func SendMsgToDcrmGroup(msg string,groupid string) {
    fmt.Println("==============SendMsgToDcrmGroup,msg =%s,send to groupid =%s =================",msg,groupid)
    BroadcastInGroupOthers(groupid,msg)
}

///
func EncryptMsg (msg string,enodeID string) (string, error) {
    fmt.Println("=============EncryptMsg,KeyFile = %s,enodeID = %s ================",KeyFile,enodeID)
    hprv, err1 := hex.DecodeString(enodeID)
    if err1 != nil {
	return "",err1
    }

    fmt.Println("=============EncryptMsg,hprv len = %v ================",len(hprv))
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
	return "",err
    }

    return string(cm),nil
}

func DecryptMsg (cm string) (string, error) {
    fmt.Println("=============DecryptMsg,KeyFile = %s ================",KeyFile)
    nodeKey, errkey := crypto.LoadECDSA(KeyFile)
    if errkey != nil {
	return "",errkey
    }

    prv := ecies.ImportECDSA(nodeKey)
    var m []byte
    m, err := prv.Decrypt([]byte(cm), nil, nil)
    if err != nil {
	return "",err
    }

    return string(m),nil
}
///

func SendMsgToPeer(enodes string,msg string) {
    fmt.Println("==============SendMsgToPeer,msg =%s,send to peer %s ===================",msg,enodes)
    en := strings.Split(string(enodes[8:]),"@")
    cm,err := EncryptMsg(msg,en[0])
    if err != nil {
	fmt.Println("==============SendMsgToPeer,encrypt msg fail,err = %v ===================",err)
	return
    }

    SendToPeer(enodes,cm)
}

type ECDSASignature struct {
	r *big.Int
	s *big.Int
	recoveryParam int32
	roudFiveAborted bool
}

func (this *ECDSASignature) New() {
}

func (this *ECDSASignature) New2(r *big.Int,s *big.Int) {
    this.r = r
    this.s = s
}

func (this *ECDSASignature) New3(r *big.Int,s *big.Int,recoveryParam int32) {
    this.r =r 
    this.s = s
    this.recoveryParam = recoveryParam
}

func Verify2(r *big.Int,s *big.Int,v int32,message string,pkx *big.Int,pky *big.Int) bool {
    z,_ := new(big.Int).SetString(message,16)
    ss := new(big.Int).ModInverse(s,secp256k1.S256().N)
    zz := new(big.Int).Mul(z,ss)
    u1 := new(big.Int).Mod(zz,secp256k1.S256().N)

    zz2 := new(big.Int).Mul(r,ss)
    u2 := new(big.Int).Mod(zz2,secp256k1.S256().N)
    
    if u1.Sign() == -1 {
		u1.Add(u1,secp256k1.S256().P)
    }
    ug := make([]byte, 32)
    ReadBits(u1, ug[:])
    ugx,ugy := secp256k1.KMulG(ug[:])

    if u2.Sign() == -1 {
		u2.Add(u2,secp256k1.S256().P)
	}
    upk := make([]byte, 32)
    ReadBits(u2,upk[:])
    upkx,upky := secp256k1.S256().ScalarMult(pkx,pky,upk[:])

    xxx,_ := secp256k1.S256().Add(ugx,ugy,upkx,upky)
    xR := new(big.Int).Mod(xxx,secp256k1.S256().N)

    if xR.Cmp(r) == 0 {
	errstring := "============= ECDSA Signature Verify Passed! (r,s) is a Valid Signature ================"
	fmt.Println(errstring)
	return true
    }

    errstring := "================ @@ERROR@@@@@@@@@@@@@@@@@@@@@@@@@@@@: ECDSA Signature Verify NOT Passed! (r,s) is a InValid Siganture! ================"
    fmt.Println(errstring)
    return false
}

////ed
//msgprex = hash 
//return value is the backup for dcrm sig.
func dcrm_sign_ed(msgprex string,txhash string,save string,pk string,cointype string,ch chan interface{}) string {

    txhashs := []rune(txhash)
    if string(txhashs[0:2]) == "0x" {
	txhash = string(txhashs[2:])
    }

    w,err := FindWorker(msgprex)
    if w == nil || err != nil {
	logs.Debug("===========get worker fail.=============")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:no find worker",Err:GetRetErr(ErrNoFindWorker)}
	ch <- res
	return ""
    }
    id := w.id

    GetEnodesInfo(w.groupid) 
    
    if int32(Enode_cnts) != int32(NodeCnt) {
	logs.Debug("============the net group is not ready.please try again.================")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:the group is not ready",Err:GetRetErr(ErrGroupNotReady)}
	ch <- res
	return ""
    }

    logs.Debug("===================!!!Start!!!====================")

    bak_sig := Sign_ed(msgprex,save,txhash,cointype,pk,ch,id)
    return bak_sig
}

//msgprex = hash
//return value is the backup for the dcrm sig
func Sign_ed(msgprex string,save string,message string,cointype string,pk string,ch chan interface{},id int) string {
    defer func () {
	if e := recover(); e != nil {
	    fmt.Errorf("Sign_ed,Runtime error: %v\n%v", e, string(debug.Stack()))
		return 
	}
    } ()

    logs.Debug("===================Sign_ed====================")
    if id < 0 || id >= len(workers) || id >= RpcMaxWorker {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get worker id fail",Err:GetRetErr(ErrGetWorkerIdError)}
	ch <- res
	return ""
    }

    w := workers[id]
    GroupId := w.groupid 
    fmt.Println("========Sign_ed============","GroupId",GroupId)
    if GroupId == "" {
	res := RpcDcrmRes{Ret:"",Tip:"get group id fail",Err:fmt.Errorf("get group id fail.")}
	ch <- res
	return ""
    }
    
    ns,_ := GetGroup(GroupId)
    if ns != NodeCnt {
	logs.Debug("Sign_ed,get nodes info error.")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:the group is not ready",Err:GetRetErr(ErrGroupNotReady)}
	ch <- res
	return "" 
    }
    
    logs.Debug("===========Sign_ed============","save len",len(save),"save",save)

    ids := GetIds(cointype,GroupId)
    idSign := ids[:ThresHold]
    
    m := strings.Split(save,common.Sep11)

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
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	//num,_ := new(big.Int).SetString(fixid[k],10)
	var t [32]byte
	//copy(t[:], num.Bytes())
	copy(t[:], id.Bytes())
	if len(id.Bytes()) < 32 {
	    l := len(id.Bytes())
	    for j:= l;j<32;j++ {
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
    
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "EDC21"
    s1 := string(CR[:])

    ss := enode + common.Sep + s0 + common.Sep + s1
    logs.Debug("================sign ed round one,send msg,code is EDC21==================")
    SendMsgToDcrmGroup(ss,GroupId)
    
    _,tip,cherr := GetChannelValue(ch_t,w.bedc21)
    if cherr != nil {
	logs.Debug("get w.bedc21 timeout.")
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:fmt.Errorf("get ed c21 timeout.")}
	ch <- res
	return "" 
    }

    if w.msg_edc21.Len() != (NodeCnt-1) {
	logs.Debug("get w.msg_edc21 fail.")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get msg_edc21 fail",Err:fmt.Errorf("get all ed c21 fail.")}
	ch <- res
	return ""
    }
    var crs = make(map[string][32]byte)
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	if IsCurNode(enodes,cur_enode) {
	    crs[cur_enode] = CR
	    continue
	}

	en := strings.Split(string(enodes[8:]),"@")
	
	iter := w.msg_edc21.Front()
	for iter != nil {
	    data := iter.Value.(string)
	    m := strings.Split(data,common.Sep)
	    ps := strings.Split(m[0],"-")
	    if strings.EqualFold(ps[1],en[0]) {
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
    SendMsgToDcrmGroup(ss,GroupId)
    
    _,tip,cherr = GetChannelValue(ch_t,w.bedzkr)
    if cherr != nil {
	logs.Debug("get w.bedzkr timeout.")
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:fmt.Errorf("get ed zkr timeout.")}
	ch <- res
	return ""
    }

    if w.msg_edzkr.Len() != (NodeCnt-1) {
	logs.Debug("get w.msg_edzkr fail.")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get all msg_edzkr fail",Err:fmt.Errorf("get all ed zkr fail.")}
	ch <- res
	return ""
    }

    var zkrs = make(map[string][64]byte)
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	if IsCurNode(enodes,cur_enode) {
	    zkrs[cur_enode] = zkR
	    continue
	}

	en := strings.Split(string(enodes[8:]),"@")
	
	iter := w.msg_edzkr.Front()
	for iter != nil {
	    data := iter.Value.(string)
	    m := strings.Split(data,common.Sep)
	    ps := strings.Split(m[0],"-")
	    if strings.EqualFold(ps[1],en[0]) {
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
    SendMsgToDcrmGroup(ss,GroupId)
    
    _,tip,cherr = GetChannelValue(ch_t,w.bedd21)
    if cherr != nil {
	logs.Debug("get w.bedd21 timeout.")
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:fmt.Errorf("get ed d21 timeout.")}
	ch <- res
	return ""
    }

    if w.msg_edd21.Len() != (NodeCnt-1) {
	logs.Debug("get w.msg_edd21 fail.")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get all msg_edd21 fail",Err:fmt.Errorf("get all ed d21 fail.")}
	ch <- res
	return ""
    }
    var drs = make(map[string][64]byte)
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	if IsCurNode(enodes,cur_enode) {
	    drs[cur_enode] = DR
	    continue
	}

	en := strings.Split(string(enodes[8:]),"@")
	
	iter := w.msg_edd21.Front()
	for iter != nil {
	    data := iter.Value.(string)
	    m := strings.Split(data,common.Sep)
	    ps := strings.Split(m[0],"-")
	    if strings.EqualFold(ps[1],en[0]) {
		var t [64]byte
		va := []byte(m[2]) 
		copy(t[:], va[:64])
		drs[en[0]] = t
		break
	    }
	    iter = iter.Next()
	}
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	CRFlag := ed.Verify(crs[en[0]],drs[en[0]])
	if !CRFlag {
	    fmt.Println("Error: Commitment(R) Not Pass at User: %s", en[0])
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:commitment verification fail in ed sign",Err:fmt.Errorf("Commitment(R) Not Pass.")}
	    ch <- res
	    return ""
	}
    }
    
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	var temR [32]byte
	t := drs[en[0]]
	copy(temR[:], t[32:])

	zkRFlag := ed.Verify_zk(zkrs[en[0]], temR)
	if !zkRFlag {
	    fmt.Println("Error: ZeroKnowledge Proof (R) Not Pass at User: %s", en[0])
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:zeroknowledge verification fail in ed sign",Err:fmt.Errorf("ZeroKnowledge Proof (R) Not Pass.")}
	    ch <- res
	    return ""
	}
    }
    
    var FinalR, temR ed.ExtendedGroupElement
    var FinalRBytes [32]byte
    for index,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	var temRBytes [32]byte
	t := drs[en[0]]
	copy(temRBytes[:],t[32:])
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

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
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
    SendMsgToDcrmGroup(ss,GroupId)
    
    _,tip,cherr = GetChannelValue(ch_t,w.bedc31)
    if cherr != nil {
	logs.Debug("get w.bedc31 timeout.")
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:fmt.Errorf("get ed c31 timeout.")}
	ch <- res
	return ""
    }

    if w.msg_edc31.Len() != (NodeCnt-1) {
	logs.Debug("get w.msg_edc31 fail.")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get msg_edc31 fail",Err:fmt.Errorf("get all ed c31 fail.")}
	ch <- res
	return ""
    }
    var csbs = make(map[string][32]byte)
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	if IsCurNode(enodes,cur_enode) {
	    csbs[cur_enode] = CSB
	    continue
	}

	en := strings.Split(string(enodes[8:]),"@")
	
	iter := w.msg_edc31.Front()
	for iter != nil {
	    data := iter.Value.(string)
	    m := strings.Split(data,common.Sep)
	    ps := strings.Split(m[0],"-")
	    if strings.EqualFold(ps[1],en[0]) {
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
    SendMsgToDcrmGroup(ss,GroupId)
    
    _,tip,cherr = GetChannelValue(ch_t,w.bedd31)
    if cherr != nil {
	logs.Debug("get w.bedd31 timeout.")
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:fmt.Errorf("get ed d31 timeout.")}
	ch <- res
	return "" 
    }

    if w.msg_edd31.Len() != (NodeCnt-1) {
	logs.Debug("get w.msg_edd31 fail.")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get all msg_edd31 fail",Err:fmt.Errorf("get all ed d31 fail.")}
	ch <- res
	return ""
    }
    var dsbs = make(map[string][64]byte)
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	if IsCurNode(enodes,cur_enode) {
	    dsbs[cur_enode] = DSB
	    continue
	}

	en := strings.Split(string(enodes[8:]),"@")
	
	iter := w.msg_edd31.Front()
	for iter != nil {
	    data := iter.Value.(string)
	    m := strings.Split(data,common.Sep)
	    ps := strings.Split(m[0],"-")
	    if strings.EqualFold(ps[1],en[0]) {
		var t [64]byte
		va := []byte(m[2]) 
		copy(t[:], va[:64])
		dsbs[en[0]] = t
		break
	    }
	    iter = iter.Next()
	}
    }
    
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	CSBFlag := ed.Verify(csbs[en[0]],dsbs[en[0]])
	if !CSBFlag {
	    fmt.Println("Error: Commitment(SB) Not Pass at User: %s",en[0])
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:commitment(CSB) not pass",Err:fmt.Errorf("Commitment(SB) Not Pass.")}
	    ch <- res
	    return ""
	}
    }
    
    var sB2, temSB ed.ExtendedGroupElement
    for index,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
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
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:not pass verification (CSB == SBCal)",Err:fmt.Errorf("Error: Not Pass Verification (SB = SBCal).")}
	ch <- res
	return ""
    }

    s0 = "EDS"
    s1 = string(s[:])
    ss = enode + common.Sep + s0 + common.Sep + s1
    logs.Debug("================sign ed round one,send msg,code is EDS==================")
    SendMsgToDcrmGroup(ss,GroupId)
    
    _,tip,cherr = GetChannelValue(ch_t,w.beds)
    if cherr != nil {
	logs.Debug("get w.beds timeout.")
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:fmt.Errorf("get ed s timeout.")}
	ch <- res
	return ""
    }

    if w.msg_eds.Len() != (NodeCnt-1) {
	logs.Debug("get w.msg_eds fail.")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get msg_eds fail",Err:fmt.Errorf("get all ed s fail.")}
	ch <- res
	return ""
    }
    var eds = make(map[string][32]byte)
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	if IsCurNode(enodes,cur_enode) {
	    eds[cur_enode] = s
	    continue
	}

	en := strings.Split(string(enodes[8:]),"@")
	
	iter := w.msg_eds.Front()
	for iter != nil {
	    data := iter.Value.(string)
	    m := strings.Split(data,common.Sep)
	    ps := strings.Split(m[0],"-")
	    if strings.EqualFold(ps[1],en[0]) {
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
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	t := eds[en[0]]
	ed.ScAdd(&FinalS, &FinalS, &t)
    }
    
    inputVerify := InputVerify{FinalR: FinalRBytes, FinalS: FinalS, Message: []byte(message), FinalPk: pkfinal}
    
    var pass = EdVerify(inputVerify)
    fmt.Println("===========ed verify pass=%v===============",pass)

    //r
    rx := hex.EncodeToString(FinalRBytes[:])
    sx := hex.EncodeToString(FinalS[:])
    logs.Debug("========sign_ed========","rx",rx,"sx",sx,"FinalRBytes",FinalRBytes,"FinalS",FinalS)

    //////test
    signature := new([64]byte)
    copy(signature[:], FinalRBytes[:])
    copy(signature[32:], FinalS[:])
    suss := ed25519.Verify(&pkfinal,[]byte(message),signature)
    fmt.Println("===========ed verify pass again=%v===============",suss)
    //////

    res := RpcDcrmRes{Ret:rx+":"+sx,Tip:"",Err:nil}
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

func IsCurNode(enodes string,cur string) bool {
    if enodes == "" || cur == "" {
	return false
    }

    s := []rune(enodes)
    en := strings.Split(string(s[8:]),"@")
    if en[0] == cur {
	return true
    }

    return false
}

func DoubleHash(id string,cointype string) *big.Int {
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
        ed.ScMulAdd(&digest,&digest,&one,&zero)
        //////
	digestBigInt := new(big.Int).SetBytes(digest[:])
	return digestBigInt
    }
    
    digest := sha3256.Sum(nil)
    // convert the hash ([]byte) to big.Int
    digestBigInt := new(big.Int).SetBytes(digest)
    return digestBigInt
}

func GetRandomInt(length int) *big.Int {
	// NewInt allocates and returns a new Int set to x.
	/*one := big.NewInt(1)
	// Lsh sets z = x << n and returns z.
	maxi := new(big.Int).Lsh(one, uint(length))

	// TODO: Random Seed, need to be replace!!!
	// New returns a new Rand that uses random values from src to generate other random values.
	// NewSource returns a new pseudo-random Source seeded with the given value.
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	// Rand sets z to a pseudo-random number in [0, n) and returns z.
	rndNum := new(big.Int).Rand(rnd, maxi)*/
	one := big.NewInt(1)
	maxi := new(big.Int).Lsh(one, uint(length))
	maxi = new(big.Int).Sub(maxi,one)
	rndNum,err := rand.Int(rand.Reader,maxi)
	if err != nil {
	    return nil
	}

	return rndNum
}

func GetRandomIntFromZn(n *big.Int) *big.Int {
	var rndNumZn *big.Int
	zero := big.NewInt(0)

	for {
		rndNumZn = GetRandomInt(n.BitLen())
		if rndNumZn == nil {
		    return nil
		}

		if rndNumZn.Cmp(n) < 0 && rndNumZn.Cmp(zero) >= 0 {
			break
		}
	}

	return rndNumZn
}

func Tool_DecimalByteSlice2HexString(DecimalSlice []byte) string {
    var sa = make([]string, 0)
    for _, v := range DecimalSlice {
        sa = append(sa, fmt.Sprintf("%02X", v))
    }
    ss := strings.Join(sa, "")
    return ss
}

// ReadBits encodes the absolute value of bigint as big-endian bytes. Callers must ensure
// that buf has enough space. If buf is too short the result will be incomplete.
func ReadBits(bigint *big.Int, buf []byte) {
	// number of bits in a big.Word
	wordBits := 32 << (uint64(^big.Word(0)) >> 63)
	// number of bytes in a big.Word
	wordBytes := wordBits / 8
	i := len(buf)
	for _, d := range bigint.Bits() {
		for j := 0; j < wordBytes && i > 0; j++ {
			i--
			buf[i] = byte(d)
			d >>= 8
		}
	}
}

func GetSignString(r *big.Int,s *big.Int,v int32,i int) string {
    rr :=  r.Bytes()
    sss :=  s.Bytes()

    //bug
    if len(rr) == 31 && len(sss) == 32 {
	sigs := make([]byte,65)
	sigs[0] = byte(0)
	ReadBits(r,sigs[1:32])
	ReadBits(s,sigs[32:64])
	sigs[64] = byte(i)
	ret := Tool_DecimalByteSlice2HexString(sigs)
	return ret
    }
    if len(rr) == 31 && len(sss) == 31 {
	sigs := make([]byte,65)
	sigs[0] = byte(0)
	sigs[32] = byte(0)
	ReadBits(r,sigs[1:32])
	ReadBits(s,sigs[33:64])
	sigs[64] = byte(i)
	ret := Tool_DecimalByteSlice2HexString(sigs)
	return ret
    }
    if len(rr) == 32 && len(sss) == 31 {
	sigs := make([]byte,65)
	sigs[32] = byte(0)
	ReadBits(r,sigs[0:32])
	ReadBits(s,sigs[33:64])
	sigs[64] = byte(i)
	ret := Tool_DecimalByteSlice2HexString(sigs)
	return ret
    }
    //

    n := len(rr) + len(sss) + 1
    sigs := make([]byte,n)
    ReadBits(r,sigs[0:len(rr)])
    ReadBits(s,sigs[len(rr):len(rr)+len(sss)])

    sigs[len(rr)+len(sss)] = byte(i)
    ret := Tool_DecimalByteSlice2HexString(sigs)

    return ret
}

func Verify(r *big.Int,s *big.Int,v int32,message string,pkx *big.Int,pky *big.Int) bool {
    return Verify2(r,s,v,message,pkx,pky)
}

func GetEnodesByUid(uid *big.Int,cointype string,groupid string) string {
    _,nodes := GetGroup(groupid)
    others := strings.Split(nodes,SepSg)
    for _,v := range others {
	id := DoubleHash(v,cointype)
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

func GetIds(cointype string,groupid string) sortableIDSSlice {
    var ids sortableIDSSlice
    _,nodes := GetGroup(groupid)
    others := strings.Split(nodes,SepSg)
    for _,v := range others {
	uid := DoubleHash(v,cointype)
	ids = append(ids,uid)
    }
    sort.Sort(ids)
    return ids
}
