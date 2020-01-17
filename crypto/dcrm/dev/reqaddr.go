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
    "fmt"
    "bytes"
    "io"
    "time"
    "math/big"
    "github.com/fsn-dev/dcrm-walletService/crypto/secp256k1"
    "github.com/fsn-dev/dcrm-walletService/crypto/dcrm/dev/lib/ec2"
    "strconv"
    "strings"
    "github.com/fsn-dev/dcrm-walletService/crypto/dcrm/dev/lib/ed"
    "github.com/fsn-dev/dcrm-walletService/internal/common"
    "github.com/fsn-dev/dcrm-walletService/coins/types"
    cryptorand "crypto/rand"
    "crypto/sha512"
    "encoding/hex"
    "github.com/fsn-dev/dcrm-walletService/ethdb"
    "github.com/fsn-dev/dcrm-walletService/coins"
    "github.com/astaxie/beego/logs"
)

//ec2
//msgprex = hash 
func dcrm_genPubKey(msgprex string,account string,cointype string,ch chan interface{}, mode string,nonce string) {

    fmt.Println("========dcrm_genPubKey============")

    wk,err := FindWorker(msgprex)
    if err != nil || wk == nil {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:no find worker",Err:err}
	ch <- res
	return
    }
    id := wk.id
    
    GetEnodesInfo(wk.groupid)

    if int32(Enode_cnts) != int32(NodeCnt) {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:group is not ready",Err:GetRetErr(ErrGroupNotReady)}
	ch <- res
	return
    }

    if types.IsDefaultED25519(cointype) {
	ok2 := KeyGenerate_ed(msgprex,ch,id,cointype)
	if ok2 == false {
	    return
	}

	itertmp := workers[id].edpk.Front()
	if itertmp == nil {
	    logs.Debug("get workers[id].edpk fail.")
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get workers[id].edpk fail",Err:GetRetErr(ErrGetGenPubkeyFail)}
	    ch <- res
	    return
	}
	sedpk := []byte(itertmp.Value.(string))

	itertmp = workers[id].edsave.Front()
	if itertmp == nil {
	    logs.Debug("get workers[id].edsave fail.")
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get workers[id].edsave fail",Err:GetRetErr(ErrGetGenSaveDataFail)}
	    ch <- res
	    return
	}
	
	sedsave := itertmp.Value.(string)
	////////
	nodesigs := make([]string,0)
	rk := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype + ":" + wk.groupid + ":" + nonce + ":" + wk.limitnum + ":" + mode))).Hex()
	var da []byte
	datmp,exsit := LdbReqAddr.ReadMap(rk)
	if exsit == false {
	    da2 := GetReqAddrValueFromDb(rk)
	    if da2 == nil {
		exsit = false
	    } else {
		exsit = true
		da = da2
	    }
	} else {
	    da = datmp.([]byte)
	}

	if exsit == true {
	    ds,err := UnCompress(string(da))
	    if err == nil {
		dss,err := Decode2(ds,"AcceptReqAddrData")
		if err == nil {
		    ac := dss.(*AcceptReqAddrData)
		    if ac != nil {
			nodesigs = ac.NodeSigs
		    }
		}
	    }
	}
	////////
	pubs := &PubKeyData{Pub:string(sedpk),Save:sedsave,Nonce:"0",GroupId:wk.groupid,LimitNum:wk.limitnum,Mode:mode,NodeSigs:nodesigs}
	epubs,err := Encode2(pubs)
	if err != nil {
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:encode PubKeyData fail in req ed pubkey",Err:err}
	    ch <- res
	    return
	}
	
	ss,err := Compress([]byte(epubs))
	if err != nil {
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:compress PubKeyData fail in req ed pubkey",Err:err}
	    ch <- res
	    return
	}

	count := AllAccounts.MapLength()
	index := strconv.Itoa(count)
	keytmp := Keccak256Hash([]byte(strings.ToLower(index))).Hex()
	kdtmp := KeyData{Key:[]byte(keytmp),Data:ss}
	AllAccountsChan <-kdtmp
	////TODO
	//AllAccounts = append(AllAccounts,pubs)
	AllAccounts.WriteMap(index,pubs)
	////////

	pubkeyhex := hex.EncodeToString(sedpk)
	fmt.Println("===============dcrm_genPubKey,pubkey = %s,nonce =%s ==================",pubkeyhex,nonce)
	////save to db
	////add for req addr
	key2 := Keccak256Hash([]byte(strings.ToLower(account))).Hex()
	kd := KeyData{Key:[]byte(key2),Data:nonce}
	PubKeyDataChan <-kd

	/////
	//LdbPubKeyData[key2] = []byte(nonce)
	LdbPubKeyData.WriteMap(key2,[]byte(nonce))
	////

	tip,reply := AcceptReqAddr(account,cointype,wk.groupid,nonce,wk.limitnum,mode,true,"true","Success",pubkeyhex,"","","",id)
	if reply != nil {
	    res := RpcDcrmRes{Ret:"",Tip:tip,Err:fmt.Errorf("update req addr status error.")}
	    ch <- res
	    return
	}
    
	if !strings.EqualFold(cointype, "ALL") {
	    h := coins.NewCryptocoinHandler(cointype)
	    if h == nil {
		res := RpcDcrmRes{Ret:"",Tip:"cointype is not supported",Err:fmt.Errorf("req addr fail,cointype is not supported.")}
		ch <- res
		return
	    }

	    ctaddr, err := h.PublicKeyToAddress(pubkeyhex)
	    if err != nil {
		res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get dcrm addr fail from pubkey:"+pubkeyhex,Err:err}
		ch <- res
		return
	    }

	    //add for lockout
	    kd = KeyData{Key:sedpk[:],Data:ss}
	    PubKeyDataChan <-kd
	    /////
	    //LdbPubKeyData[string(sedpk[:])] = []byte(ss)
	    LdbPubKeyData.WriteMap(string(sedpk[:]),[]byte(ss))
	    ////

	    key := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype))).Hex()
	    kd = KeyData{Key:[]byte(key),Data:ss}
	    PubKeyDataChan <-kd
	    /////
	    //LdbPubKeyData[key] = []byte(ss)
	    LdbPubKeyData.WriteMap(key,[]byte(ss))
	    ////

	    key = Keccak256Hash([]byte(strings.ToLower(ctaddr))).Hex()
	    kd = KeyData{Key:[]byte(key),Data:ss}
	    PubKeyDataChan <-kd
	    /////
	    //LdbPubKeyData[key] = []byte(ss)
	    LdbPubKeyData.WriteMap(key,[]byte(ss))
	    ////
	} else {
	    kd = KeyData{Key:sedpk[:],Data:ss}
	    PubKeyDataChan <-kd
	    /////
	    //LdbPubKeyData[string(sedpk[:])] = []byte(ss)
	    LdbPubKeyData.WriteMap(string(sedpk[:]),[]byte(ss))
	    ////

	    key := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype))).Hex()
	    kd = KeyData{Key:[]byte(key),Data:ss}
	    PubKeyDataChan <-kd
	    /////
	    //LdbPubKeyData[key] = []byte(ss)
	    LdbPubKeyData.WriteMap(key,[]byte(ss))
	    ////

	    for _, ct := range coins.Cointypes {
		if strings.EqualFold(ct, "ALL") {
		    continue
		}

		h := coins.NewCryptocoinHandler(ct)
		if h == nil {
		    continue
		}
		ctaddr, err := h.PublicKeyToAddress(pubkeyhex)
		if err != nil {
		    continue
		}
		
		key = Keccak256Hash([]byte(strings.ToLower(ctaddr))).Hex()
		kd = KeyData{Key:[]byte(key),Data:ss}
		PubKeyDataChan <-kd
		/////
		//LdbPubKeyData[key] = []byte(ss)
		LdbPubKeyData.WriteMap(key,[]byte(ss))
		////
	    }
	}

	res := RpcDcrmRes{Ret:pubkeyhex,Tip:"",Err:nil}
	ch <- res
	return
    }
    
    ok := KeyGenerate_DECDSA(msgprex,ch,id,cointype)
    if ok == false {
	return
    }

    iter := workers[id].pkx.Front()
    if iter == nil {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get pkx fail in req ec2 pubkey",Err:GetRetErr(ErrGetGenPubkeyFail)}
	ch <- res
	return
    }
    spkx := iter.Value.(string)
    pkx := new(big.Int).SetBytes([]byte(spkx))
    iter = workers[id].pky.Front()
    if iter == nil {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get pky fail in req ec2 pubkey",Err:GetRetErr(ErrGetGenPubkeyFail)}
	ch <- res
	return
    }
    spky := iter.Value.(string)
    pky := new(big.Int).SetBytes([]byte(spky))
    ys := secp256k1.S256().Marshal(pkx,pky)

    iter = workers[id].save.Front()
    if iter == nil {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get save data fail in req ec2 pubkey",Err:GetRetErr(ErrGetGenSaveDataFail)}
	ch <- res
	return
    }
    save := iter.Value.(string)
    ////////
    nodesigs := make([]string,0)
    rk := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype + ":" + wk.groupid + ":" + nonce + ":" + wk.limitnum + ":" + mode))).Hex()
    var da []byte
    datmp,exsit := LdbReqAddr.ReadMap(rk)
    if exsit == false {
	da2 := GetReqAddrValueFromDb(rk)
	if da2 == nil {
	    exsit = false
	} else {
	    exsit = true
	    da = da2
	}
    } else {
	da = datmp.([]byte)
    }

    if exsit == true {
	ds,err := UnCompress(string(da))
	if err == nil {
	    dss,err := Decode2(ds,"AcceptReqAddrData")
	    if err == nil {
		ac := dss.(*AcceptReqAddrData)
		if ac != nil {
		    nodesigs = ac.NodeSigs
		}
	    }
	}
    }
    ////////
    pubs := &PubKeyData{Pub:string(ys),Save:save,Nonce:"0",GroupId:wk.groupid,LimitNum:wk.limitnum,Mode:mode,NodeSigs:nodesigs}
    epubs,err := Encode2(pubs)
    if err != nil {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:encode PubKeyData fail in req ec2 pubkey",Err:err}
	ch <- res
	return
    }
    
    ss,err := Compress([]byte(epubs))
    if err != nil {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:compress PubKeyData fail in req ec2 pubkey",Err:err}
	ch <- res
	return
    }
   
    count := AllAccounts.MapLength()
    index := strconv.Itoa(count)
    keytmp := Keccak256Hash([]byte(strings.ToLower(index))).Hex()
    kdtmp := KeyData{Key:[]byte(keytmp),Data:ss}
    AllAccountsChan <-kdtmp
    ////TODO
    //AllAccounts = append(AllAccounts,pubs)
    AllAccounts.WriteMap(index,pubs)
    ////////

    pubkeyhex := hex.EncodeToString(ys)
    fmt.Println("===============dcrm_genPubKey,pubkey = %s,nonce =%s ==================",pubkeyhex,nonce)
    
    key2 := Keccak256Hash([]byte(strings.ToLower(account))).Hex()
    kd := KeyData{Key:[]byte(key2),Data:nonce}
    PubKeyDataChan <-kd
    /////
    //LdbPubKeyData[key2] = []byte(nonce)
    LdbPubKeyData.WriteMap(key2,[]byte(nonce))
    ////

    tip,reply := AcceptReqAddr(account,cointype,wk.groupid,nonce,wk.limitnum,mode,true,"true","Success",pubkeyhex,"","","",id)
    if reply != nil {
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:fmt.Errorf("update req addr status error.")}
	ch <- res
	return
    }

    if !strings.EqualFold(cointype, "ALL") {
	h := coins.NewCryptocoinHandler(cointype)
	if h == nil {
	    res := RpcDcrmRes{Ret:"",Tip:"cointype is not supported",Err:fmt.Errorf("req addr fail,cointype is not supported.")}
	    ch <- res
	    return
	}

	ctaddr, err := h.PublicKeyToAddress(pubkeyhex)
	if err != nil {
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get dcrm addr fail from pubkey:"+pubkeyhex,Err:err}
	    ch <- res
	    return
	}
	
	kd = KeyData{Key:ys,Data:ss}
	PubKeyDataChan <-kd
	/////
	//LdbPubKeyData[string(ys)] = []byte(ss)
	LdbPubKeyData.WriteMap(string(ys),[]byte(ss))
	////

	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype))).Hex()
	kd = KeyData{Key:[]byte(key),Data:ss}
	PubKeyDataChan <-kd
	/////
	//LdbPubKeyData[key] = []byte(ss)
	LdbPubKeyData.WriteMap(key,[]byte(ss))
	////

	key = Keccak256Hash([]byte(strings.ToLower(ctaddr))).Hex()
	kd = KeyData{Key:[]byte(key),Data:ss}
	PubKeyDataChan <-kd
	/////
	//LdbPubKeyData[key] = []byte(ss)
	LdbPubKeyData.WriteMap(key,[]byte(ss))
	////
    } else {
	kd = KeyData{Key:ys,Data:ss}
	PubKeyDataChan <-kd
	/////
	//LdbPubKeyData[string(ys)] = []byte(ss)
	LdbPubKeyData.WriteMap(string(ys),[]byte(ss))
	////

	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype))).Hex()
	kd = KeyData{Key:[]byte(key),Data:ss}
	PubKeyDataChan <-kd
	/////
	//LdbPubKeyData[key] = []byte(ss)
	LdbPubKeyData.WriteMap(key,[]byte(ss))
	////

	for _, ct := range coins.Cointypes {
	    if strings.EqualFold(ct, "ALL") {
		continue
	    }

	    h := coins.NewCryptocoinHandler(ct)
	    if h == nil {
		continue
	    }
	    ctaddr, err := h.PublicKeyToAddress(pubkeyhex)
	    if err != nil {
		continue
	    }
	    
	    key = Keccak256Hash([]byte(strings.ToLower(ctaddr))).Hex()
	    kd = KeyData{Key:[]byte(key),Data:ss}
	    PubKeyDataChan <-kd
	    /////
	    //LdbPubKeyData[key] = []byte(ss)
	    LdbPubKeyData.WriteMap(key,[]byte(ss))
	    ////
	}
    }
    
    res := RpcDcrmRes{Ret:pubkeyhex,Tip:"",Err:nil}
    ch <- res
}

type KeyData struct {
    Key []byte
    Data string
}

func SavePubKeyDataToDb() {
    for {
	select {
	    case kd := <-PubKeyDataChan:
		dir := GetDbDir()
		db,err := ethdb.NewLDBDatabase(dir, 0, 0)
		//bug
		if err != nil {
		    for i:=0;i<100;i++ {
			db,err = ethdb.NewLDBDatabase(dir, 0, 0)
			if err == nil && db != nil {
			    break
			}
			
			time.Sleep(time.Duration(1000000))
		    }
		}
		//
		if db != nil {
		    db.Put(kd.Key,[]byte(kd.Data))
		    db.Close()
		} else {
		    PubKeyDataChan <-kd
		}
		
		time.Sleep(time.Duration(1000000))  //na, 1 s = 10e9 na
	}
    }
}

func SaveAllAccountsToDb() {
    for {
	select {
	    case kd := <-AllAccountsChan:
		dir := GetAllAccountsDir()
		db,err := ethdb.NewLDBDatabase(dir, 0, 0)
		//bug
		if err != nil {
		    for i:=0;i<100;i++ {
			db,err = ethdb.NewLDBDatabase(dir, 0, 0)
			if err == nil && db != nil {
			    break
			}
			
			time.Sleep(time.Duration(1000000))
		    }
		}
		//
		if db != nil {
		    db.Put(kd.Key,[]byte(kd.Data))
		    db.Close()
		} else {
		    AllAccountsChan <-kd
		}
		
		time.Sleep(time.Duration(1000000))  //na, 1 s = 10e9 na
	}
    }
}

func SaveReqAddrToDb() {
    for {
	select {
	    case kd := <-ReqAddrChan:
		dir := GetAcceptReqAddrDir()
		db,err := ethdb.NewLDBDatabase(dir, 0, 0)
		//bug
		if err != nil {
		    for i:=0;i<100;i++ {
			db,err = ethdb.NewLDBDatabase(dir, 0, 0)
			if err == nil && db != nil {
			    break
			}
			
			time.Sleep(time.Duration(1000000))
		    }
		}
		//
		if db != nil {
		    db.Put(kd.Key,[]byte(kd.Data))
		    db.Close()
		} else {
		    ReqAddrChan <-kd
		}
		
		time.Sleep(time.Duration(1000000))  //na, 1 s = 10e9 na
	}
    }
}

func SaveLockOutToDb() {
    for {
	select {
	    case kd := <-LockOutChan:
		dir := GetAcceptLockOutDir()
		db,err := ethdb.NewLDBDatabase(dir, 0, 0)
		//bug
		if err != nil {
		    for i:=0;i<100;i++ {
			db,err = ethdb.NewLDBDatabase(dir, 0, 0)
			if err == nil && db != nil {
			    break
			}
			
			time.Sleep(time.Duration(1000000))
		    }
		}
		//
		if db != nil {
		    db.Put(kd.Key,[]byte(kd.Data))
		    db.Close()
		} else {
		    LockOutChan <-kd
		}
		
		time.Sleep(time.Duration(1000000))  //na, 1 s = 10e9 na
	}
    }
}

func GetReqAddrValueFromDb(key string) []byte {
    lock.Lock()
    dir := GetAcceptReqAddrDir()
    ////////
    db,err := ethdb.NewLDBDatabase(dir, 0, 0)
    //bug
    if err != nil {
	for i:=0;i<100;i++ {
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
	return nil 
    }
    
    da,err := db.Get([]byte(key))
    ///////
    if err != nil {
	db.Close()
	lock.Unlock()
	return nil
    }

    db.Close()
    lock.Unlock()
    return da
}

func GetLockOutValueFromDb(key string) []byte {
    lock5.Lock()
    dir := GetAcceptLockOutDir()
    ////////
    db,err := ethdb.NewLDBDatabase(dir, 0, 0)
    //bug
    if err != nil {
	for i:=0;i<100;i++ {
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
	return nil 
    }
    
    da,err := db.Get([]byte(key))
    ///////
    if err != nil {
	db.Close()
	lock5.Unlock()
	return nil
    }

    db.Close()
    lock5.Unlock()
    return da
}

func GetAllPubKeyDataFromDb() *common.SafeMap {
    kd := common.NewSafeMap(10)
    fmt.Println("==============GetAllPubKeyDataFromDb,start read from db===============")
    dir := GetAllAccountsDir()
    db,err := ethdb.NewLDBDatabase(dir, 0, 0)
    //bug
    if err != nil {
	for i:=0;i<100;i++ {
	    db,err = ethdb.NewLDBDatabase(dir, 0, 0)
	    if err == nil && db != nil {
		break
	    }
	    
	    time.Sleep(time.Duration(1000000))
	}
    }
    //
    if db != nil {
	fmt.Println("==============GetAllPubKeyDataFromDb,open db success===============")
	index := 0
	iter := db.NewIterator() 
	for iter.Next() {
	    value := string(iter.Value())
	    ss,err := UnCompress(value)
	    if err != nil {
		fmt.Println("==============GetAllPubKeyDataFromDb,1111 err = %v===============",err)
		continue
	    }
	    
	    pubs,err := Decode2(ss,"PubKeyData")
	    if err != nil {
		fmt.Println("==============GetAllPubKeyDataFromDb,2222 err = %v===============",err)
		continue
	    }
	    
	    pd := pubs.(*PubKeyData)
	    if pd == nil {
		continue
	    }

	    ind := strconv.Itoa(index)
	    kd.WriteMap(ind,pd)
	    index++
	}
	iter.Release()
	db.Close()
    }

    return kd
}

func GetAllPendingReqAddrFromDb() *common.SafeMap {
    kd := common.NewSafeMap(10) 
    fmt.Println("==============GetAllPendingReqAddrFromDb,start read from db===============")
    dir := GetAcceptReqAddrDir()
    db,err := ethdb.NewLDBDatabase(dir, 0, 0)
    //bug
    if err != nil {
	for i:=0;i<100;i++ {
	    db,err = ethdb.NewLDBDatabase(dir, 0, 0)
	    if err == nil && db != nil {
		break
	    }
	    
	    time.Sleep(time.Duration(1000000))
	}
    }
    //
    if db != nil {
	fmt.Println("==============GetAllPendingReqAddrFromDb,open db success===============")
	iter := db.NewIterator() 
	for iter.Next() {
	    key := string(iter.Key())
	    value := string(iter.Value())
	    ss,err := UnCompress(value)
	    if err != nil {
		fmt.Println("==============GetAllPendingReqAddrFromDb,1111 err = %v===============",err)
		continue
	    }
	    
	    pubs,err := Decode2(ss,"AcceptReqAddrData")
	    if err != nil {
		fmt.Println("==============GetAllPendingReqAddrFromDb,2222 err = %v===============",err)
		continue
	    }
	    
	    pd := pubs.(*AcceptReqAddrData)
	    if pd == nil {
		continue
	    }

	    if pd.Deal == true || pd.Status == "Success" {
		continue
	    }

	    if pd.Status != "Pending" {
		continue
	    }

	    //kd[key] = iter.Value()
	    kd.WriteMap(key,iter.Value())
	}
	iter.Release()
	db.Close()
    }

    return kd
}

func GetAllPendingLockOutFromDb() *common.SafeMap {
    kd := common.NewSafeMap(10)
    fmt.Println("==============GetAllPendingLockOutFromDb,start read from db===============")
    dir := GetAcceptLockOutDir()
    db,err := ethdb.NewLDBDatabase(dir, 0, 0)
    //bug
    if err != nil {
	for i:=0;i<100;i++ {
	    db,err = ethdb.NewLDBDatabase(dir, 0, 0)
	    if err == nil && db != nil {
		break
	    }
	    
	    time.Sleep(time.Duration(1000000))
	}
    }
    //
    if db != nil {
	fmt.Println("==============GetAllPendingLockOutFromDb,open db success===============")
	iter := db.NewIterator() 
	for iter.Next() {
	    key := string(iter.Key())
	    value := string(iter.Value())
	    ss,err := UnCompress(value)
	    if err != nil {
		fmt.Println("==============GetAllPendingLockOutFromDb,1111 err = %v===============",err)
		continue
	    }
	    
	    pubs,err := Decode2(ss,"AcceptLockOutData")
	    if err != nil {
		fmt.Println("==============GetAllPendingLockOutFromDb,2222 err = %v===============",err)
		continue
	    }
	    
	    pd := pubs.(*AcceptLockOutData)
	    if pd == nil {
		continue
	    }

	    if pd.Deal == true || pd.Status == "Success" {
		continue
	    }

	    if pd.Status != "Pending" {
		continue
	    }

	    //kd[key] = iter.Value()
	    kd.WriteMap(key,iter.Value())
	}
	iter.Release()
	db.Close()
    }

    return kd
}

//ed
//msgprex = hash
func KeyGenerate_ed(msgprex string,ch chan interface{},id int,cointype string) bool {
    if id < 0 || id >= RpcMaxWorker || id >= len(workers) {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:no find worker id",Err:GetRetErr(ErrGetWorkerIdError)}
	ch <- res
	return false
    }

    w := workers[id]
    GroupId := w.groupid 
    fmt.Println("========KeyGenerate_ed============","GroupId",GroupId)
    if GroupId == "" {
	res := RpcDcrmRes{Ret:"",Tip:"get group id fail",Err:fmt.Errorf("get group id fail.")}
	ch <- res
	return false
    }
    
    ns,_ := GetGroup(GroupId)
    if ns != NodeCnt {
	logs.Debug("KeyGenerate_ed,get nodes info error.")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:the group is not ready",Err:GetRetErr(ErrGroupNotReady)}
	ch <- res
	return false 
    }
		
    rand := cryptorand.Reader
    var seed [32]byte

    if _, err := io.ReadFull(rand, seed[:]); err != nil {
	    fmt.Println("Error: io.ReadFull(rand, seed)")
    }

    // 1.2 privateKey' = SHA512(seed)
    var sk [64]byte
    var pk [32]byte

    seedDigest := sha512.Sum512(seed[:])

    seedDigest[0] &= 248
    seedDigest[31] &= 127
    seedDigest[31] |= 64

    copy(sk[:], seedDigest[:])

    // 1.3 publicKey
    var temSk [32]byte
    copy(temSk[:], sk[:32])

    var A ed.ExtendedGroupElement
    ed.GeScalarMultBase(&A, &temSk)

    A.ToBytes(&pk)

    CPk, DPk := ed.Commit(pk)
    zkPk := ed.Prove(temSk)
    
    ids := GetIds(cointype,GroupId)
    
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "EDC11"
    s1 := string(CPk[:])
    ss := enode + common.Sep + s0 + common.Sep + s1
    logs.Debug("================kg ed round one,send msg,code is EDC11==================")
    SendMsgToDcrmGroup(ss,GroupId)
    
    _,tip,cherr := GetChannelValue(ch_t,w.bedc11)
    if cherr != nil {
	logs.Debug("get w.bedc11 timeout.")
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:fmt.Errorf("get ed c11 timeout.")}
	ch <- res
	return false 
    }

    if w.msg_edc11.Len() != (NodeCnt-1) {
	logs.Debug("get w.msg_edc11 fail.")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get all msg_edc11 fail",Err:fmt.Errorf("get all ed c11 fail.")}
	ch <- res
	return false
    }
    var cpks = make(map[string][32]byte)
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	if IsCurNode(enodes,cur_enode) {
	    cpks[cur_enode] = CPk 
	    continue
	}

	en := strings.Split(string(enodes[8:]),"@")
	
	iter := w.msg_edc11.Front()
	for iter != nil {
	    data := iter.Value.(string)
	    m := strings.Split(data,common.Sep)
	    ps := strings.Split(m[0],"-")
	    if strings.EqualFold(ps[1],en[0]) {
		var t [32]byte
		va := []byte(m[2])
		copy(t[:], va[:32])
		cpks[en[0]] = t
		break
	    }
	    iter = iter.Next()
	}
    }

    s0 = "EDZK"
    s1 = string(zkPk[:])
    ss = enode + common.Sep + s0 + common.Sep + s1
    logs.Debug("================kg ed round one,send msg,code is EDZK==================")
    SendMsgToDcrmGroup(ss,GroupId)
    
    _,tip,cherr = GetChannelValue(ch_t,w.bedzk)
    if cherr != nil {
	logs.Debug("get w.bedzk timeout.")
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:fmt.Errorf("get ed zk timeout.")}
	ch <- res
	return false 
    }

    if w.msg_edzk.Len() != (NodeCnt-1) {
	logs.Debug("get w.msg_edzk fail.")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get w.msg_edzk fail",Err:fmt.Errorf("get all ed zk fail.")}
	ch <- res
	return false
    }

    var zks = make(map[string][64]byte)
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	if IsCurNode(enodes,cur_enode) {
	    zks[cur_enode] = zkPk
	    continue
	}

	en := strings.Split(string(enodes[8:]),"@")
	
	iter := w.msg_edzk.Front()
	for iter != nil {
	    data := iter.Value.(string)
	    m := strings.Split(data,common.Sep)
	    ps := strings.Split(m[0],"-")
	    if strings.EqualFold(ps[1],en[0]) {
		var t [64]byte
		va := []byte(m[2])
		copy(t[:], va[:64])
		zks[en[0]] = t
		break
	    }
	    iter = iter.Next()
	}
    }

    s0 = "EDD11"
    s1 = string(DPk[:])
    ss = enode + common.Sep + s0 + common.Sep + s1
    logs.Debug("================kg ed round one,send msg,code is EDD11==================")
    SendMsgToDcrmGroup(ss,GroupId)
    
    _,tip,cherr = GetChannelValue(ch_t,w.bedd11)
    if cherr != nil {
	logs.Debug("get w.bedd11 timeout.")
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:fmt.Errorf("get ed d11 timeout.")}
	ch <- res
	return false 
    }

    if w.msg_edd11.Len() != (NodeCnt-1) {
	logs.Debug("get w.msg_edd11 fail.")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get msg_edd11 fail",Err:fmt.Errorf("get all ed d11 fail.")}
	ch <- res
	return false
    }
    var dpks = make(map[string][64]byte)
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	if IsCurNode(enodes,cur_enode) {
	    dpks[cur_enode] = DPk
	    continue
	}

	en := strings.Split(string(enodes[8:]),"@")
	
	iter := w.msg_edd11.Front()
	for iter != nil {
	    data := iter.Value.(string)
	    m := strings.Split(data,common.Sep)
	    ps := strings.Split(m[0],"-")
	    if strings.EqualFold(ps[1],en[0]) {
		var t [64]byte
		va := []byte(m[2])
		copy(t[:], va[:64])
		dpks[en[0]] = t
		break
	    }
	    iter = iter.Next()
	}
    }

    //1.4
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

    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	CPkFlag := ed.Verify(cpks[en[0]],dpks[en[0]])
	if !CPkFlag {
	    fmt.Println("Error: Commitment(PK) Not Pass at User: %s",en[0])
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:commitment check fail in req ed pubkey",Err:fmt.Errorf("Commitment(PK) Not Pass at User.")}
	    ch <- res
	    return false
	}
    }

    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	dpk := dpks[en[0]]
	var t [32]byte
	copy(t[:], dpk[32:])
	zkPkFlag := ed.Verify_zk(zks[en[0]], t)
	if !zkPkFlag {
		fmt.Println("Error: ZeroKnowledge Proof (Pk) Not Pass at User: %s", en[0])
		res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:zeroknowledge check fail",Err:fmt.Errorf("ZeroKnowledge Proof (Pk) Not Pass.")}
		ch <- res
		return false
	}
    }

    // 2.5 calculate a = SHA256(PkU1, {PkU2, PkU3})
    var a [32]byte
    var aDigest [64]byte
    var PkSet []byte

    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	dpk := dpks[en[0]]
	PkSet = append(PkSet[:], (dpk[32:])...)
    }
    h := sha512.New()
    dpk := dpks[cur_enode]
    h.Write(dpk[32:])
    h.Write(PkSet)
    h.Sum(aDigest[:0])
    ed.ScReduce(&a, &aDigest)

    // 2.6 calculate ask
    var ask [32]byte
    var temSk2 [32]byte
    copy(temSk2[:], sk[:32])
    ed.ScMul(&ask, &a, &temSk2)
    
    // 2.7 calculate vss
    /*var inputid [][32]byte
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype)
	en := strings.Split(string(enodes[8:]),"@")
	id := []byte(uids[en[0]])
	inputid = append(inputid,id[:])
    }*/

    _, cfsBBytes, shares := ed.Vss2(ask,ThresHold, NodeCnt,uids)

    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)

	if enodes == "" {
	    logs.Debug("=========KeyGenerate_ed,don't find proper enodes========")
	    res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get enode by uid fail",Err:GetRetErr(ErrGetEnodeByUIdFail)}
	    ch <- res
	    return false
	}
	
	if IsCurNode(enodes,cur_enode) {
	    continue
	}

	en := strings.Split(string(enodes[8:]),"@")
	for k,v := range shares {
	    if strings.EqualFold(k,en[0]) {
		s0 := "EDSHARE1"
		s1 := string(v[:])
		ss := enode + common.Sep + s0 + common.Sep + s1
		logs.Debug("================kg ed round two,send msg,code is EDSHARE1==================")
		SendMsgToPeer(enodes,ss)
		break
	    }
	}
    }

    _,tip,cherr = GetChannelValue(ch_t,w.bedshare1)
    if cherr != nil {
	logs.Debug("get w.bedshare1 timeout in keygenerate.")
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:fmt.Errorf("get ed share1 fail.")}
	ch <- res
	return false 
    }
    logs.Debug("================kg ed round two,receiv msg,code is EDSHARE1.==================")

    if w.msg_edshare1.Len() != (NodeCnt-1) {
	logs.Debug("get w.msg_edshare1 fail.")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get all msg_edshare1 fail",Err:fmt.Errorf("get all ed share1 fail.")}
	ch <- res
	return false
    }

    var edshares = make(map[string][32]byte)
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	if IsCurNode(enodes,cur_enode) {
	    edshares[cur_enode] = shares[cur_enode]
	    continue
	}

	en := strings.Split(string(enodes[8:]),"@")
	
	iter := w.msg_edshare1.Front()
	for iter != nil {
	    data := iter.Value.(string)
	    m := strings.Split(data,common.Sep)
	    ps := strings.Split(m[0],"-")
	    if strings.EqualFold(ps[1],en[0]) {
		var t [32]byte
		va := []byte(m[2]) 
		copy(t[:], va[:32])
		edshares[en[0]] = t
		break
	    }
	    iter = iter.Next()
	}
    }

    s0 = "EDCFSB"
    ss = enode + common.Sep + s0 + common.Sep
    for _,v := range cfsBBytes {
	vv := string(v[:])
	ss = ss + vv + common.Sep
    }
    ss = ss + "NULL"

    logs.Debug("================kg ed round two,send msg,code is EDCFSB==================")
    SendMsgToDcrmGroup(ss,GroupId)

     _,tip,cherr = GetChannelValue(ch_t,w.bedcfsb)
    if cherr != nil {
	logs.Debug("get w.bedcfsb timeout.")
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:fmt.Errorf("get ed cfsb timeout.")}
	ch <- res
	return false 
    }

    if w.msg_edcfsb.Len() != (NodeCnt-1) {
	logs.Debug("get w.msg_edcfsb fail.")
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get all msg_edcfsb fail",Err:fmt.Errorf("get all ed cfsb fail.")}
	ch <- res
	return false
    }
    var cfsbs = make(map[string][][32]byte)
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	if IsCurNode(enodes,cur_enode) {
	    cfsbs[cur_enode] = cfsBBytes
	    continue
	}

	en := strings.Split(string(enodes[8:]),"@")
	
	iter := w.msg_edcfsb.Front()
	for iter != nil {
	    data := iter.Value.(string)
	    m := strings.Split(data,common.Sep)
	    ps := strings.Split(m[0],"-")
	    if strings.EqualFold(ps[1],en[0]) {
		mm := m[2:]
		var cfs [][32]byte
		for _,tmp := range mm {
		    if tmp == "NULL" {
			break
		    }
		    var t [32]byte
		    va := []byte(tmp)
		    copy(t[:], va[:32])
		    cfs = append(cfs,t)
		}
		cfsbs[en[0]] = cfs
		break
	    }
	    iter = iter.Next()
	}
    }

    // 3.1 verify share
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	
	shareUFlag := ed.Verify_vss(edshares[en[0]],uids[cur_enode],cfsbs[en[0]])

	if !shareUFlag {
		fmt.Println("Error: VSS Share Verification Not Pass at User: %s",en[0])
		res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:VSS Share verification fail",Err:fmt.Errorf("VSS Share Verification Not Pass.")}
		ch <- res
		return false
	}
    }

    // 3.2 verify share2
    var a2 [32]byte
    var aDigest2 [64]byte

    var PkSet2 []byte
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	var temPk [32]byte
	t := dpks[en[0]]
	copy(temPk[:], t[32:])
	PkSet2 = append(PkSet2[:], (temPk[:])...)
    }
    
    h = sha512.New()
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	var temPk [32]byte
	t := dpks[en[0]]
	copy(temPk[:], t[32:])

	h.Reset()
	h.Write(temPk[:])
	h.Write(PkSet2)
	h.Sum(aDigest2[:0])
	ed.ScReduce(&a2, &aDigest2)

	var askB, A ed.ExtendedGroupElement
	A.FromBytes(&temPk)
	ed.GeScalarMult(&askB, &a2, &A)

	var askBBytes [32]byte
	askB.ToBytes(&askBBytes)

	t2 := cfsbs[en[0]]
	tt := t2[0]
	if !bytes.Equal(askBBytes[:], tt[:]) {
		fmt.Println("Error: VSS Coefficient Verification Not Pass at User: %s",en[0])
		res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:VSS Coefficient verification fail",Err:fmt.Errorf("VSS Coefficient Verification Not Pass.")}
		ch <- res
		return false
	}
    }

    // 3.3 calculate tSk
    var tSk [32]byte
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	t := edshares[en[0]]
	ed.ScAdd(&tSk, &tSk, &t)
    }

    // 3.4 calculate pk
    var finalPk ed.ExtendedGroupElement
    var finalPkBytes [32]byte

    i := 0
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	var temPk [32]byte
	t := dpks[en[0]]
	copy(temPk[:], t[32:])

	h.Reset()
	h.Write(temPk[:])
	h.Write(PkSet2)
	h.Sum(aDigest2[:0])
	ed.ScReduce(&a2, &aDigest2)

	var askB, A ed.ExtendedGroupElement
	A.FromBytes(&temPk)
	ed.GeScalarMult(&askB, &a2, &A)

	if i == 0 {
		finalPk = askB
	} else {
		ed.GeAdd(&finalPk, &finalPk, &askB)
	}

	i++
    }
    
    finalPk.ToBytes(&finalPkBytes)

    //save the local db
    //sk:pk:tsk:pkfinal
    save := string(sk[:]) + common.Sep11 + string(pk[:]) + common.Sep11 + string(tSk[:]) + common.Sep11 + string(finalPkBytes[:])
    
    w.edsave.PushBack(save)
    w.edpk.PushBack(string(finalPkBytes[:]))

    return true
}

func DECDSAGenKeyRoundOne(msgprex string,ch chan interface{},w *RpcReqWorker) (*big.Int,*ec2.PolyStruct2, *ec2.PolyGStruct2,*ec2.Commitment,*ec2.PublicKey, *ec2.PrivateKey,bool) {
    if w == nil || msgprex == "" {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("no find worker.")}
	ch <- res
	return nil,nil,nil,nil,nil,nil,false
    }

    u1,u1Poly,u1PolyG,commitU1G,u1PaillierPk, u1PaillierSk := DECDSA_Key_RoundOne(ThresHold,PaillierKeyLength)
    if u1PaillierPk == nil || u1PaillierSk == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("gen paillier key pair fail")}
	ch <- res
	return nil,nil,nil,nil,nil,nil,false
    }

    // 4. Broadcast
    // commitU1G.C, commitU2G.C, commitU3G.C, commitU4G.C, commitU5G.C
    // u1PaillierPk, u2PaillierPk, u3PaillierPk, u4PaillierPk, u5PaillierPk
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "C1"
    s1 := string(commitU1G.C.Bytes())
    s2 := u1PaillierPk.Length
    s3 := string(u1PaillierPk.N.Bytes()) 
    s4 := string(u1PaillierPk.G.Bytes()) 
    s5 := string(u1PaillierPk.N2.Bytes()) 
    ss := enode + Sep + s0 + Sep + s1 + Sep + s2 + Sep + s3 + Sep + s4 + Sep + s5
    SendMsgToDcrmGroup(ss,w.groupid)

    // 1. Receive Broadcast
    // commitU1G.C, commitU2G.C, commitU3G.C, commitU4G.C, commitU5G.C
    // u1PaillierPk, u2PaillierPk, u3PaillierPk, u4PaillierPk, u5PaillierPk
     _,tip,cherr := GetChannelValue(ch_t,w.bc1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:GetRetErr(ErrGetC1Timeout)}
	ch <- res
	return nil,nil,nil,nil,nil,nil,false
    }

    return u1,u1Poly,u1PolyG,commitU1G,u1PaillierPk, u1PaillierSk,true
}

func DECDSAGenKeyRoundTwo(msgprex string,cointype string,ch chan interface{},w *RpcReqWorker,u1Poly *ec2.PolyStruct2,ids sortableIDSSlice) ([]*ec2.ShareStruct2,bool) {
    if w == nil || cointype == "" || msgprex == "" || u1Poly == nil || len(ids) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil,false
    }
    
    // 2. generate their vss to get shares which is a set
    // [notes]
    // all nodes has their own id, in practival, we can take it as double hash of public key of fusion

    u1Shares,err := DECDSA_Key_Vss(u1Poly,ids)
    if err != nil {
	res := RpcDcrmRes{Ret:"",Err:err}
	ch <- res
	return nil,false 
    }

    // 3. send the the proper share to proper node 
    //example for u1:
    // Send u1Shares[0] to u1
    // Send u1Shares[1] to u2
    // Send u1Shares[2] to u3
    // Send u1Shares[3] to u4
    // Send u1Shares[4] to u5
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,w.groupid)

	if enodes == "" {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetEnodeByUIdFail)}
	    ch <- res
	    return nil,false
	}
	
	if IsCurNode(enodes,cur_enode) {
	    continue
	}

	for _,v := range u1Shares {
	    uid := DECDSA_Key_GetSharesId(v)
	    if uid != nil && uid.Cmp(id) == 0 {
		mp := []string{msgprex,cur_enode}
		enode := strings.Join(mp,"-")
		s0 := "SHARE1"
		s2 := string(v.Id.Bytes()) 
		s3 := string(v.Share.Bytes()) 
		ss := enode + Sep + s0 + Sep + s2 + Sep + s3
		SendMsgToPeer(enodes,ss)
		break
	    }
	}
    }

    return u1Shares,true
}

func DECDSAGenKeyRoundThree(msgprex string,cointype string,ch chan interface{},w *RpcReqWorker,u1PolyG *ec2.PolyGStruct2,commitU1G *ec2.Commitment,ids sortableIDSSlice) bool {
    if w == nil || cointype == "" || msgprex == "" || u1PolyG == nil || len(ids) == 0 || commitU1G == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return false
    }
    
    // 4. Broadcast
    // commitU1G.D, commitU2G.D, commitU3G.D, commitU4G.D, commitU5G.D
    // u1PolyG, u2PolyG, u3PolyG, u4PolyG, u5PolyG
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "D1"
    dlen := len(commitU1G.D)
    s1 := strconv.Itoa(dlen)

    ss := enode + Sep + s0 + Sep + s1 + Sep
    for _,d := range commitU1G.D {
	ss += string(d.Bytes())
	ss += Sep
    }

    pglen := 2*(len(u1PolyG.PolyG))
    s4 := strconv.Itoa(pglen)

    ss = ss + s4 + Sep

    for _,p := range u1PolyG.PolyG {
	for _,d := range p {
	    ss += string(d.Bytes())
	    ss += Sep
	}
    }
    ss = ss + "NULL"
    SendMsgToDcrmGroup(ss,w.groupid)
    
    // 1. Receive Broadcast
    // commitU1G.D, commitU2G.D, commitU3G.D, commitU4G.D, commitU5G.D
    // u1PolyG, u2PolyG, u3PolyG, u4PolyG, u5PolyG
    _,tip,cherr := GetChannelValue(ch_t,w.bd1_1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:GetRetErr(ErrGetD1Timeout)}
	ch <- res
	return false 
    }

    return true
}

func DECDSAGenKeyVerifyShareData(msgprex string,cointype string,ch chan interface{},w *RpcReqWorker,u1PolyG *ec2.PolyGStruct2,u1Shares []*ec2.ShareStruct2,ids sortableIDSSlice) (map[string]*ec2.ShareStruct2,[]string,bool) {
    if w == nil || cointype == "" || msgprex == "" || u1PolyG == nil || len(ids) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil,nil,false
    }
 
    // 2. Receive Personal Data
    _,tip,cherr := GetChannelValue(ch_t,w.bshare1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:GetRetErr(ErrGetSHARE1Timeout)}
	ch <- res
	return nil,nil,false
    }

    var sstruct = make(map[string]*ec2.ShareStruct2)
    shares := make([]string,NodeCnt-1)
    if w.msg_share1.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllSHARE1Fail)}
	ch <- res
	return nil,nil,false
    }

    itmp := 0
    iter := w.msg_share1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	shares[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }
    
    for _,v := range shares {
	mm := strings.Split(v, Sep)
	//bug
	if len(mm) < 4 {
	    fmt.Println("===================!!! KeyGenerate_ECDSA,fill ec2.ShareStruct map error. !!!,Nonce =%s ==================",msgprex)
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("fill ec2.ShareStruct map error.")}
	    ch <- res
	    return nil,nil,false
	}
	//
	ushare := &ec2.ShareStruct2{Id:new(big.Int).SetBytes([]byte(mm[2])),Share:new(big.Int).SetBytes([]byte(mm[3]))}
	prex := mm[0]
	prexs := strings.Split(prex,"-")
	sstruct[prexs[len(prexs)-1]] = ushare
    }

    for _,v := range u1Shares {
	uid := DECDSA_Key_GetSharesId(v)
	if uid == nil {
	    continue
	}

	enodes := GetEnodesByUid(uid,cointype,w.groupid)
	if IsCurNode(enodes,cur_enode) {
	    sstruct[cur_enode] = v 
	    break
	}
    }

    ds := make([]string,NodeCnt-1)
    if w.msg_d1_1.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllD1Fail)}
	ch <- res
	return nil,nil,false
    }

    itmp = 0
    iter = w.msg_d1_1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	ds[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    var upg = make(map[string]*ec2.PolyGStruct2)
    for _,v := range ds {
	mm := strings.Split(v, Sep)
	dlen,_ := strconv.Atoi(mm[2])
	if len(mm) < (4+dlen) {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_d1_1 data error")}
	    ch <- res
	    return nil,nil,false
	}

	pglen,_ := strconv.Atoi(mm[3+dlen])
	pglen = (pglen/2)
	var pgss = make([][]*big.Int, 0)
	l := 0
	for j:=0;j<pglen;j++ {
	    l++
	    var gg = make([]*big.Int,0)
	    if len(mm) < (4+dlen+l) {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_d1_1 data error")}
		ch <- res
		return nil,nil,false
	    }

	    gg = append(gg,new(big.Int).SetBytes([]byte(mm[3+dlen+l])))
	    l++
	    if len(mm) < (4+dlen+l) {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_d1_1 data error")}
		ch <- res
		return nil,nil,false
	    }
	    gg = append(gg,new(big.Int).SetBytes([]byte(mm[3+dlen+l])))
	    pgss = append(pgss,gg)
	}

	ps := &ec2.PolyGStruct2{PolyG:pgss}
	prex := mm[0]
	prexs := strings.Split(prex,"-")
	upg[prexs[len(prexs)-1]] = ps
    }
    upg[cur_enode] = u1PolyG

    // 3. verify the share
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	//bug
	if len(en) == 0 || en[0] == "" || sstruct[en[0]] == nil || upg[en[0]] == nil {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifySHARE1Fail)}
	    ch <- res
	    return nil,nil,false
	}
	//
	if DECDSA_Key_Verify_Share(sstruct[en[0]],upg[en[0]]) == false {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifySHARE1Fail)}
	    ch <- res
	    return nil,nil,false
	}
    }

    return sstruct,ds,true
}

func DECDSAGenKeyCalcPubKey(msgprex string,cointype string,ch chan interface{},w *RpcReqWorker,udecom map[string]*ec2.Commitment,ids sortableIDSSlice) (map[string][]*big.Int,bool) {
    if w == nil || cointype == "" || msgprex == "" || len(udecom) == 0 || len(ids) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil,false
    }

    // for all nodes, de-commitment
    var ug = make(map[string][]*big.Int)
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	_, u1G := udecom[en[0]].DeCommit()
	ug[en[0]] = u1G
    }

    // for all nodes, calculate the public key
    var pkx *big.Int
    var pky *big.Int
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	pkx = (ug[en[0]])[0]
	pky = (ug[en[0]])[1]
	break
    }

    for k,id := range ids {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	pkx, pky = secp256k1.S256().Add(pkx, pky, (ug[en[0]])[0],(ug[en[0]])[1])
    }
    w.pkx.PushBack(string(pkx.Bytes()))
    w.pky.PushBack(string(pky.Bytes()))

    return ug,true
}
 
func DECDSAGenKeyCalcPrivKey(msgprex string,cointype string,ch chan interface{},w *RpcReqWorker,sstruct map[string]*ec2.ShareStruct2,ids sortableIDSSlice) (*big.Int,bool) {
    if w == nil || cointype == "" || msgprex == "" || len(sstruct) == 0 || len(ids) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil,false
    }
    
    // 5. calculate the share of private key
    var skU1 *big.Int
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	skU1 = sstruct[en[0]].Share
	break
    }

    for k,id := range ids {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	skU1 = new(big.Int).Add(skU1,sstruct[en[0]].Share)
    }
    skU1 = new(big.Int).Mod(skU1, secp256k1.S256().N)

    return skU1,true
}

func DECDSAGenKeyVerifyCommitment(msgprex string,cointype string,ch chan interface{},w *RpcReqWorker,ds []string,commitU1G *ec2.Commitment,ids sortableIDSSlice) ([]string,map[string]*ec2.Commitment,bool) {
    if w == nil || cointype == "" || msgprex == "" || len(ds) == 0 || len(ids) == 0 || commitU1G == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil,nil,false
    }
 
    // 4.verify and de-commitment to get uG
    // for all nodes, construct the commitment by the receiving C and D
    cs := make([]string,NodeCnt-1)
    if w.msg_c1.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllC1Fail)}
	ch <- res
	return nil,nil,false
    }

    itmp := 0
    iter := w.msg_c1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	cs[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    var udecom = make(map[string]*ec2.Commitment)
    for _,v := range cs {
	mm := strings.Split(v, Sep)
	if len(mm) < 3 {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllC1Fail)}
	    ch <- res
	    return nil,nil,false
	}

	prex := mm[0]
	prexs := strings.Split(prex,"-")
	for _,vv := range ds {
	    mmm := strings.Split(vv, Sep)
	    //bug
	    if len(mmm) < 3 {
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllC1Fail)}
		ch <- res
		return nil,nil,false
	    }

	    prex2 := mmm[0]
	    prexs2 := strings.Split(prex2,"-")
	    if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
		dlen,_ := strconv.Atoi(mmm[2])
		var gg = make([]*big.Int,0)
		l := 0
		for j:=0;j<dlen;j++ {
		    l++
		    //bug
		    if len(mmm) < (3+l) {
			res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllC1Fail)}
			ch <- res
			return nil,nil,false
		    }
		    gg = append(gg,new(big.Int).SetBytes([]byte(mmm[2+l])))
		}
		deCommit := &ec2.Commitment{C:new(big.Int).SetBytes([]byte(mm[2])), D:gg}
		udecom[prexs[len(prexs)-1]] = deCommit
		break
	    }
	}
    }
    deCommit_commitU1G := &ec2.Commitment{C: commitU1G.C, D: commitU1G.D}
    udecom[cur_enode] = deCommit_commitU1G

    // for all nodes, verify the commitment
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	if len(en) == 0 || en[0] == "" || udecom[en[0]] == nil {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrKeyGenVerifyCommitFail)}
	    ch <- res
	    return nil,nil,false
	}
	if DECDSA_Key_Commitment_Verify(udecom[en[0]]) == false {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrKeyGenVerifyCommitFail)}
	    ch <- res
	    return nil,nil,false
	}
    }

    return cs,udecom,true
}

func DECDSAGenKeyRoundFour(msgprex string,ch chan interface{},w *RpcReqWorker) (*ec2.NtildeH1H2,bool) {
    if w == nil || msgprex == "" {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil,false
    }

    // 6. calculate the zk
    
    // zk of paillier key
    NtildeLength := 2048 
    // for u1
    u1NtildeH1H2 := DECDSA_Key_GenerateNtildeH1H2(NtildeLength)
    if u1NtildeH1H2 == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("gen ntilde h1 h2 fail.")}
	ch <- res
	return nil,false 
    }

    // 7. Broadcast ntilde 
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "NTILDEH1H2" //delete zkfactor add ntild h1 h2
    s1 := string(u1NtildeH1H2.Ntilde.Bytes())
    s2 := string(u1NtildeH1H2.H1.Bytes())
    s3 := string(u1NtildeH1H2.H2.Bytes())
    ss := enode + Sep + s0 + Sep + s1 + Sep + s2 + Sep + s3
    SendMsgToDcrmGroup(ss,w.groupid)

    // 1. Receive Broadcast zk
    // u1zkFactProof, u2zkFactProof, u3zkFactProof, u4zkFactProof, u5zkFactProof
    _,tip,cherr := GetChannelValue(ch_t,w.bzkfact)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:GetRetErr(ErrGetZKFACTPROOFTimeout)}
	ch <- res
	return nil,false
    }

    return u1NtildeH1H2,true
}

func DECDSAGenKeyRoundFive(msgprex string,ch chan interface{},w *RpcReqWorker,u1 *big.Int) bool {
    if w == nil || msgprex == "" {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return false
    }

    // zk of u
    u1zkUProof := DECDSA_Key_ZkUProve(u1) 

    // 8. Broadcast zk
    // u1zkUProof, u2zkUProof, u3zkUProof, u4zkUProof, u5zkUProof
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "ZKUPROOF"
    s1 := string(u1zkUProof.E.Bytes())
    s2 := string(u1zkUProof.S.Bytes())
    ss := enode + Sep + s0 + Sep + s1 + Sep + s2
    SendMsgToDcrmGroup(ss,w.groupid)

    // 9. Receive Broadcast zk
    // u1zkUProof, u2zkUProof, u3zkUProof, u4zkUProof, u5zkUProof
    _,tip,cherr := GetChannelValue(ch_t,w.bzku)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Tip:tip,Err:GetRetErr(ErrGetZKUPROOFTimeout)}
	ch <- res
	return false 
    }

    return true
}

func DECDSAGenKeyVerifyZKU(msgprex string,cointype string,ch chan interface{},w *RpcReqWorker,ids sortableIDSSlice,ug map[string][]*big.Int) bool {
    if w == nil || msgprex == "" || cointype == "" || len(ids) == 0 || len(ug) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return false
    }

    // for all nodes, verify zk of u
    zku := make([]string,NodeCnt-1)
    if w.msg_zku.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllZKUPROOFFail)}
	ch <- res
	return false
    }
    itmp := 0
    iter := w.msg_zku.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	zku[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	for _,v := range zku {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		e := new(big.Int).SetBytes([]byte(mm[2]))
		s := new(big.Int).SetBytes([]byte(mm[3]))
		zkUProof := &ec2.ZkUProof{E: e, S: s}
		if !DECDSA_Key_ZkUVerify(ug[en[0]],zkUProof) {
		    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyZKUPROOFFail)}
		    ch <- res
		    return false 
		}

		break
	    }
	}
    }

    return true
}

func DECDSAGenKeySaveData(cointype string,ids sortableIDSSlice,w *RpcReqWorker,ch chan interface{},skU1 *big.Int,u1PaillierPk *ec2.PublicKey, u1PaillierSk *ec2.PrivateKey,cs []string,u1NtildeH1H2 *ec2.NtildeH1H2) bool {
    if cointype == "" || len(ids) == 0 || w == nil || skU1 == nil || u1PaillierPk == nil || u1PaillierSk == nil || len(cs) == 0 || u1NtildeH1H2 == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return false
    }

    //save skU1/u1PaillierSk/u1PaillierPk/...
    ss := string(skU1.Bytes())
    ss = ss + SepSave
    s1 := u1PaillierSk.Length
    s2 := string(u1PaillierSk.L.Bytes()) 
    s3 := string(u1PaillierSk.U.Bytes())
    ss = ss + s1 + SepSave + s2 + SepSave + s3 + SepSave

    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    s1 = u1PaillierPk.Length
	    s2 = string(u1PaillierPk.N.Bytes()) 
	    s3 = string(u1PaillierPk.G.Bytes()) 
	    s4 := string(u1PaillierPk.N2.Bytes()) 
	    ss = ss + s1 + SepSave + s2 + SepSave + s3 + SepSave + s4 + SepSave
	    continue
	}
	for _,v := range cs {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		s1 = mm[3] 
		s2 = mm[4] 
		s3 = mm[5] 
		s4 := mm[6] 
		ss = ss + s1 + SepSave + s2 + SepSave + s3 + SepSave + s4 + SepSave
		break
	    }
	}
    }

    zkfacts := make([]string,NodeCnt-1)
    if w.msg_zkfact.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllZKFACTPROOFFail)}
	ch <- res
	return false
    }

    itmp := 0
    iter := w.msg_zkfact.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	zkfacts[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    s1 = string(u1NtildeH1H2.Ntilde.Bytes())
	    s2 = string(u1NtildeH1H2.H1.Bytes())
	    s3 = string(u1NtildeH1H2.H2.Bytes())
	    ss = ss + s1 + SepSave + s2 + SepSave + s3 + SepSave
	    continue
	}

	for _,v := range zkfacts {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		ss = ss + mm[2] + SepSave + mm[3] + SepSave + mm[4] + SepSave //for ntilde 
		break
	    }
	}
    }

    ss = ss + "NULL"
    //w.save:  sku1:UiSK:U1PK:U2PK:U3PK:....:UnPK:U1H1:U1H2:U1Y:U1E:U1N:U2H1:U2H2:U2Y:U2E:U2N:U3H1:U3H2:U3Y:U3E:U3N:......:NULL
    //w.save:  sku1:UiSK.Len:UiSK.L:UiSK.U:U1PK.Len:U1PK.N:U1PK.G:U1PK.N2:U2PK.Len:U2PK.N:U2PK.G:U2PK.N2:....:UnPK.Len:UnPK.N:UnPK.G:UnPK.N2:U1Ntilde:U1H1:U1H2:U2Ntilde::U2H1:U2H2:......:UnNtilde:UnH1:UnH2:NULL
    w.save.PushBack(ss)
    return true
}

//ec2
//msgprex = hash 
func KeyGenerate_DECDSA(msgprex string,ch chan interface{},id int,cointype string) bool {
    if id < 0 || id >= RpcMaxWorker || id >= len(workers) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetWorkerIdError)}
	ch <- res
	return false
    }

    w := workers[id]
    if w.groupid == "" {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get group id fail.")}
	ch <- res
	return false
    }
    
    ns,_ := GetGroup(w.groupid)
    if ns != NodeCnt {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGroupNotReady)}
	ch <- res
	return false 
    }

    ids := GetIds(cointype,w.groupid)
    
    //*******************!!!Distributed ECDSA Start!!!**********************************

    u1,u1Poly, u1PolyG,commitU1G,u1PaillierPk, u1PaillierSk,status := DECDSAGenKeyRoundOne(msgprex,ch,w)
    if status != true {
	return status
    }
    fmt.Println("=================generate key,round one finish===================")

    u1Shares,status := DECDSAGenKeyRoundTwo(msgprex,cointype,ch,w,u1Poly,ids)
    if status != true {
	return status
    }
    fmt.Println("=================generate key,round two finish===================")

    if DECDSAGenKeyRoundThree(msgprex,cointype,ch,w,u1PolyG,commitU1G,ids) == false {
	return false
    }
    fmt.Println("=================generate key,round three finish===================")

    sstruct,ds,status := DECDSAGenKeyVerifyShareData(msgprex,cointype,ch,w,u1PolyG,u1Shares,ids)
    if status != true {
	return status
    }
    fmt.Println("=================generate key,verify share data finish===================")

    cs,udecom,status := DECDSAGenKeyVerifyCommitment(msgprex,cointype,ch,w,ds,commitU1G,ids)
    if status != true {
	return false
    }
    fmt.Println("=================generate key,verify commitment finish===================")

    ug,status := DECDSAGenKeyCalcPubKey(msgprex,cointype,ch,w,udecom,ids)
    if status != true {
	return false
    }
    fmt.Println("=================generate key,calc pubkey finish===================")

    skU1,status := DECDSAGenKeyCalcPrivKey(msgprex,cointype,ch,w,sstruct,ids)
    if status != true {
	return false
    }
    fmt.Println("=================generate key,calc privkey finish===================")

    u1NtildeH1H2,status := DECDSAGenKeyRoundFour(msgprex,ch,w)
    if status != true {
	return false
    }
    fmt.Println("=================generate key,round four finish===================")

    if DECDSAGenKeyRoundFive(msgprex,ch,w,u1) != true {
	return false
    }
    fmt.Println("=================generate key,round five finish===================")

    if DECDSAGenKeyVerifyZKU(msgprex,cointype,ch,w,ids,ug) != true {
	return false
    }
    fmt.Println("=================generate key,verify zk of u1 finish===================")

    if DECDSAGenKeySaveData(cointype,ids,w,ch,skU1,u1PaillierPk,u1PaillierSk,cs,u1NtildeH1H2) != true {
	return false
    }
    fmt.Println("=================generate key,save data finish===================")

    //*******************!!!Distributed ECDSA End!!!**********************************
    return true
}

