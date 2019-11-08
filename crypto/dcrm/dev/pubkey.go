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
    "math/big"
    "github.com/syndtr/goleveldb/leveldb"
    "github.com/fsn-dev/dcrm-sdk/crypto/secp256k1"
    "github.com/fsn-dev/dcrm-sdk/crypto/dcrm/dev/lib/ec2"
    "encoding/hex"
    "strconv"
    "strings"
    "github.com/fsn-dev/dcrm-sdk/crypto/dcrm/dev/lib/ed"
    "github.com/fsn-dev/dcrm-sdk/internal/common"
    "github.com/fsn-dev/dcrm-sdk/crypto/dcrm/cryptocoins/types"
    cryptorand "crypto/rand"
    "crypto/sha512"
    "github.com/astaxie/beego/logs"
)

func ExsitPubKey(account string,cointype string) (string,bool) {
     //db
    lock.Lock()
    dir := GetDbDir()
    ////////
    db, err := leveldb.OpenFile(dir, nil)
    if err != nil {
        lock.Unlock()
        return "",false
    }
    
    key := Keccak256Hash([]byte(account + ":" + cointype)).Hex()
    da,err := db.Get([]byte(key),nil)
    ///////
    if err != nil {
	key = Keccak256Hash([]byte(account + ":" + "ALL")).Hex()
	da,err = db.Get([]byte(key),nil)
	///////
	if err != nil {
	    db.Close()
	    lock.Unlock()
	    return "",false
	}
    }

    
    data := string(da)
    datas := strings.Split(data,Sep)
    pubkey := hex.EncodeToString([]byte(datas[0]))
    db.Close()
    lock.Unlock()
    return pubkey,true
}

//ec2
//msgprex = hash 
func dcrm_genPubKey(msgprex string,account string,cointype string,ch chan interface{}) {

    fmt.Println("========dcrm_genPubKey============")
    GetEnodesInfo()

    if int32(Enode_cnts) != int32(NodeCnt) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGroupNotReady)}
	ch <- res
	return
    }

    wk,err := FindWorker(msgprex)
    if err != nil || wk == nil {
	res := RpcDcrmRes{Ret:"",Err:err}
	ch <- res
	return
    }
    id := wk.id

    if da,b := ExsitPubKey(account,cointype); b == true {
	res := RpcDcrmRes{Ret:da,Err:nil}
	ch <- res
	return
    }

    if types.IsDefaultED25519(cointype) {
	ok2 := KeyGenerate_ed(msgprex,ch,id,cointype)
	if ok2 == false {
	    logs.Debug("========dcrm_genPubKey,addr generate fail.=========")
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("addr generate fail")}
	    ch <- res
	    return
	}

	itertmp := workers[id].edpk.Front()
	if itertmp == nil {
	    logs.Debug("get workers[id].edpk fail.")
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetGenPubkeyFail)}
	    ch <- res
	    return
	}
	sedpk := []byte(itertmp.Value.(string))

	itertmp = workers[id].edsave.Front()
	if itertmp == nil {
	    logs.Debug("get workers[id].edsave fail.")
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetGenSaveDataFail)}
	    ch <- res
	    return
	}
	sedsave := itertmp.Value.(string)

	lock.Lock()
	dir := GetDbDir()
	db, err := leveldb.OpenFile(dir, nil) 
	if err != nil { 
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrCreateDbFail)}
	    ch <- res
	    lock.Unlock()
	    return
	}

	pubkeyhex2 := hex.EncodeToString(sedpk[:])
	logs.Debug("========key gen=========","pubkeyhex2",pubkeyhex2,"sedpk len",len(sedpk))
	s := []string{string(sedpk),sedsave,"0"}
	ss := strings.Join(s,common.Sep)
	//db.Put(sedpk[:],[]byte(ss),nil)
	key := Keccak256Hash([]byte(account + ":" + cointype)).Hex()
	db.Put([]byte(key),[]byte(ss),nil)

	res := RpcDcrmRes{Ret:pubkeyhex2,Err:nil}
	ch <- res

	db.Close()
	lock.Unlock()
	return
    }
    
    ok := KeyGenerate_ec2(msgprex,ch,id,cointype)
    if ok == false {
	return
    }

    iter := workers[id].pkx.Front()
    if iter == nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetGenPubkeyFail)}
	ch <- res
	return
    }
    spkx := iter.Value.(string)
    pkx := new(big.Int).SetBytes([]byte(spkx))
    iter = workers[id].pky.Front()
    if iter == nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetGenPubkeyFail)}
	ch <- res
	return
    }
    spky := iter.Value.(string)
    pky := new(big.Int).SetBytes([]byte(spky))
    ys := secp256k1.S256().Marshal(pkx,pky)

    iter = workers[id].save.Front()
    if iter == nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetGenSaveDataFail)}
	ch <- res
	return
    }
    save := iter.Value.(string)

    lock.Lock()
    dir := GetDbDir()
    db, err := leveldb.OpenFile(dir, nil) 
    if err != nil { 
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrCreateDbFail)}
	ch <- res
	lock.Unlock()
	return
    }

    pubkeyhex := hex.EncodeToString(ys)

    s := []string{string(ys),save,"0"}
    ss := strings.Join(s,Sep)
    //db.Put(ys,[]byte(ss),nil)
    key := Keccak256Hash([]byte(account + ":" + cointype)).Hex()
    db.Put([]byte(key),[]byte(ss),nil)
    db.Close()
    lock.Unlock()
    res := RpcDcrmRes{Ret:pubkeyhex,Err:nil}
    ch <- res
}

//ed
//msgprex = hash
func KeyGenerate_ed(msgprex string,ch chan interface{},id int,cointype string) bool {
    if id < 0 || id >= RpcMaxWorker || id >= len(workers) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetWorkerIdError)}
	ch <- res
	return false
    }

    w := workers[id]
    GroupId := w.groupid 
    fmt.Println("========KeyGenerate_ed============","GroupId",GroupId)
    if GroupId == "" {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get group id fail.")}
	ch <- res
	return false
    }
    
    ns,_ := GetGroup(GroupId)
    if ns != NodeCnt {
	logs.Debug("KeyGenerate_ed,get nodes info error.")
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGroupNotReady)}
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
    
    _,cherr := GetChannelValue(ch_t,w.bedc11)
    if cherr != nil {
	logs.Debug("get w.bedc11 timeout.")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get ed c11 timeout.")}
	ch <- res
	return false 
    }

    if w.msg_edc11.Len() != (NodeCnt-1) {
	logs.Debug("get w.msg_edc11 fail.")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all ed c11 fail.")}
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
    
    _,cherr = GetChannelValue(ch_t,w.bedzk)
    if cherr != nil {
	logs.Debug("get w.bedzk timeout.")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get ed zk timeout.")}
	ch <- res
	return false 
    }

    if w.msg_edzk.Len() != (NodeCnt-1) {
	logs.Debug("get w.msg_edzk fail.")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all ed zk fail.")}
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
    
    _,cherr = GetChannelValue(ch_t,w.bedd11)
    if cherr != nil {
	logs.Debug("get w.bedd11 timeout.")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get ed d11 timeout.")}
	ch <- res
	return false 
    }

    if w.msg_edd11.Len() != (NodeCnt-1) {
	logs.Debug("get w.msg_edd11 fail.")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all ed d11 fail.")}
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
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("Commitment(PK) Not Pass at User.")}
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
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("ZeroKnowledge Proof (Pk) Not Pass.")}
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
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetEnodeByUIdFail)}
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

    _,cherr = GetChannelValue(ch_t,w.bedshare1)
    if cherr != nil {
	logs.Debug("get w.bedshare1 timeout in keygenerate.")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get ed share1 fail.")}
	ch <- res
	return false 
    }
    logs.Debug("================kg ed round two,receiv msg,code is EDSHARE1.==================")

    if w.msg_edshare1.Len() != (NodeCnt-1) {
	logs.Debug("get w.msg_edshare1 fail.")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all ed share1 fail.")}
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

     _,cherr = GetChannelValue(ch_t,w.bedcfsb)
    if cherr != nil {
	logs.Debug("get w.bedcfsb timeout.")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get ed cfsb timeout.")}
	ch <- res
	return false 
    }

    if w.msg_edcfsb.Len() != (NodeCnt-1) {
	logs.Debug("get w.msg_edcfsb fail.")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all ed cfsb fail.")}
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
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("VSS Share Verification Not Pass.")}
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
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("VSS Coefficient Verification Not Pass.")}
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

//ec2
//msgprex = hash 
func KeyGenerate_ec2(msgprex string,ch chan interface{},id int,cointype string) bool {
    if id < 0 || id >= RpcMaxWorker || id >= len(workers) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetWorkerIdError)}
	ch <- res
	return false
    }

    w := workers[id]
    GroupId := w.groupid 
    fmt.Println("========KeyGenerate_ec2============","GroupId",GroupId)
    if GroupId == "" {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get group id fail.")}
	ch <- res
	return false
    }
    
    ns,_ := GetGroup(GroupId)
    if ns != NodeCnt {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGroupNotReady)}
	ch <- res
	return false 
    }

    //1. generate their own "partial" private key secretly
    u1 := GetRandomIntFromZn(secp256k1.S256().N)

    // 2. calculate "partial" public key, make "pritial" public key commiment to get (C,D)
    u1Gx, u1Gy := secp256k1.S256().ScalarBaseMult(u1.Bytes())
    commitU1G := new(ec2.Commitment).Commit(u1Gx, u1Gy)

    // 3. generate their own paillier public key and private key
    u1PaillierPk, u1PaillierSk := ec2.GenerateKeyPair(PaillierKeyLength)

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
    SendMsgToDcrmGroup(ss,GroupId)

    // 1. Receive Broadcast
    // commitU1G.C, commitU2G.C, commitU3G.C, commitU4G.C, commitU5G.C
    // u1PaillierPk, u2PaillierPk, u3PaillierPk, u4PaillierPk, u5PaillierPk
     _,cherr := GetChannelValue(ch_t,w.bc1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetC1Timeout)}
	ch <- res
	return false 
    }

    // 2. generate their vss to get shares which is a set
    // [notes]
    // all nodes has their own id, in practival, we can take it as double hash of public key of fusion

    ids := GetIds(cointype,GroupId)

    u1PolyG, _, u1Shares, err := ec2.Vss(u1, ids, ThresHold, NodeCnt)
    if err != nil {
	res := RpcDcrmRes{Ret:"",Err:err}
	ch <- res
	return false 
    }

    // 3. send the the proper share to proper node 
    //example for u1:
    // Send u1Shares[0] to u1
    // Send u1Shares[1] to u2
    // Send u1Shares[2] to u3
    // Send u1Shares[3] to u4
    // Send u1Shares[4] to u5
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)

	if enodes == "" {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetEnodeByUIdFail)}
	    ch <- res
	    return false
	}
	
	if IsCurNode(enodes,cur_enode) {
	    continue
	}

	for _,v := range u1Shares {
	    uid := ec2.GetSharesId(v)
	    if uid.Cmp(id) == 0 {
		mp := []string{msgprex,cur_enode}
		enode := strings.Join(mp,"-")
		s0 := "SHARE1"
		s1 := strconv.Itoa(v.T) 
		s2 := string(v.Id.Bytes()) 
		s3 := string(v.Share.Bytes()) 
		ss := enode + Sep + s0 + Sep + s1 + Sep + s2 + Sep + s3
		SendMsgToPeer(enodes,ss)
		break
	    }
	}
    }

    // 4. Broadcast
    // commitU1G.D, commitU2G.D, commitU3G.D, commitU4G.D, commitU5G.D
    // u1PolyG, u2PolyG, u3PolyG, u4PolyG, u5PolyG
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "D1"
    dlen := len(commitU1G.D)
    s1 = strconv.Itoa(dlen)

    ss = enode + Sep + s0 + Sep + s1 + Sep
    for _,d := range commitU1G.D {
	ss += string(d.Bytes())
	ss += Sep
    }

    s2 = strconv.Itoa(u1PolyG.T)
    s3 = strconv.Itoa(u1PolyG.N)
    ss = ss + s2 + Sep + s3 + Sep

    pglen := 2*(len(u1PolyG.PolyG))
    s4 = strconv.Itoa(pglen)

    ss = ss + s4 + Sep

    for _,p := range u1PolyG.PolyG {
	for _,d := range p {
	    ss += string(d.Bytes())
	    ss += Sep
	}
    }
    ss = ss + "NULL"
    SendMsgToDcrmGroup(ss,GroupId)

    // 1. Receive Broadcast
    // commitU1G.D, commitU2G.D, commitU3G.D, commitU4G.D, commitU5G.D
    // u1PolyG, u2PolyG, u3PolyG, u4PolyG, u5PolyG
    _,cherr = GetChannelValue(ch_t,w.bd1_1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetD1Timeout)}
	ch <- res
	return false 
    }

    // 2. Receive Personal Data
    _,cherr = GetChannelValue(ch_t,w.bshare1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetSHARE1Timeout)}
	ch <- res
	return false 
    }
	 
    shares := make([]string,NodeCnt-1)
    if w.msg_share1.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllSHARE1Fail)}
	ch <- res
	return false
    }
    itmp := 0
    iter := w.msg_share1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	shares[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }
    
    //var sstruct = make(map[string]*vss.ShareStruct)
    var sstruct = make(map[string]*ec2.ShareStruct)
    for _,v := range shares {
	mm := strings.Split(v, Sep)
	t,_ := strconv.Atoi(mm[2])
	ushare := &ec2.ShareStruct{T:t,Id:new(big.Int).SetBytes([]byte(mm[3])),Share:new(big.Int).SetBytes([]byte(mm[4]))}
	prex := mm[0]
	prexs := strings.Split(prex,"-")
	sstruct[prexs[len(prexs)-1]] = ushare
    }
    for _,v := range u1Shares {
	uid := ec2.GetSharesId(v)
	enodes := GetEnodesByUid(uid,cointype,GroupId)
	if IsCurNode(enodes,cur_enode) {
	    sstruct[cur_enode] = v 
	    break
	}
    }

    ds := make([]string,NodeCnt-1)
    if w.msg_d1_1.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllD1Fail)}
	ch <- res
	return false
    }
    itmp = 0
    iter = w.msg_d1_1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	ds[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    var upg = make(map[string]*ec2.PolyGStruct)
    for _,v := range ds {
	mm := strings.Split(v, Sep)
	dlen,_ := strconv.Atoi(mm[2])
	pglen,_ := strconv.Atoi(mm[3+dlen+2])
	pglen = (pglen/2)
	var pgss = make([][]*big.Int, 0)
	l := 0
	for j:=0;j<pglen;j++ {
	    l++
	    var gg = make([]*big.Int,0)
	    gg = append(gg,new(big.Int).SetBytes([]byte(mm[5+dlen+l])))
	    l++
	    gg = append(gg,new(big.Int).SetBytes([]byte(mm[5+dlen+l])))
	    pgss = append(pgss,gg)
	}

	t,_ := strconv.Atoi(mm[3+dlen])
	n,_ := strconv.Atoi(mm[4+dlen])
	ps := &ec2.PolyGStruct{T:t,N:n,PolyG:pgss}
	prex := mm[0]
	prexs := strings.Split(prex,"-")
	upg[prexs[len(prexs)-1]] = ps
    }
    upg[cur_enode] = u1PolyG

    // 3. verify the share
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if sstruct[en[0]].Verify(upg[en[0]]) == false {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifySHARE1Fail)}
	    ch <- res
	    return false
	}
    }

    // 4.verify and de-commitment to get uG
    // for all nodes, construct the commitment by the receiving C and D
    cs := make([]string,NodeCnt-1)
    if w.msg_c1.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllC1Fail)}
	ch <- res
	return false
    }
    itmp = 0
    iter = w.msg_c1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	cs[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    var udecom = make(map[string]*ec2.Commitment)
    for _,v := range cs {
	mm := strings.Split(v, Sep)
	prex := mm[0]
	prexs := strings.Split(prex,"-")
	for _,vv := range ds {
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
    deCommit_commitU1G := &ec2.Commitment{C: commitU1G.C, D: commitU1G.D}
    udecom[cur_enode] = deCommit_commitU1G

    // for all nodes, verify the commitment
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if udecom[en[0]].Verify() == false {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrKeyGenVerifyCommitFail)}
	    ch <- res
	    return false
	}
    }

    // for all nodes, de-commitment
    var ug = make(map[string][]*big.Int)
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	_, u1G := udecom[en[0]].DeCommit()
	ug[en[0]] = u1G
    }

    // for all nodes, calculate the public key
    var pkx *big.Int
    var pky *big.Int
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	pkx = (ug[en[0]])[0]
	pky = (ug[en[0]])[1]
	break
    }

    for k,id := range ids {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	pkx, pky = secp256k1.S256().Add(pkx, pky, (ug[en[0]])[0],(ug[en[0]])[1])
    }
    w.pkx.PushBack(string(pkx.Bytes()))
    w.pky.PushBack(string(pky.Bytes()))

    // 5. calculate the share of private key
    var skU1 *big.Int
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	skU1 = sstruct[en[0]].Share
	break
    }

    for k,id := range ids {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	skU1 = new(big.Int).Add(skU1,sstruct[en[0]].Share)
    }
    skU1 = new(big.Int).Mod(skU1, secp256k1.S256().N)

    //save skU1/u1PaillierSk/u1PaillierPk/...
    ss = string(skU1.Bytes())
    ss = ss + SepSave
    s1 = u1PaillierSk.Length
    s2 = string(u1PaillierSk.L.Bytes()) 
    s3 = string(u1PaillierSk.U.Bytes())
    ss = ss + s1 + SepSave + s2 + SepSave + s3 + SepSave

    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    s1 = u1PaillierPk.Length
	    s2 = string(u1PaillierPk.N.Bytes()) 
	    s3 = string(u1PaillierPk.G.Bytes()) 
	    s4 = string(u1PaillierPk.N2.Bytes()) 
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
		s4 = mm[6] 
		ss = ss + s1 + SepSave + s2 + SepSave + s3 + SepSave + s4 + SepSave
		break
	    }
	}
    }

    sstmp := ss //////
    tmp := ss

    ss = ss + "NULL"

    // 6. calculate the zk
    // ## add content: zk of paillier key, zk of u
    
    // zk of paillier key
    u1zkFactProof := u1PaillierSk.ZkFactProve()
    // zk of u
    //u1zkUProof := schnorrZK.ZkUProve(u1)
    u1zkUProof := ec2.ZkUProve(u1)

    // 7. Broadcast zk
    // u1zkFactProof, u2zkFactProof, u3zkFactProof, u4zkFactProof, u5zkFactProof
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "ZKFACTPROOF"
    s1 = string(u1zkFactProof.H1.Bytes())
    s2 = string(u1zkFactProof.H2.Bytes())
    s3 = string(u1zkFactProof.Y.Bytes())
    s4 = string(u1zkFactProof.E.Bytes())
    s5 = string(u1zkFactProof.N.Bytes())
    ss = enode + Sep + s0 + Sep + s1 + Sep + s2 + Sep + s3 + Sep + s4 + Sep + s5
    SendMsgToDcrmGroup(ss,GroupId)

    // 1. Receive Broadcast zk
    // u1zkFactProof, u2zkFactProof, u3zkFactProof, u4zkFactProof, u5zkFactProof
    _,cherr = GetChannelValue(ch_t,w.bzkfact)
    if cherr != nil {
//	logs.Debug("get w.bzkfact timeout in keygenerate.")
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetZKFACTPROOFTimeout)}
	ch <- res
	return false 
    }

    sstmp2 := s1 + SepSave + s2 + SepSave + s3 + SepSave + s4 + SepSave + s5

    // 8. Broadcast zk
    // u1zkUProof, u2zkUProof, u3zkUProof, u4zkUProof, u5zkUProof
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "ZKUPROOF"
    s1 = string(u1zkUProof.E.Bytes())
    s2 = string(u1zkUProof.S.Bytes())
    ss = enode + Sep + s0 + Sep + s1 + Sep + s2
    SendMsgToDcrmGroup(ss,GroupId)

    // 9. Receive Broadcast zk
    // u1zkUProof, u2zkUProof, u3zkUProof, u4zkUProof, u5zkUProof
    _,cherr = GetChannelValue(ch_t,w.bzku)
    if cherr != nil {
//	logs.Info("get w.bzku timeout in keygenerate.")
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetZKUPROOFTimeout)}
	ch <- res
	return false 
    }
    
    // 1. verify the zk
    // ## add content: verify zk of paillier key, zk of u
	
    // for all nodes, verify zk of paillier key
    zkfacts := make([]string,NodeCnt-1)
    if w.msg_zkfact.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllZKFACTPROOFFail)}
	ch <- res
	return false
    }
    itmp = 0
    iter = w.msg_zkfact.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	zkfacts[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for k,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) { /////bug for save zkfact
	    sstmp = sstmp + sstmp2 + SepSave
	    continue
	}

	u1PaillierPk2 := GetPaillierPk(tmp,k)
	for _,v := range zkfacts {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		h1 := new(big.Int).SetBytes([]byte(mm[2]))
		h2 := new(big.Int).SetBytes([]byte(mm[3]))
		y := new(big.Int).SetBytes([]byte(mm[4]))
		e := new(big.Int).SetBytes([]byte(mm[5]))
		n := new(big.Int).SetBytes([]byte(mm[6]))
		zkFactProof := &ec2.ZkFactProof{H1: h1, H2: h2, Y: y, E: e,N:n}
		///////
		sstmp = sstmp + mm[2] + SepSave + mm[3] + SepSave + mm[4] + SepSave + mm[5] + SepSave + mm[6] + SepSave  ///for save zkfact
		//////

		if !u1PaillierPk2.ZkFactVerify(zkFactProof) {
		    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyZKFACTPROOFFail)}
		    ch <- res
	    
		    return false 
		}

		break
	    }
	}
    }

    // for all nodes, verify zk of u
    zku := make([]string,NodeCnt-1)
    if w.msg_zku.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllZKUPROOFFail)}
	ch <- res
	return false
    }
    itmp = 0
    iter = w.msg_zku.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	zku[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	for _,v := range zku {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		e := new(big.Int).SetBytes([]byte(mm[2]))
		s := new(big.Int).SetBytes([]byte(mm[3]))
		zkUProof := &ec2.ZkUProof{E: e, S: s}
		if !ec2.ZkUVerify(ug[en[0]],zkUProof) {
		    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyZKUPROOFFail)}
		    ch <- res
		    return false 
		}

		break
	    }
	}
    } 
    
    sstmp = sstmp + "NULL"
    //w.save <- sstmp
    //w.save:  sku1:UiSK:U1PK:U2PK:U3PK:....:UnPK:U1H1:U1H2:U1Y:U1E:U1N:U2H1:U2H2:U2Y:U2E:U2N:U3H1:U3H2:U3Y:U3E:U3N:......:NULL
    w.save.PushBack(sstmp)
    return true
}

