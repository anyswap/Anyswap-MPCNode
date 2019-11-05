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
    "github.com/fsn-dev/dcrm-sdk/crypto/dcrm/dev/lib"
    "math/big"
    "github.com/fsn-dev/dcrm-sdk/crypto/secp256k1"
    "github.com/fsn-dev/dcrm-sdk/crypto/sha3"
    "time"
    "sort"
    "math/rand"
    "strconv"
    "strings"
    "fmt"
    "encoding/hex"
    "github.com/syndtr/goleveldb/leveldb"
    "bytes"
)

func validate_lockout(wsid string,pubkey string,keytype string,message string,ch chan interface{}) {
    fmt.Println("========validate_lockout============")
    lock5.Lock()
    pub, err := hex.DecodeString(pubkey)
    if err != nil {
        res := RpcDcrmRes{Ret:"",Err:err}
        ch <- res
        lock5.Unlock()
        return
    }

    //db
    dir := GetDbDir()
    ////////
    db, err := leveldb.OpenFile(dir, nil) 
    if err != nil { 
        fmt.Println("===========validate_lockout,open db fail.=============")
        res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("open db fail.")}
        ch <- res
        lock5.Unlock()
        return
    } 

    var data string
    var b bytes.Buffer 
    b.WriteString("") 
    b.WriteByte(0) 
    b.WriteString("") 
    iter := db.NewIterator(nil, nil) 
    for iter.Next() { 
	key := string(iter.Key())
	value := string(iter.Value())
	if strings.EqualFold(key,string(pub)) {
	    data = value
	    break
	}
    }
    iter.Release()
    ///////
    if data == "" {
	fmt.Println("===========get generate save data fail.=============")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get data fail.")}
	ch <- res
	db.Close()
	lock5.Unlock()
	return
    }
    
    datas := strings.Split(data,Sep)

    realdcrmpubkey := hex.EncodeToString([]byte(datas[0]))
    if !strings.EqualFold(realdcrmpubkey,pubkey) {
        res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get data fail")}
        ch <- res
        db.Close()
        lock5.Unlock()
        return
    }

    db.Close()
    lock5.Unlock()

    rch := make(chan interface{}, 1)
    dcrm_sign(wsid,"xxx",message,realdcrmpubkey,keytype,rch)
    ret,cherr := GetChannelValue(ch_t,rch)
    if cherr != nil {
	    res := RpcDcrmRes{Ret:"",Err:cherr}
	    ch <- res
	    return
    }

    res := RpcDcrmRes{Ret:ret,Err:nil}
    ch <- res
    return
}

//ec2
//msgprex = hash 
//return value is the backup for dcrm sig.
func dcrm_sign(msgprex string,sig string,txhash string,pubkey string,cointype string,ch chan interface{}) string {

    GetEnodesInfo() 
    
    if int32(Enode_cnts) != int32(NodeCnt) {
	fmt.Println("============the net group is not ready.please try again.================")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("group not ready.")}
	ch <- res
	return ""
    }

    fmt.Println("===================!!!Start!!!====================")

    lock.Lock()
    //db
    dir := GetDbDir()
    db, err := leveldb.OpenFile(dir, nil) 
    if err != nil { 
	fmt.Println("===========open db fail.=============")
        res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("open db fail.")}
        ch <- res
        lock.Unlock()
        return ""
    } 

    //
    pub,err := hex.DecodeString(pubkey)
    if err != nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get data fail.")}
	ch <- res
	db.Close()
	lock.Unlock()
	return ""
    }

    var data string
    var b bytes.Buffer 
    b.WriteString("") 
    b.WriteByte(0) 
    b.WriteString("") 
    iter := db.NewIterator(nil, nil) 
    for iter.Next() { 
	key := string(iter.Key())
	value := string(iter.Value())
	if strings.EqualFold(key,string(pub)) {
	    data = value
	    break
	}
    }
    iter.Release()
    
    if data == "" {
	fmt.Println("===========get generate save data fail.=============")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get data fail.")}
	ch <- res
	db.Close()
	lock.Unlock()
	return ""
    }

    datas := strings.Split(string(data),Sep)

    save := datas[1] 
    
    dcrmpub := datas[0]
    dcrmpks := []byte(dcrmpub)
    dcrmpkx,dcrmpky := secp256k1.S256().Unmarshal(dcrmpks[:])

    txhashs := []rune(txhash)
    if string(txhashs[0:2]) == "0x" {
	txhash = string(txhashs[2:])
    }

    db.Close()
    lock.Unlock()

    w,err := FindWorker(msgprex)
    if w == nil || err != nil {
	fmt.Println("===========get worker fail.=============")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("no find worker.")}
	ch <- res
	return ""
    }
    id := w.id
    bak_sig := Sign_ec2(msgprex,save,txhash,cointype,dcrmpkx,dcrmpky,ch,id)
    return bak_sig
}

//msgprex = hash
//return value is the backup for the dcrm sig
func Sign_ec2(msgprex string,save string,message string,cointype string,pkx *big.Int,pky *big.Int,ch chan interface{},id int) string {
    //gc := getgroupcount()
    if id < 0 || id >= len(workers) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("no find worker.")}
	ch <- res
	return ""
    }
    w := workers[id]
    GroupId := w.groupid
    fmt.Println("========Sign_ec2============","GroupId",GroupId)
    if GroupId == "" {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get group id fail.")}
	ch <- res
	return ""
    }
    
    hashBytes, err2 := hex.DecodeString(message)
    if err2 != nil {
	res := RpcDcrmRes{Ret:"",Err:err2}
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
    u1Gamma := GetRandomIntFromZn(secp256k1.S256().N)
    
    // 3. make gamma*G commitment to get (C, D)
    u1GammaGx,u1GammaGy := secp256k1.S256().ScalarBaseMult(u1Gamma.Bytes())
    commitU1GammaG := new(lib.Commitment).Commit(u1GammaGx, u1GammaGy)

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
     _,cherr := GetChannelValue(ch_t,w.bc11)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetC11Timeout)}
	ch <- res
	return ""
    }
    
    // 2. MtA(k, gamma) and MtA(k, w)
    // 2.1 encrypt c_k = E_paillier(k)
    var ukc = make(map[string]*big.Int)
    var ukc2 = make(map[string]*big.Int)
    var ukc3 = make(map[string]*lib.PublicKey)
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
    var zk1proof = make(map[string]*lib.MtAZK1Proof)
    var zkfactproof = make(map[string]*lib.ZkFactProof)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	u1zkFactProof := GetZkFactProof(save,k)
	zkfactproof[en[0]] = u1zkFactProof
	if IsCurNode(enodes,cur_enode) {
	    u1u1MtAZK1Proof := lib.MtAZK1Prove(u1K,ukc2[en[0]], ukc3[en[0]], u1zkFactProof)
	    zk1proof[en[0]] = u1u1MtAZK1Proof
	} else {
	    u1u1MtAZK1Proof := lib.MtAZK1Prove(u1K,ukc2[cur_enode], ukc3[cur_enode], u1zkFactProof)
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

    _,cherr = GetChannelValue(ch_t,w.bmtazk1proof)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetMTAZK1PROOFTimeout)}
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
     _,cherr = GetChannelValue(ch_t,w.bkc)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetKCTimeout)}
	ch <- res
	return ""
    }

    var i int
    kcs := make([]string,ThresHold-1)
    if w.msg_kc.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllKCFail)}
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
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllMTAZK1PROOFFail)}
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
		mtAZK1Proof := &lib.MtAZK1Proof{Z: z, U: u, W: w, S: s, S1: s1, S2: s2}
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
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }
	} else {
	    if len(en) <= 0 {
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }

	    _,exsit := zk1proof[en[0]]
	    if exsit == false {
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }

	    _,exsit = ukc[en[0]]
	    if exsit == false {
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }
	    
	    u1PaillierPk := GetPaillierPk(save,k)
	    if u1PaillierPk == nil {
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }

	    _,exsit = zkfactproof[cur_enode]
	    if exsit == false {
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }

	    u1rlt1 := zk1proof[en[0]].MtAZK1Verify(ukc[en[0]],u1PaillierPk,zkfactproof[cur_enode])
	    if !u1rlt1 {
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
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
	beta1U1 := new(big.Int).Mul(MinusOne, beta1U1Star)
	betaU1Star[i] = beta1U1Star
	betaU1[i] = beta1U1
    }

    vU1Star := make([]*big.Int,ThresHold)
    vU1 := make([]*big.Int,ThresHold)
    for i=0;i<ThresHold;i++ {
	v1U1Star := GetRandomIntFromZn(NSubN2)
	v1U1 := new(big.Int).Mul(MinusOne, v1U1Star)
	vU1Star[i] = v1U1Star
	vU1[i] = v1U1
    }

    // 2.7
    // send c_kGamma to proper node, MtA(k, gamma)   zk
    var mkg = make(map[string]*big.Int)
    var mkg_mtazk2 = make(map[string]*lib.MtAZK2Proof)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1PaillierPk := GetPaillierPk(save,k)
	    u1KGamma1Cipher := u1PaillierPk.HomoMul(ukc[en[0]], u1Gamma)
	    beta1U1StarCipher, u1BetaR1,_ := u1PaillierPk.Encrypt(betaU1Star[k])
	    u1KGamma1Cipher = u1PaillierPk.HomoAdd(u1KGamma1Cipher, beta1U1StarCipher) // send to u1
	    u1u1MtAZK2Proof := lib.MtAZK2Prove(u1Gamma, betaU1Star[k], u1BetaR1, ukc[cur_enode],ukc3[cur_enode], zkfactproof[cur_enode])
	    mkg[en[0]] = u1KGamma1Cipher
	    mkg_mtazk2[en[0]] = u1u1MtAZK2Proof
	    continue
	}
	
	u2PaillierPk := GetPaillierPk(save,k)
	u2KGamma1Cipher := u2PaillierPk.HomoMul(ukc[en[0]], u1Gamma)
	beta2U1StarCipher, u2BetaR1,_ := u2PaillierPk.Encrypt(betaU1Star[k])
	u2KGamma1Cipher = u2PaillierPk.HomoAdd(u2KGamma1Cipher, beta2U1StarCipher) // send to u2
	u2u1MtAZK2Proof := lib.MtAZK2Prove(u1Gamma, betaU1Star[k], u2BetaR1, ukc[en[0]],u2PaillierPk,zkfactproof[cur_enode])
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
    var mkw_mtazk2 = make(map[string]*lib.MtAZK2Proof)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1PaillierPk := GetPaillierPk(save,k)
	    u1Kw1Cipher := u1PaillierPk.HomoMul(ukc[en[0]], w1)
	    v1U1StarCipher, u1VR1,_ := u1PaillierPk.Encrypt(vU1Star[k])
	    u1Kw1Cipher = u1PaillierPk.HomoAdd(u1Kw1Cipher, v1U1StarCipher) // send to u1
	    u1u1MtAZK2Proof2 := lib.MtAZK2Prove(w1, vU1Star[k], u1VR1, ukc[cur_enode], ukc3[cur_enode], zkfactproof[cur_enode])
	    mkw[en[0]] = u1Kw1Cipher
	    mkw_mtazk2[en[0]] = u1u1MtAZK2Proof2
	    continue
	}
	
	u2PaillierPk := GetPaillierPk(save,k)
	u2Kw1Cipher := u2PaillierPk.HomoMul(ukc[en[0]], w1)
	v2U1StarCipher, u2VR1,_ := u2PaillierPk.Encrypt(vU1Star[k])
	u2Kw1Cipher = u2PaillierPk.HomoAdd(u2Kw1Cipher,v2U1StarCipher) // send to u2
	u2u1MtAZK2Proof2 := lib.MtAZK2Prove(w1, vU1Star[k], u2VR1, ukc[en[0]], u2PaillierPk, zkfactproof[cur_enode])

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
     _,cherr = GetChannelValue(ch_t,w.bmkg)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetMKGTimeout)}
	ch <- res
	return ""
    }

    mkgs := make([]string,ThresHold-1)
    if w.msg_mkg.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllMKGFail)}
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
		mtAZK2Proof := &lib.MtAZK2Proof{Z: z, ZBar: zbar, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}
		mkg_mtazk2[en[0]] = mtAZK2Proof
		break
	    }
	}
    }

    // 2.10
    // receive c_kw from proper node, MtA(k, w)    zk
    _,cherr = GetChannelValue(ch_t,w.bmkw)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetMKWTimeout)}
	ch <- res
	return ""
    }

    mkws := make([]string,ThresHold-1)
    if w.msg_mkw.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllMKWFail)}
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
		mtAZK2Proof := &lib.MtAZK2Proof{Z: z, ZBar: zbar, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}
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
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMKGFail)}
	    ch <- res
	    return ""
	}

	rlt112 := mkw_mtazk2[en[0]].MtAZK2Verify(ukc[cur_enode], mkw[en[0]], ukc3[cur_enode], zkfactproof[en[0]])
	if !rlt112 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("mkw mtazk2 verify fail.")}
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
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get sk fail.")}
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
     _,cherr = GetChannelValue(ch_t,w.bdelta1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all delta timeout.")}
	ch <- res
	return ""
    }
    
    var delta1s = make(map[string]*big.Int)
    delta1s[cur_enode] = delta1

    dels := make([]string,ThresHold-1)
    if w.msg_delta1.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all delta fail.")}
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
	    res := RpcDcrmRes{Ret:"",Err:ret2}
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
    _,cherr = GetChannelValue(ch_t,w.bd11_1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all c11 fail.")}
	ch <- res
	return ""
    }

    d11s := make([]string,ThresHold-1)
    if w.msg_d11_1.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all c11 fail.")}
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
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all c11 fail.")}
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
    var udecom = make(map[string]*lib.Commitment)
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
		deCommit := &lib.Commitment{C:new(big.Int).SetBytes([]byte(mm[2])), D:gg}
		udecom[prexs[len(prexs)-1]] = deCommit
		break
	    }
	}
    }
    deCommit_commitU1GammaG := &lib.Commitment{C: commitU1GammaG.C, D: commitU1GammaG.D}
    udecom[cur_enode] = deCommit_commitU1GammaG

    // for all nodes, verify the commitment
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	//bug
	if len(en) <= 0 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("verify commit fail.")}
	    ch <- res
	    return ""
	}
	_,exsit := udecom[en[0]]
	if exsit == false {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("verify commit fail.")}
	    ch <- res
	    return ""
	}
	//

	if udecom[en[0]].Verify() == false {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("verify commit fail.")}
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
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("r == 0.")}
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
    _,cherr = GetChannelValue(ch_t,w.bs1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get s1 timeout.")}
	ch <- res
	return ""
    }

    var s1s = make(map[string][]*big.Int)
    s1ss := []*big.Int{S1x,S1y}
    s1s[cur_enode] = s1ss

    us1s := make([]string,ThresHold-1)
    if w.msg_s1.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get s1 fail.")}
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
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("verify SAll != m*G + r*PK in sign ec2.")}
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
    _,cherr = GetChannelValue(ch_t,w.bss1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get ss1 timeout.")}
	ch <- res
	return ""
    }

    var ss1s = make(map[string]*big.Int)
    ss1s[cur_enode] = us1

    uss1s := make([]string,ThresHold-1)
    if w.msg_ss1.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get ss1 fail.")}
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
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("s == 0.")}
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
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("sign verify fail.")}
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

func GetPaillierPk(save string,index int) *lib.PublicKey {
    if save == "" || index < 0 {
	return nil
    }

    mm := strings.Split(save, SepSave)
    s := 4 + 4*index
    l := mm[s]
    n := new(big.Int).SetBytes([]byte(mm[s+1]))
    g := new(big.Int).SetBytes([]byte(mm[s+2]))
    n2 := new(big.Int).SetBytes([]byte(mm[s+3]))
    publicKey := &lib.PublicKey{Length: l, N: n, G: g, N2: n2}
    return publicKey
}

func GetPaillierSk(save string,index int) *lib.PrivateKey {
    publicKey := GetPaillierPk(save,index)
    if publicKey != nil {
	mm := strings.Split(save, SepSave)
	l := mm[1]
	ll := new(big.Int).SetBytes([]byte(mm[2]))
	uu := new(big.Int).SetBytes([]byte(mm[3]))
	privateKey := &lib.PrivateKey{Length: l, PublicKey: *publicKey, L: ll, U: uu}
	return privateKey
    }

    return nil
}

func GetZkFactProof(save string,index int) *lib.ZkFactProof {
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
    zkFactProof := &lib.ZkFactProof{H1: h1, H2: h2, Y: y, E: e,N: n}
    return zkFactProof
}

func SendMsgToDcrmGroup(msg string,groupid string) {
    BroadcastInGroupOthers(groupid,msg)
}

func SendMsgToPeer(enodes string,msg string) {
    SendToPeer(enodes,msg)
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

func DoubleHash(id string,keytype string) *big.Int {
    // Generate the random num

    // First, hash with the keccak256
    keccak256 := sha3.NewKeccak256()
    //keccak256.Write(rnd.Bytes())

    keccak256.Write([]byte(id))

    digestKeccak256 := keccak256.Sum(nil)

    //second, hash with the SHA3-256
    sha3256 := sha3.New256()

    sha3256.Write(digestKeccak256)

    digest := sha3256.Sum(nil)
    // convert the hash ([]byte) to big.Int
    digestBigInt := new(big.Int).SetBytes(digest)
    return digestBigInt
}

func GetRandomInt(length int) *big.Int {
	// NewInt allocates and returns a new Int set to x.
	one := big.NewInt(1)
	// Lsh sets z = x << n and returns z.
	maxi := new(big.Int).Lsh(one, uint(length))

	// TODO: Random Seed, need to be replace!!!
	// New returns a new Rand that uses random values from src to generate other random values.
	// NewSource returns a new pseudo-random Source seeded with the given value.
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	// Rand sets z to a pseudo-random number in [0, n) and returns z.
	rndNum := new(big.Int).Rand(rnd, maxi)
	return rndNum
}

func GetRandomIntFromZn(n *big.Int) *big.Int {
	var rndNumZn *big.Int
	zero := big.NewInt(0)

	for {
		rndNumZn = GetRandomInt(n.BitLen())
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
