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
    "math/big"
    "github.com/syndtr/goleveldb/leveldb"
    "github.com/fsn-dev/dcrm-sdk/crypto/secp256k1"
    "github.com/fsn-dev/dcrm-sdk/crypto/dcrm/dev/lib"
    "encoding/hex"
    "strconv"
    "strings"
)

//ec2
//msgprex = hash 
func dcrm_liloreqAddress(msgprex string,keytype string,ch chan interface{}) {

    fmt.Println("========dcrm_liloreqAddress============")
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

    ok := KeyGenerate_ec2(msgprex,ch,id,keytype)
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
    //write db
    dir := GetDbDir()
    db, err := leveldb.OpenFile(dir, nil) 
    if err != nil { 
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrCreateDbFail)}
	ch <- res
	lock.Unlock()
	return
    }

    pubkeyhex := hex.EncodeToString(ys)

    s := []string{string(ys),save} ////fusionaddr ??
    ss := strings.Join(s,Sep)
    db.Put(ys,[]byte(ss),nil)
    db.Close()
    lock.Unlock()
    res := RpcDcrmRes{Ret:pubkeyhex,Err:nil}
    ch <- res
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
    commitU1G := new(lib.Commitment).Commit(u1Gx, u1Gy)

    // 3. generate their own paillier public key and private key
    u1PaillierPk, u1PaillierSk := lib.GenerateKeyPair(PaillierKeyLength)

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

    u1PolyG, _, u1Shares, err := lib.Vss(u1, ids, ThresHold, NodeCnt)
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
	    uid := lib.GetSharesId(v)
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
    var sstruct = make(map[string]*lib.ShareStruct)
    for _,v := range shares {
	mm := strings.Split(v, Sep)
	t,_ := strconv.Atoi(mm[2])
	ushare := &lib.ShareStruct{T:t,Id:new(big.Int).SetBytes([]byte(mm[3])),Share:new(big.Int).SetBytes([]byte(mm[4]))}
	prex := mm[0]
	prexs := strings.Split(prex,"-")
	sstruct[prexs[len(prexs)-1]] = ushare
    }
    for _,v := range u1Shares {
	uid := lib.GetSharesId(v)
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

    var upg = make(map[string]*lib.PolyGStruct)
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
	ps := &lib.PolyGStruct{T:t,N:n,PolyG:pgss}
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

    var udecom = make(map[string]*lib.Commitment)
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
		deCommit := &lib.Commitment{C:new(big.Int).SetBytes([]byte(mm[2])), D:gg}
		udecom[prexs[len(prexs)-1]] = deCommit
		break
	    }
	}
    }
    deCommit_commitU1G := &lib.Commitment{C: commitU1G.C, D: commitU1G.D}
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
    u1zkUProof := lib.ZkUProve(u1)

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
//	log.Debug("get w.bzkfact timeout in keygenerate.")
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
//	log.Info("get w.bzku timeout in keygenerate.")
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
		zkFactProof := &lib.ZkFactProof{H1: h1, H2: h2, Y: y, E: e,N:n}
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
		zkUProof := &lib.ZkUProof{E: e, S: s}
		if !lib.ZkUVerify(ug[en[0]],zkUProof) {
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

