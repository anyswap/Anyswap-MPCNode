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
	"strconv"
	"strings"
	"time"

	"github.com/fsn-dev/dcrm-walletService/mpcdsa/crypto/ec2"
	"github.com/fsn-dev/dcrm-walletService/ethdb"
	"github.com/fsn-dev/dcrm-walletService/mpcdsa/ecdsa/keygen"
	"github.com/fsn-dev/dcrm-walletService/crypto/secp256k1"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	"github.com/fsn-dev/cryptoCoins/coins"
)

func GetReShareNonce(account string) (string, string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + "RESHARE"))).Hex()
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

func SetReShareNonce(account string,nonce string) (string, error) {
	key2 := Keccak256Hash([]byte(strings.ToLower(account + ":" + "RESHARE"))).Hex()
	kd := KeyData{Key: []byte(key2), Data: nonce}
	PubKeyDataChan <- kd
	LdbPubKeyData.WriteMap(key2, []byte(nonce))

	return "", nil
}

//param groupid is not subgroupid
//w.groupid is subgroupid
func reshare(wsid string, initator string, groupid string,pubkey string,account string,mode string,sigs string,ch chan interface{}) {

	rch := make(chan interface{}, 1)
	dcrm_reshare(wsid,initator,groupid,pubkey,account,mode,sigs,rch)
	ret, _, cherr := GetChannelValue(ch_t, rch)
	if ret != "" {
		w, err := FindWorker(wsid)
		if w == nil || err != nil {
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker", Err: fmt.Errorf("get worker error.")}
			ch <- res
			return
		}

		///////TODO tmp
		//sid-enode:SendReShareRes:Success:ret
		//sid-enode:SendReShareRes:Fail:err
		mp := []string{w.sid, cur_enode}
		enode := strings.Join(mp, "-")
		s0 := "SendReShareRes"
		s1 := "Success"
		s2 := ret
		ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
		SendMsgToDcrmGroup(ss, groupid)
		///////////////

		tip, reply := AcceptReShare("",initator, groupid,w.groupid,pubkey, w.limitnum, mode,"true", "true", "Success", ret, "", "", nil, w.id)
		if reply != nil {
			res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("update reshare status error.")}
			ch <- res
			return
		}

		common.Debug("================reshare,the terminal res is success=================","key",wsid)
		res := RpcDcrmRes{Ret: ret, Tip: tip, Err: err}
		ch <- res
		return
	}

	if cherr != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:reshare fail", Err: cherr}
		ch <- res
		return
	}
}

//ec2
//msgprex = hash
//return value is the backup for dcrm sig.
func dcrm_reshare(msgprex string, initator string, groupid string,pubkey string,account string,mode string,sigs string,ch chan interface{}) {

	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker", Err: fmt.Errorf("no find worker.")}
		ch <- res
		return
	}
	id := w.id

    var ch1 = make(chan interface{}, 1)
    for i:=0;i < recalc_times;i++ {
	if len(ch1) != 0 {
	    <-ch1
	}

	ReShare_ec2(msgprex, initator, groupid,pubkey, account,mode,sigs, ch1, id)
	ret, _, cherr := GetChannelValue(ch_t, ch1)
	if ret != "" && cherr == nil {
		res := RpcDcrmRes{Ret: ret, Tip: "", Err: cherr}
		ch <- res
		break
	}
	
	w.Clear2()
	time.Sleep(time.Duration(3) * time.Second) //1000 == 1s
    }
}

//msgprex = hash
//return value is the backup for the dcrm sig
func ReShare_ec2(msgprex string, initator string, groupid string,pubkey string, account string,mode string,sigs string,ch chan interface{}, id int) {
	if id < 0 || id >= len(workers) {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("no find worker.")}
		ch <- res
		return
	}
	w := workers[id]
	if w.groupid == "" {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get group id fail.")}
		ch <- res
		return
	}

	// [Notes]
	// 1. assume the nodes who take part in the signature generation as follows
	ids := GetIds("ALL", w.groupid)
	if len(ids) < w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("calc ids fail")}
		ch <- res
		return
	}

	idSign := ids[:w.ThresHold]

	take_reshare := true
	var skU1 *big.Int
	var w1 *big.Int

	dcrmpks, _ := hex.DecodeString(pubkey)
	///sku1
	da := GetSkU1FromLocalDb(string(dcrmpks[:]))
	if da == nil {
	    common.Debug("=====================ReShare_ec2,da is nil =====================","key",msgprex)
	    take_reshare = false
	    skU1 = nil
	    w1 = nil
	} else {
	    skU1 = new(big.Int).SetBytes(da)
	    if skU1 == nil {
		take_reshare = false
		w1 = nil
	    } else {
		skU1, w1 = MapPrivKeyShare("ALL", w, idSign, string(skU1.Bytes()))
	    }
	}

	//*******************!!!Distributed ECDSA Sign Start!!!**********************************

	if !take_reshare || skU1 == nil || w1 == nil {
	    ////////test reshare///////////////////////
	    ids = GetIds("ALL", groupid)
	    common.Debug("=============ReShare_ec2,cur node not take part in reshare==============","gid",groupid,"ids",ids,"key",msgprex)
	    
	    _, tip, cherr := GetChannelValue(120, w.bc11)
	    suss := false
	    if cherr != nil {
		suss = ReqDataFromGroup(msgprex,w.id,"C11",reqdata_trytimes,reqdata_timeout)
	    } else {
		suss = true
	    }
	    if !suss {
		    res := RpcDcrmRes{Ret: "", Tip: tip, Err: GetRetErr(ErrGetC11Timeout)}
		    ch <- res
		    return
	    }

	    _, tip, cherr = GetChannelValue(120, w.bss1)
	    if cherr != nil {
		suss = ReqDataFromGroup(msgprex,w.id,"SS1",reqdata_trytimes,reqdata_timeout)
	    } else {
		suss = true
	    }
	    if !suss {
		    res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ss1 timeout")}
		    ch <- res
		    return
	    }

	    _, tip, cherr = GetChannelValue(120, w.bd11_1)
	    if cherr != nil {
		suss = ReqDataFromGroup(msgprex,w.id,"D11",reqdata_trytimes,reqdata_timeout)
	    } else {
		suss = true
	    }
	    if !suss {
		    res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get d11 timeout")}
		    ch <- res
		    return
	    }

	    ss1s2 := make([]string, w.ThresHold)
	    if w.msg_ss1.Len() != w.ThresHold {
		    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all ss1 fail.")}
		    ch <- res
		    return
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
		    return
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
			    return
		    }

		    prex := mm[0]
		    prexs := strings.Split(prex, "-")
		    for _, vv := range ss1s2 {
			    mmm := strings.Split(vv, common.Sep)
			    if len(mmm) < 3 {
				    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_ss1 fail.")}
				    ch <- res
				    return
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
						    return 
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
		    enodes := GetEnodesByUid(id, "ALL", w.groupid)
		    ////////bug
		    if len(enodes) < 9 {
			    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			    ch <- res
			    return 
		    }
		    ////////
		    en := strings.Split(string(enodes[8:]), "@")
		    //bug
		    if len(en) <= 0 || en[0] == "" {
			    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			    ch <- res
			    return
		    }

		    _, exsit := udecom[en[0]]
		    if !exsit {
			    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			    ch <- res
			    return
		    }
		    //

		    if udecom[en[0]] == nil {
			    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			    ch <- res
			    return
		    }

		    if !keygen.DECDSA_Key_Commitment_Verify(udecom[en[0]]) {
			    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			    ch <- res
			    return
		    }
	    }

	    var sstruct = make(map[string]*ec2.ShareStruct2)
	    shares := make([]string, w.ThresHold)
	    if w.msg_d11_1.Len() != w.ThresHold {
		    res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetAllSHARE1Fail)}
		    ch <- res
		    return
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
			    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("fill ec2.ShareStruct map error.")}
			    ch <- res
			    return
		    }
		    //
		    ushare := &ec2.ShareStruct2{Id: new(big.Int).SetBytes([]byte(mm[2])), Share: new(big.Int).SetBytes([]byte(mm[3]))}
		    prex := mm[0]
		    prexs := strings.Split(prex, "-")
		    sstruct[prexs[len(prexs)-1]] = ushare
	    }

	    var upg = make(map[string]*ec2.PolyGStruct2)
	    for _, v := range ss1s2 {
		    mm := strings.Split(v, common.Sep)
		    dlen, _ := strconv.Atoi(mm[2])
		    if len(mm) < (4 + dlen) {
			    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_ss1 data error")}
			    ch <- res
			    return 
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
				    return
			    }

			    gg = append(gg, new(big.Int).SetBytes([]byte(mm[3+dlen+l])))
			    l++
			    if len(mm) < (4 + dlen + l) {
				    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_ss1 data error")}
				    ch <- res
				    return
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
		    enodes := GetEnodesByUid(id, "ALL", w.groupid)
		    en := strings.Split(string(enodes[8:]), "@")
		    //bug
		    if len(en) == 0 || en[0] == "" || sstruct[en[0]] == nil || upg[en[0]] == nil {
			    res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifySHARE1Fail)}
			    ch <- res
			    return 
		    }
		    //
		    if !keygen.DECDSA_Key_Verify_Share(sstruct[en[0]], upg[en[0]]) {
			    res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifySHARE1Fail)}
			    ch <- res
			    return
		    }
	    }

	    // for all nodes, de-commitment
	    var ug = make(map[string][]*big.Int)
	    for _, id := range idSign {
		    enodes := GetEnodesByUid(id, "ALL", w.groupid)
		    en := strings.Split(string(enodes[8:]), "@")
		    _, u1G := udecom[en[0]].DeCommit()
		    ug[en[0]] = u1G
	    }

	    // for all nodes, calculate the public key
	    var pkx *big.Int
	    var pky *big.Int
	    for _, id := range idSign {
		    enodes := GetEnodesByUid(id, "ALL", w.groupid)
		    en := strings.Split(string(enodes[8:]), "@")
		    pkx = (ug[en[0]])[0]
		    pky = (ug[en[0]])[1]
		    break
	    }

	    for k, id := range idSign {
		    if k == 0 {
			    continue
		    }

		    enodes := GetEnodesByUid(id, "ALL", w.groupid)
		    en := strings.Split(string(enodes[8:]), "@")
		    pkx, pky = secp256k1.S256().Add(pkx, pky, (ug[en[0]])[0], (ug[en[0]])[1])
	    }
	    ys := secp256k1.S256().Marshal(pkx, pky)
	    pubkeyhex := hex.EncodeToString(ys)
	    if !strings.EqualFold(pubkey,pubkeyhex) {
		common.Debug("=====================ReShare_ec2, reshare fail,new pubkey != old pubkey====================","old pubkey",pubkey,"new pubkey",pubkeyhex,"key",msgprex)
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("reshare fail,new pubkey != old pubkey")}
		ch <- res
		return 
	    }

	    var newskU1 *big.Int
	    for _, id := range idSign {
		    enodes := GetEnodesByUid(id, "ALL", w.groupid)
		    en := strings.Split(string(enodes[8:]), "@")
		    newskU1 = sstruct[en[0]].Share
		    break
	    }

	    for k, id := range idSign {
		    if k == 0 {
			    continue
		    }

		    enodes := GetEnodesByUid(id, "ALL", w.groupid)
		    en := strings.Split(string(enodes[8:]), "@")
		    newskU1 = new(big.Int).Add(newskU1, sstruct[en[0]].Share)
	    }
	    newskU1 = new(big.Int).Mod(newskU1, secp256k1.S256().N)

	    //set new sk
	    dir := GetSkU1Dir()
	    dbsktmp, err := ethdb.NewLDBDatabase(dir, cache, handles)
	    //bug
	    if err != nil {
		    for i := 0; i < 100; i++ {
			    dbsktmp, err = ethdb.NewLDBDatabase(dir, cache, handles)
			    if err == nil {
				    break
			    }

			    time.Sleep(time.Duration(1000000))
		    }
	    }
	    if err != nil {
		//dbsk = nil
	    } else {
		dbsk = dbsktmp
	    }

	    sk := KeyData{Key: dcrmpks[:], Data: string(newskU1.Bytes())}
	    SkU1Chan <- sk

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

		    key := Keccak256Hash([]byte(strings.ToLower(ctaddr))).Hex()
		    sk = KeyData{Key: []byte(key), Data: string(newskU1.Bytes())}
		    SkU1Chan <- sk
	    }
	    //
	    
	    ///////gen paillier key
	    u1PaillierPk, u1PaillierSk := ec2.GenerateKeyPair(PaillierKeyLength)
	    mp := []string{msgprex, cur_enode}
	    enode := strings.Join(mp, "-")
	    s0 := "PaillierKey"
	    s1 := u1PaillierPk.Length
	    s2 := string(u1PaillierPk.N.Bytes())
	    s3 := string(u1PaillierPk.G.Bytes())
	    s4 := string(u1PaillierPk.N2.Bytes())
	    ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2 + common.Sep + s3 + common.Sep + s4
	    SendMsgToDcrmGroup(ss, groupid)
	    DisMsg(ss)

	    _, _, cherr = GetChannelValue(120, w.bpaillierkey)
	    if cherr != nil {
		suss = ReqDataFromGroup(msgprex,w.id,"PaillierKey",reqdata_trytimes,reqdata_timeout)
	    } else {
		suss = true
	    }

	    if !suss {
		    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get paillier key fail")}
		    ch <- res
		    return 
	    }

	    NtildeLength := 2048
	    // for u1
	    u1NtildeH1H2 := keygen.DECDSA_Key_GenerateNtildeH1H2(NtildeLength)
	    if u1NtildeH1H2 == nil {
		    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("gen ntilde h1 h2 fail.")}
		    ch <- res
		    return
	    }

	    // 7. Broadcast ntilde
	    mp = []string{msgprex, cur_enode}
	    enode = strings.Join(mp, "-")
	    s0 = "NTILDEH1H2" //delete zkfactor add ntild h1 h2
	    s1 = string(u1NtildeH1H2.Ntilde.Bytes())
	    s2 = string(u1NtildeH1H2.H1.Bytes())
	    s3 = string(u1NtildeH1H2.H2.Bytes())
	    ss = enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2 + common.Sep + s3
	    SendMsgToDcrmGroup(ss, groupid)
	    DisMsg(ss)
	    _, _, cherr = GetChannelValue(120, w.bzkfact)
	    if cherr != nil {
		suss = ReqDataFromGroup(msgprex,w.id,"NTILDEH1H2",reqdata_trytimes,reqdata_timeout)
	    } else {
		suss = true
	    }
	    
	    if !suss {
		    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get NTILDEH1H2 fail")}
		    ch <- res
		    return
	    }

	    ids = GetIds("ALL", groupid)
	    sstmp := "XXX"
	    sstmp = sstmp + common.SepSave
	    s1 = u1PaillierSk.Length
	    s2 = string(u1PaillierSk.L.Bytes())
	    s3 = string(u1PaillierSk.U.Bytes())
	    sstmp = sstmp + s1 + common.SepSave + s2 + common.SepSave + s3 + common.SepSave
	    for _, id := range ids {
		    enodes := GetEnodesByUid(id, "ALL", groupid)
		    en := strings.Split(string(enodes[8:]), "@")

		    if enodes == "" {
			    res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetEnodeByUIdFail)}
			    ch <- res
			    return 
		    }

		    if IsCurNode(enodes, cur_enode) {
			s1 = u1PaillierPk.Length
			s2 = string(u1PaillierPk.N.Bytes())
			s3 = string(u1PaillierPk.G.Bytes())
			s4 := string(u1PaillierPk.N2.Bytes())
			sstmp = sstmp + s1 + common.SepSave + s2 + common.SepSave + s3 + common.SepSave + s4 + common.SepSave
			continue
		    }

		    iter := w.msg_paillierkey.Front() //////by type
		    for iter != nil {
			if iter.Value == nil {
			    iter = iter.Next()
			    continue
			}

			mdss,ok := iter.Value.(string)
			if !ok {
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
			if strings.EqualFold(node3,en[0]) {
			    s1 = ms[2]
			    s2 = ms[3]
			    s3 = ms[4]
			    s4 := ms[5]
			    sstmp = sstmp + s1 + common.SepSave + s2 + common.SepSave + s3 + common.SepSave + s4 + common.SepSave
			    break
			}

			iter = iter.Next()
		    }
	    }

	    for _, id := range ids {
		    enodes := GetEnodesByUid(id, "ALL", groupid)
		    en := strings.Split(string(enodes[8:]), "@")

		    if enodes == "" {
			    res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetEnodeByUIdFail)}
			    ch <- res
			    return 
		    }

		    if IsCurNode(enodes, cur_enode) {
			s1 = string(u1NtildeH1H2.Ntilde.Bytes())
			s2 = string(u1NtildeH1H2.H1.Bytes())
			s3 = string(u1NtildeH1H2.H2.Bytes())
			sstmp = sstmp + s1 + common.SepSave + s2 + common.SepSave + s3 + common.SepSave
			continue
		    }

		    iter := w.msg_zkfact.Front() //////by type
		    for iter != nil {
			if iter.Value == nil {
			    iter = iter.Next()
			    continue
			}

			mdss,ok := iter.Value.(string)
			if !ok {
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
			if strings.EqualFold(node3,en[0]) {
			    sstmp = sstmp + ms[2] + common.SepSave + ms[3] + common.SepSave + ms[4] + common.SepSave //for ntilde
			    break
			}

			iter = iter.Next()
		    }
	    }
	    
	    sstmp = sstmp + "NULL"
	    
	    dir = GetDbDir()
	    dbtmp, err := ethdb.NewLDBDatabase(dir, cache, handles)
	    //bug
	    if err != nil {
		    for i := 0; i < 100; i++ {
			    dbtmp, err = ethdb.NewLDBDatabase(dir, cache, handles)
			    if err == nil {
				    break
			    }

			    time.Sleep(time.Duration(1000000))
		    }
	    }
	    if err != nil {
		//dbsk = nil
	    } else {
		db = dbtmp
	    }

	    nonce,_,err := GetReqAddrNonce(account) //reqaddr nonce
	    if err != nil {
		nonce = "0"
	    }

	    rk := Keccak256Hash([]byte(strings.ToLower(account + ":" + "ALL" + ":" + groupid + ":" + nonce + ":" + w.limitnum + ":" + mode))).Hex() //reqaddr key
	    tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
	    pubs := &PubKeyData{Key:rk,Account:account, Pub: string(dcrmpks[:]), Save: sstmp, Nonce: nonce, GroupId: groupid, LimitNum: w.limitnum, Mode: mode,KeyGenTime:tt,RefReShareKeys:msgprex}
	    epubs, err := Encode2(pubs)
	    if err != nil {
		    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:encode PubKeyData fail in req ec2 pubkey", Err: err}
		    ch <- res
		    return
	    }

	    ss1, err := Compress([]byte(epubs))
	    if err != nil {
		    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:compress PubKeyData fail in req ec2 pubkey", Err: err}
		    ch <- res
		    return
	    }

	    exsit,pda := GetPubKeyDataFromLocalDb(string(dcrmpks[:]))
	    if exsit {
		daa,ok := pda.(*PubKeyData)
		if ok {
		    //check mode
		    if daa.Mode != mode {
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:check mode fail", Err: fmt.Errorf("check mode fail")}
			ch <- res
			return
		    }
		    //

		    //check account
		    if !strings.EqualFold(account, daa.Account) {
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:check account fail", Err: fmt.Errorf("check account fail")}
			ch <- res
			return
		    }
		    //

		    go LdbPubKeyData.DeleteMap(daa.Key)
		    kd := KeyData{Key: []byte(daa.Key), Data: "CLEAN"}
		    PubKeyDataChan <- kd
		}
	    }
	    
	    kd := KeyData{Key: dcrmpks[:], Data: ss1}
	    PubKeyDataChan <- kd
	    /////
	    LdbPubKeyData.WriteMap(string(dcrmpks[:]), pubs)
	    ////
	    for _, ct := range coins.Cointypes {
		    if strings.EqualFold(ct, "ALL") {
			    continue
		    }

		    h := coins.NewCryptocoinHandler(ct)
		    if h == nil {
			    continue
		    }
		    ctaddr, err := h.PublicKeyToAddress(pubkey)
		    if err != nil {
			    continue
		    }

		    key := Keccak256Hash([]byte(strings.ToLower(ctaddr))).Hex()
		    kd = KeyData{Key: []byte(key), Data: ss1}
		    PubKeyDataChan <- kd
		    /////
		    LdbPubKeyData.WriteMap(key, pubs)
		    ////
	    }
	    
	    _,err = SetReqAddrNonce(account,nonce)
	    if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:set reqaddr nonce fail", Err: fmt.Errorf("set reqaddr nonce fail")}
		ch <- res
		return
	    }

	    wid := -1
	    var allreply []NodeReply
	    exsit,da2 := GetValueFromPubKeyData(msgprex)
	    if exsit {
		acr,ok := da2.(*AcceptReShareData)
		if ok {
		    wid = acr.WorkId
		    allreply = acr.AllReply
		}
	    }

	    //ars := GetAllReplyFromGroup(-1,groupid,Rpc_REQADDR,cur_enode)
	    ac := &AcceptReqAddrData{Initiator:cur_enode,Account: account, Cointype: "ALL", GroupId: groupid, Nonce: nonce, LimitNum: w.limitnum, Mode: mode, TimeStamp: tt, Deal: "true", Accept: "true", Status: "Success", PubKey: pubkey, Tip: "", Error: "", AllReply: allreply, WorkId: wid,Sigs:sigs}
	    err = SaveAcceptReqAddrData(ac)
	    if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:save reqaddr accept data fail", Err: fmt.Errorf("save reqaddr accept data fail")}
		ch <- res
		return
	    }

	    if mode == "0" {
		sigs2 := strings.Split(ac.Sigs,common.Sep)
		cnt,_ := strconv.Atoi(sigs2[0])
		for j := 0;j<cnt;j++ {
		    fr := sigs2[2*j+2]
		    exsit,da := GetValueFromPubKeyData(strings.ToLower(fr))
		    if !exsit {
			kdtmp := KeyData{Key: []byte(strings.ToLower(fr)), Data: rk}
			PubKeyDataChan <- kdtmp
			LdbPubKeyData.WriteMap(strings.ToLower(fr), []byte(rk))
		    } else {
			//
			found := false
			keys := strings.Split(string(da.([]byte)),":")
			for _,v := range keys {
			    if strings.EqualFold(v,rk) {
				found = true
				break
			    }
			}
			//

			if !found {
			    da2 := string(da.([]byte)) + ":" + rk
			    kdtmp := KeyData{Key: []byte(strings.ToLower(fr)), Data: da2}
			    PubKeyDataChan <- kdtmp
			    LdbPubKeyData.WriteMap(strings.ToLower(fr), []byte(da2))
			}
		    }
		}
	    } else {
		exsit,da := GetValueFromPubKeyData(strings.ToLower(account))
		if !exsit {
		    kdtmp := KeyData{Key: []byte(strings.ToLower(account)), Data: rk}
		    PubKeyDataChan <- kdtmp
		    LdbPubKeyData.WriteMap(strings.ToLower(account), []byte(rk))
		} else {
		    //
		    found := false
		    keys := strings.Split(string(da.([]byte)),":")
		    for _,v := range keys {
			if strings.EqualFold(v,rk) {
			    found = true
			    break
			}
		    }
		    //

		    if !found {
			da2 := string(da.([]byte)) + ":" + rk
			kdtmp := KeyData{Key: []byte(strings.ToLower(account)), Data: da2}
			PubKeyDataChan <- kdtmp
			LdbPubKeyData.WriteMap(strings.ToLower(account), []byte(da2))
		    }

		}
	    }
	    //AcceptReqAddr("",account, "ALL", groupid, nonce, w.limitnum, mode, "true", "true", "Success", pubkey, "", "", nil, w.id,"")
	    /////////////////////
	    common.Debug("=====================ReShare_ec2====================","gen newsku1",newskU1,"key",msgprex)

	    res := RpcDcrmRes{Ret: fmt.Sprintf("%v",newskU1), Err: nil}
	    ch <- res
	    return
	}

	/////////test reshare //////////
	skP1Poly, skP1PolyG, _ := ec2.Vss2Init(w1, w.ThresHold)
	skP1Gx, skP1Gy := secp256k1.S256().ScalarBaseMult(w1.Bytes())
	u1CommitValues := make([]*big.Int, 0)
	u1CommitValues = append(u1CommitValues, skP1Gx)
	u1CommitValues = append(u1CommitValues, skP1Gy)
	for i := 1; i < len(skP1PolyG.PolyG); i++ {
		u1CommitValues = append(u1CommitValues, skP1PolyG.PolyG[i][0])
		u1CommitValues = append(u1CommitValues, skP1PolyG.PolyG[i][1])
	}
	commitSkP1G := new(ec2.Commitment).Commit(u1CommitValues...)

	ids = GetIds("ALL", groupid)

	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "C11"
	s1 := string(commitSkP1G.C.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToDcrmGroup(ss, groupid)
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
		return 
	}

	skP1Shares, err := keygen.DECDSA_Key_Vss(skP1Poly, ids)
	if err != nil {
		res := RpcDcrmRes{Ret: "", Err: err}
		ch <- res
		return 
	}

	for _, id := range ids {
		enodes := GetEnodesByUid(id, "ALL", groupid)

		if enodes == "" {
			res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetEnodeByUIdFail)}
			ch <- res
			return 
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
				break
			}
		}
	}

	for _, v := range skP1Shares {
		uid := keygen.DECDSA_Key_GetSharesId(v)
		if uid == nil {
			continue
		}

		enodes := GetEnodesByUid(uid, "ALL", groupid)
		if IsCurNode(enodes, cur_enode) {
			mp := []string{msgprex, cur_enode}
			enode := strings.Join(mp, "-")
			s0 := "D11"
			s2 := string(v.Id.Bytes())
			s3 := string(v.Share.Bytes())
			ss := enode + common.Sep + s0 + common.Sep + s2 + common.Sep + s3
			DisMsg(ss)
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
	SendMsgToDcrmGroup(ss, groupid)
	DisMsg(ss)
	
	_, tip, cherr = GetChannelValue(ch_t, w.bss1)
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"SS1",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ss1 timeout")}
		ch <- res
		return
	}

	_, tip, cherr = GetChannelValue(ch_t, w.bd11_1)
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"D11",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get d11 timeout")}
		ch <- res
		return 
	}

	ss1s2 := make([]string, w.ThresHold)
	if w.msg_ss1.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all ss1 fail.")}
		ch <- res
		return
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
		return
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
			return
		}

		prex := mm[0]
		prexs := strings.Split(prex, "-")
		for _, vv := range ss1s2 {
			mmm := strings.Split(vv, common.Sep)
			if len(mmm) < 3 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_ss1 fail.")}
				ch <- res
				return
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
						return
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
		enodes := GetEnodesByUid(id, "ALL", w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return 
		}
		////////
		en := strings.Split(string(enodes[8:]), "@")
		//bug
		if len(en) <= 0 || en[0] == "" {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			ch <- res
			return 
		}

		_, exsit := udecom[en[0]]
		if !exsit {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			ch <- res
			return 
		}
		//

		if udecom[en[0]] == nil {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			ch <- res
			return 
		}

		if !keygen.DECDSA_Key_Commitment_Verify(udecom[en[0]]) {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			ch <- res
			return 
		}
	}

	var sstruct = make(map[string]*ec2.ShareStruct2)
	shares := make([]string, w.ThresHold)
	if w.msg_d11_1.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetAllSHARE1Fail)}
		ch <- res
		return
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
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("fill ec2.ShareStruct map error.")}
			ch <- res
			return 
		}
		//
		ushare := &ec2.ShareStruct2{Id: new(big.Int).SetBytes([]byte(mm[2])), Share: new(big.Int).SetBytes([]byte(mm[3]))}
		prex := mm[0]
		prexs := strings.Split(prex, "-")
		sstruct[prexs[len(prexs)-1]] = ushare
	}

	var upg = make(map[string]*ec2.PolyGStruct2)
	for _, v := range ss1s2 {
		mm := strings.Split(v, common.Sep)
		dlen, _ := strconv.Atoi(mm[2])
		if len(mm) < (4 + dlen) {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_ss1 data error")}
			ch <- res
			return 
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
				return 
			}

			gg = append(gg, new(big.Int).SetBytes([]byte(mm[3+dlen+l])))
			l++
			if len(mm) < (4 + dlen + l) {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_ss1 data error")}
				ch <- res
				return 
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
		enodes := GetEnodesByUid(id, "ALL", w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		//bug
		if len(en) == 0 || en[0] == "" || sstruct[en[0]] == nil || upg[en[0]] == nil {
			res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifySHARE1Fail)}
			ch <- res
			return
		}
		//
		if !keygen.DECDSA_Key_Verify_Share(sstruct[en[0]], upg[en[0]]) {
			res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifySHARE1Fail)}
			ch <- res
			return 
		}
	}

	// for all nodes, de-commitment
	var ug = make(map[string][]*big.Int)
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, "ALL", w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		_, u1G := udecom[en[0]].DeCommit()
		ug[en[0]] = u1G
	}

	// for all nodes, calculate the public key
	var pkx *big.Int
	var pky *big.Int
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, "ALL", w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		pkx = (ug[en[0]])[0]
		pky = (ug[en[0]])[1]
		break
	}

	for k, id := range idSign {
		if k == 0 {
			continue
		}

		enodes := GetEnodesByUid(id, "ALL", w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		pkx, pky = secp256k1.S256().Add(pkx, pky, (ug[en[0]])[0], (ug[en[0]])[1])
	}
	ys := secp256k1.S256().Marshal(pkx, pky)
	pubkeyhex := hex.EncodeToString(ys)
	if !strings.EqualFold(pubkey,pubkeyhex) {
	    common.Debug("=====================ReShare_ec2, reshare fail,new pubkey != old pubkey====================","old pubkey",pubkey,"new pubkey",pubkeyhex,"key",msgprex)
	    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("reshare fail,new pubkey != old pubkey")}
	    ch <- res
	    return 
	}

	//gen new sku1
	var newskU1 *big.Int
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, "ALL", w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		newskU1 = sstruct[en[0]].Share
		break
	}

	for k, id := range idSign {
		if k == 0 {
			continue
		}

		enodes := GetEnodesByUid(id, "ALL", w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		newskU1 = new(big.Int).Add(newskU1, sstruct[en[0]].Share)
	}
	newskU1 = new(big.Int).Mod(newskU1, secp256k1.S256().N)
	
	//set new sk
	dir := GetSkU1Dir()
	dbsktmp, err := ethdb.NewLDBDatabase(dir, cache, handles)
	//bug
	if err != nil {
		for i := 0; i < 100; i++ {
			dbsktmp, err = ethdb.NewLDBDatabase(dir, cache, handles)
			if err == nil {
				break
			}

			time.Sleep(time.Duration(1000000))
		}
	}
	if err != nil {
	    //dbsk = nil
	} else {
	    dbsk = dbsktmp
	}

	sk := KeyData{Key: dcrmpks[:], Data: string(newskU1.Bytes())}
	SkU1Chan <- sk

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

		key := Keccak256Hash([]byte(strings.ToLower(ctaddr))).Hex()
		sk = KeyData{Key: []byte(key), Data: string(newskU1.Bytes())}
		SkU1Chan <- sk
	}
	//

	///////gen paillier key
	u1PaillierPk, u1PaillierSk := ec2.GenerateKeyPair(PaillierKeyLength)
	mp = []string{msgprex, cur_enode}
	enode = strings.Join(mp, "-")
	s0 = "PaillierKey"
	s1 = u1PaillierPk.Length
	s2 := string(u1PaillierPk.N.Bytes())
	s3 := string(u1PaillierPk.G.Bytes())
	s4 = string(u1PaillierPk.N2.Bytes())
	ss = enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2 + common.Sep + s3 + common.Sep + s4
	SendMsgToDcrmGroup(ss, groupid)
	DisMsg(ss)

	_, _, cherr = GetChannelValue(120, w.bpaillierkey)
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"PaillierKey",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}

	if !suss {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get paillier key fail")}
		ch <- res
		return 
	}

	NtildeLength := 2048
	// for u1
	u1NtildeH1H2 := keygen.DECDSA_Key_GenerateNtildeH1H2(NtildeLength)
	if u1NtildeH1H2 == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("gen ntilde h1 h2 fail.")}
		ch <- res
		return
	}

	// 7. Broadcast ntilde
	mp = []string{msgprex, cur_enode}
	enode = strings.Join(mp, "-")
	s0 = "NTILDEH1H2" //delete zkfactor add ntild h1 h2
	s1 = string(u1NtildeH1H2.Ntilde.Bytes())
	s2 = string(u1NtildeH1H2.H1.Bytes())
	s3 = string(u1NtildeH1H2.H2.Bytes())
	ss = enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2 + common.Sep + s3
	SendMsgToDcrmGroup(ss, groupid)
	DisMsg(ss)
	_, _, cherr = GetChannelValue(120, w.bzkfact)
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"NTILDEH1H2",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	
	if !suss {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get NTILDEH1H2 fail")}
		ch <- res
		return
	}

	sstmp := "XXX"
	sstmp = sstmp + common.SepSave
	s1 = u1PaillierSk.Length
	s2 = string(u1PaillierSk.L.Bytes())
	s3 = string(u1PaillierSk.U.Bytes())
	sstmp = sstmp + s1 + common.SepSave + s2 + common.SepSave + s3 + common.SepSave
	for _, id := range ids {
		enodes := GetEnodesByUid(id, "ALL", groupid)
		en := strings.Split(string(enodes[8:]), "@")

		if enodes == "" {
			res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetEnodeByUIdFail)}
			ch <- res
			return 
		}

		if IsCurNode(enodes, cur_enode) {
		    s1 = u1PaillierPk.Length
		    s2 = string(u1PaillierPk.N.Bytes())
		    s3 = string(u1PaillierPk.G.Bytes())
		    s4 := string(u1PaillierPk.N2.Bytes())
		    sstmp = sstmp + s1 + common.SepSave + s2 + common.SepSave + s3 + common.SepSave + s4 + common.SepSave
		    continue
		}

		iter := w.msg_paillierkey.Front() //////by type
		for iter != nil {
		    if iter.Value == nil {
			iter = iter.Next()
			continue
		    }

		    mdss,ok := iter.Value.(string)
		    if !ok {
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
		    if strings.EqualFold(node3,en[0]) {
			s1 = ms[2]
			s2 = ms[3]
			s3 = ms[4]
			s4 := ms[5]
			sstmp = sstmp + s1 + common.SepSave + s2 + common.SepSave + s3 + common.SepSave + s4 + common.SepSave
			break
		    }

		    iter = iter.Next()
		}
	}

	for _, id := range ids {
		enodes := GetEnodesByUid(id, "ALL", groupid)
		en := strings.Split(string(enodes[8:]), "@")

		if enodes == "" {
			res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetEnodeByUIdFail)}
			ch <- res
			return 
		}

		if IsCurNode(enodes, cur_enode) {
		    s1 = string(u1NtildeH1H2.Ntilde.Bytes())
		    s2 = string(u1NtildeH1H2.H1.Bytes())
		    s3 = string(u1NtildeH1H2.H2.Bytes())
		    sstmp = sstmp + s1 + common.SepSave + s2 + common.SepSave + s3 + common.SepSave
		    continue
		}

		iter := w.msg_zkfact.Front() //////by type
		for iter != nil {
		    if iter.Value == nil {
			iter = iter.Next()
			continue
		    }

		    mdss,ok := iter.Value.(string)
		    if !ok {
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
		    if strings.EqualFold(node3,en[0]) {
			sstmp = sstmp + ms[2] + common.SepSave + ms[3] + common.SepSave + ms[4] + common.SepSave //for ntilde
			break
		    }

		    iter = iter.Next()
		}
	}
	
	sstmp = sstmp + "NULL"
	
	dir = GetDbDir()
	dbtmp, err := ethdb.NewLDBDatabase(dir, cache, handles)
	//bug
	if err != nil {
		for i := 0; i < 100; i++ {
			dbtmp, err = ethdb.NewLDBDatabase(dir, cache, handles)
			if err == nil {
				break
			}

			time.Sleep(time.Duration(1000000))
		}
	}
	if err != nil {
	    //dbsk = nil
	} else {
	    db = dbtmp
	}

	nonce,_,err := GetReqAddrNonce(account) //reqaddr nonce
	if err != nil {
	    nonce = "0"
	}

	rk := Keccak256Hash([]byte(strings.ToLower(account + ":" + "ALL" + ":" + groupid + ":" + nonce + ":" + w.limitnum + ":" + mode))).Hex() //reqaddr key
	tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
	pubs := &PubKeyData{Key:rk,Account:account, Pub: string(dcrmpks[:]), Save: sstmp, Nonce: nonce, GroupId: groupid, LimitNum: w.limitnum, Mode: mode,KeyGenTime:tt,RefReShareKeys:msgprex}
	epubs, err := Encode2(pubs)
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:encode PubKeyData fail in req ec2 pubkey", Err: err}
		ch <- res
		return
	}

	ss1, err := Compress([]byte(epubs))
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:compress PubKeyData fail in req ec2 pubkey", Err: err}
		ch <- res
		return
	}

	exsit,pda := GetPubKeyDataFromLocalDb(string(dcrmpks[:]))
	if exsit {
	    daa,ok := pda.(*PubKeyData)
	    if ok {
		//check mode
		if daa.Mode != mode {
		    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:check mode fail", Err: fmt.Errorf("check mode fail")}
		    ch <- res
		    return
		}
		//

		//check account
		if !strings.EqualFold(account, daa.Account) {
		    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:check account fail", Err: fmt.Errorf("check account fail")}
		    ch <- res
		    return
		}
		//

		go LdbPubKeyData.DeleteMap(daa.Key)
		kd := KeyData{Key: []byte(daa.Key), Data: "CLEAN"}
		PubKeyDataChan <- kd
	    }
	}
	
	kd := KeyData{Key: dcrmpks[:], Data: ss1}
	PubKeyDataChan <- kd
	/////
	LdbPubKeyData.WriteMap(string(dcrmpks[:]), pubs)
	////
	for _, ct := range coins.Cointypes {
		if strings.EqualFold(ct, "ALL") {
			continue
		}

		h := coins.NewCryptocoinHandler(ct)
		if h == nil {
			continue
		}
		ctaddr, err := h.PublicKeyToAddress(pubkey)
		if err != nil {
			continue
		}

		key := Keccak256Hash([]byte(strings.ToLower(ctaddr))).Hex()
		kd = KeyData{Key: []byte(key), Data: ss1}
		PubKeyDataChan <- kd
		/////
		LdbPubKeyData.WriteMap(key, pubs)
		////
	}
	
	_,err = SetReqAddrNonce(account,nonce)
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:set reqaddr nonce fail", Err: fmt.Errorf("set reqaddr nonce fail")}
	    ch <- res
	    return
	}

	wid := -1
	var allreply []NodeReply
	exsit,da2 := GetValueFromPubKeyData(msgprex)
	if exsit {
	    acr,ok := da2.(*AcceptReShareData)
	    if ok {
		wid = acr.WorkId
		allreply = acr.AllReply
	    }
	}

	//ars := GetAllReplyFromGroup(-1,groupid,Rpc_REQADDR,cur_enode)
	ac := &AcceptReqAddrData{Initiator:cur_enode,Account: account, Cointype: "ALL", GroupId: groupid, Nonce: nonce, LimitNum: w.limitnum, Mode: mode, TimeStamp: tt, Deal: "true", Accept: "true", Status: "Success", PubKey: pubkey, Tip: "", Error: "", AllReply: allreply, WorkId: wid,Sigs:sigs}
	err = SaveAcceptReqAddrData(ac)
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:save reqaddr accept data fail", Err: fmt.Errorf("save reqaddr accept data fail")}
	    ch <- res
	    return
	}

	if mode == "0" {
	    sigs2 := strings.Split(ac.Sigs,common.Sep)
	    cnt,_ := strconv.Atoi(sigs2[0])
	    for j := 0;j<cnt;j++ {
		fr := sigs2[2*j+2]
		exsit,da := GetValueFromPubKeyData(strings.ToLower(fr))
		if !exsit {
		    kdtmp := KeyData{Key: []byte(strings.ToLower(fr)), Data: rk}
		    PubKeyDataChan <- kdtmp
		    LdbPubKeyData.WriteMap(strings.ToLower(fr), []byte(rk))
		} else {
		    //
		    found := false
		    keys := strings.Split(string(da.([]byte)),":")
		    for _,v := range keys {
			if strings.EqualFold(v,rk) {
			    found = true
			    break
			}
		    }
		    //

		    if !found {
			da2 := string(da.([]byte)) + ":" + rk
			kdtmp := KeyData{Key: []byte(strings.ToLower(fr)), Data: da2}
			PubKeyDataChan <- kdtmp
			LdbPubKeyData.WriteMap(strings.ToLower(fr), []byte(da2))
		    }
		}
	    }
	} else {
	    exsit,da := GetValueFromPubKeyData(strings.ToLower(account))
	    if !exsit {
		kdtmp := KeyData{Key: []byte(strings.ToLower(account)), Data: rk}
		PubKeyDataChan <- kdtmp
		LdbPubKeyData.WriteMap(strings.ToLower(account), []byte(rk))
	    } else {
		//
		found := false
		keys := strings.Split(string(da.([]byte)),":")
		for _,v := range keys {
		    if strings.EqualFold(v,rk) {
			found = true
			break
		    }
		}
		//

		if !found {
		    da2 := string(da.([]byte)) + ":" + rk
		    kdtmp := KeyData{Key: []byte(strings.ToLower(account)), Data: da2}
		    PubKeyDataChan <- kdtmp
		    LdbPubKeyData.WriteMap(strings.ToLower(account), []byte(da2))
		}

		}
	}
	//AcceptReqAddr("",account, "ALL", groupid, nonce, w.limitnum, mode, "true", "true", "Success", pubkey, "", "", nil, w.id,"")
	/////////////////////
	common.Debug("=====================ReShare_ec2===================","gen newsku1",newskU1,"key",msgprex)

	res := RpcDcrmRes{Ret: fmt.Sprintf("%v",newskU1), Err: nil}
	ch <- res
	////////////////////////////////
}

