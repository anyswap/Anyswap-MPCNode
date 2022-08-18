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
	cryptorand "crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"time"
	"encoding/json"
	"sync"
	"github.com/fsn-dev/cryptoCoins/coins"
	"github.com/fsn-dev/cryptoCoins/coins/types"
	"github.com/anyswap/Anyswap-MPCNode/mpcdsa/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/mpcdsa/crypto/ed"
	"github.com/anyswap/Anyswap-MPCNode/mpcdsa/ecdsa/keygen"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/internal/common"
	"github.com/anyswap/Anyswap-MPCNode/log"
)

var (
	PaillierKeyLength        = 2048
	reqdata_trytimes = 5
	reqdata_timeout = 60
)

const (
	paillierBitsLen = 2048
)

type PubKeyData struct {
        Key string
	Account  string
	Pub      string
	Save     string
	Nonce    string
	GroupId  string
	LimitNum string
	Mode     string
	KeyGenTime string
	RefReShareKeys string //key1:key2...
}

func GetReqAddrNonce(account string) (string, string, error) {
	key2 := Keccak256Hash([]byte(strings.ToLower(account))).Hex()
	var da []byte
	datmp, exsit := LdbPubKeyData.ReadMap(key2)
	if !exsit {
		da2 := GetPubKeyDataValueFromDb(key2)
		if da2 == nil {
			exsit = false
		} else {
			exsit = true
			da = da2
		}
	} else {
		da = datmp.([]byte)
	}
	///////
	if !exsit {
		return "0", "", nil
	}

	nonce, _ := new(big.Int).SetString(string(da), 10)
	one, _ := new(big.Int).SetString("1", 10)
	nonce = new(big.Int).Add(nonce, one)

	return fmt.Sprintf("%v", nonce), "", nil
}

func SetReqAddrNonce(account string, nonce string) (string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account))).Hex()
	kd := KeyData{Key: []byte(key), Data: nonce}
	PubKeyDataChan <- kd
	return "", nil
}

type TxDataReqAddr struct {
    TxType string
    GroupId string
    ThresHold string
    Mode string
    TimeStamp string
    Sigs string
}

func GetDcrmAddr(pubkey string) (string, string, error) {
	var m interface{}
	addrmp := make(map[string]string)
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

		addrmp[ct] = ctaddr
	}

	m = &DcrmPubkeyRes{Account: "", PubKey: pubkey, DcrmAddress: addrmp}
	b,_ := json.Marshal(m)
	return string(b), "", nil
}

func ReqDcrmAddr(raw string) (string, string, error) {
    hash := Keccak256Hash([]byte(raw)).Hex()
    key,_,_,txdata,err := CheckRaw(raw)
    if err != nil {
	log.Error("[KEYGEN] check raw data fail","err",err,"raw data hash",hash)
	return "",err.Error(),err
    }

    req,ok := txdata.(*TxDataReqAddr)
    if !ok {
	return "","check raw data fail",fmt.Errorf("check raw data fail")
    }

    log.Info("[KEYGEN] broadcasting keygen cmd raw data to group","raw data hash",hash,"gid",req.GroupId,"group nodes",getGroupNodes(req.GroupId))
    SendMsgToDcrmGroup(raw, req.GroupId)
    SetUpMsgList(raw,cur_enode)
    return key, "", nil
}

func RpcAcceptReqAddr(raw string) (string, string, error) {
    hash := Keccak256Hash([]byte(raw)).Hex()
    _,_,_,txdata,err := CheckRaw(raw)
    if err != nil {
	log.Error("[ACCEPT KEYGEN] check raw data fail","raw data hash",hash)
	return "Failure",err.Error(),err
    }

    acceptreq,ok := txdata.(*TxDataAcceptReqAddr)
    if !ok {
	return "Failure","check raw data fail",fmt.Errorf("check raw data fail")
    }

    exsit,da := GetValueFromPubKeyData(acceptreq.Key)
    if exsit {
	ac,ok := da.(*AcceptReqAddrData)
	if ok && ac != nil {
	    log.Info("[ACCEPT KEYGEN] broadcasting keygen accept raw data to group","raw data hash",hash,"gid",ac.GroupId,"group nodes",getGroupNodes(ac.GroupId))
	    SendMsgToDcrmGroup(raw, ac.GroupId)
	    SetUpMsgList(raw,cur_enode)
	    return "Success", "", nil
	}
    }

    return "Failure","accept fail",fmt.Errorf("accept fail")
}

type ReqAddrStatus struct {
	Status    string
	PubKey    string
	Tip       string
	Error     string
	AllReply  []NodeReply 
	TimeStamp string
}

func GetReqAddrStatus(key string) (string, string, error) {
	exsit,da := GetValueFromPubKeyData(key)
	if !exsit || da == nil {
		return "", "", fmt.Errorf("No keygen result was found in the database","key",key)
	}

	ac,ok := da.(*AcceptReqAddrData)
	if !ok {
		return "", "", fmt.Errorf("No keygen result was found in the database")
	}

	los := &ReqAddrStatus{Status: ac.Status, PubKey: ac.PubKey, Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
	ret, err := json.Marshal(los)
	if err != nil {
	    log.Error("[KEYGEN] get keygen result from db fail","key",key)
	    return "","",err
	}

	return string(ret), "", nil
}

type ReqAddrReply struct {
	Key       string
	Account   string
	Cointype  string
	GroupId   string
	Nonce     string
	ThresHold  string
	Mode      string
	TimeStamp string
}

func GetCurNodeReqAddrInfo(geter_acc string) ([]*ReqAddrReply, string, error) {
	var ret []*ReqAddrReply
	var wg sync.WaitGroup
	LdbPubKeyData.RLock()
	for k, v := range LdbPubKeyData.Map {
	    wg.Add(1)
	    go func(key string,value interface{}) {
		defer wg.Done()

		vv,ok := value.(*AcceptReqAddrData)
		if vv == nil || !ok {
		    return
		}

		if vv.Deal == "true" || vv.Status == "Success" {
		    return
		}

		if vv.Status != "Pending" {
		    return
		}

		if vv.Mode == "1" {
		    return
		}

		if vv.Mode == "0" && !CheckAcc(cur_enode,geter_acc,vv.Sigs) {
		    return
		}

		los := &ReqAddrReply{Key: key, Account: vv.Account, Cointype: vv.Cointype, GroupId: vv.GroupId, Nonce: vv.Nonce, ThresHold: vv.LimitNum, Mode: vv.Mode, TimeStamp: vv.TimeStamp}
		ret = append(ret, los)
	    }(k,v)
	}
	LdbPubKeyData.RUnlock()
	wg.Wait()
	return ret, "", nil
}

//ec2
//msgprex = hash
func dcrm_genPubKey(msgprex string, account string, cointype string, ch chan interface{}, mode string, nonce string) {

	wk, err := FindWorker(msgprex)
	if err != nil || wk == nil {
		res := RpcDcrmRes{Ret: "", Tip: "get worker fail", Err: err}
		ch <- res
		return
	}
	id := wk.id

	cur_enode = GetSelfEnode()

	if types.IsDefaultED25519(cointype) {
		ok2 := false
		for j := 0;j < recalc_times;j++ { //try 20 times
		    if len(ch) != 0 {
			<-ch
		    }

		    ok2 = KeyGenerate_ed(msgprex, ch, id, cointype)
		    if ok2 {
			break
		    }

		    wk.Clear2()
		    time.Sleep(time.Duration(3) * time.Second) //1000 == 1s
		}

		if !ok2 {
			return
		}

		itertmp := workers[id].edpk.Front()
		if itertmp == nil {
			res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("get pk fail")}
			ch <- res
			return
		}
		sedpk := []byte(itertmp.Value.(string))

		itertmp = workers[id].edsave.Front()
		if itertmp == nil {
			res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("get pubkey data fail")}
			ch <- res
			return
		}

		sedsave := itertmp.Value.(string)
		itertmp = workers[id].edsku1.Front()
		if itertmp == nil {
			res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("get private share fail")}
			ch <- res
			return
		}

		sedsku1 := itertmp.Value.(string)
		tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
		pubkeyhex := hex.EncodeToString(sedpk)
		pubs := &PubKeyData{Key:msgprex,Account: account, Pub: string(sedpk), Save: sedsave, Nonce: nonce, GroupId: wk.groupid, LimitNum: wk.limitnum, Mode: mode,KeyGenTime:tt}
		epubs, err := Encode2(pubs)
		if err != nil {
			res := RpcDcrmRes{Ret: "", Tip: "", Err: err}
			ch <- res
			return
		}

		ss, err := Compress([]byte(epubs))
		if err != nil {
			res := RpcDcrmRes{Ret: "", Tip: "", Err: err}
			ch <- res
			return
		}

		tip, reply := AcceptReqAddr("",account, cointype, wk.groupid, nonce, wk.limitnum, mode, "true", "true", "Success", pubkeyhex, "", "", nil, id,"")
		if reply != nil {
			res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("update keygen status error")}
			ch <- res
			return
		}

		if !strings.EqualFold(cointype, "ALL") {
			h := coins.NewCryptocoinHandler(cointype)
			if h == nil {
				res := RpcDcrmRes{Ret: "", Tip: "cointype is not supported", Err: fmt.Errorf("keygen fail,cointype is not supported")}
				ch <- res
				return
			}

			ctaddr, err := h.PublicKeyToAddress(pubkeyhex)
			if err != nil {
				res := RpcDcrmRes{Ret: "", Tip: "get dcrm addr fail from pubkey:" + pubkeyhex, Err: err}
				ch <- res
				return
			}

			kd := KeyData{Key: sedpk[:], Data: ss}
			PubKeyDataChan <- kd

			key := Keccak256Hash([]byte(strings.ToLower(ctaddr))).Hex()
			kd = KeyData{Key: []byte(key), Data: ss}
			PubKeyDataChan <- kd
			
			sk := KeyData{Key: sedpk[:], Data: sedsku1}
			SkU1Chan <- sk
			sk = KeyData{Key: []byte(key), Data: sedsku1}
			SkU1Chan <- sk
		} else {
			kd := KeyData{Key: sedpk[:], Data: ss}
			PubKeyDataChan <- kd
			
			sk := KeyData{Key: sedpk[:], Data: sedsku1}
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
				kd = KeyData{Key: []byte(key), Data: ss}
				PubKeyDataChan <- kd
				
				sk = KeyData{Key: []byte(key), Data: sedsku1}
				SkU1Chan <- sk
			}
		}

		res := RpcDcrmRes{Ret: pubkeyhex, Tip: "", Err: nil}
		ch <- res
		return
	}

	ok := false
	for j := 0;j < recalc_times;j++ { //try 20 times
	    if len(ch) != 0 {
		<-ch
	    }

	    ok = KeyGenerate_DECDSA(msgprex, ch, id, cointype)
	    if ok {
		break
	    }

	    wk.Clear2()
	}

	if !ok {
		return
	}

	iter := workers[id].pkx.Front()
	if iter == nil {
		res := RpcDcrmRes{Ret: "", Tip: "", Err: GetRetErr(ErrGetGenPubkeyFail)}
		ch <- res
		return
	}
	spkx := iter.Value.(string)
	pkx := new(big.Int).SetBytes([]byte(spkx))
	iter = workers[id].pky.Front()
	if iter == nil {
		res := RpcDcrmRes{Ret: "", Tip: "", Err: GetRetErr(ErrGetGenPubkeyFail)}
		ch <- res
		return
	}
	spky := iter.Value.(string)
	pky := new(big.Int).SetBytes([]byte(spky))
	ys := secp256k1.S256().Marshal(pkx, pky)

	iter = workers[id].save.Front()
	if iter == nil {
		res := RpcDcrmRes{Ret: "", Tip: "", Err: GetRetErr(ErrGetGenSaveDataFail)}
		ch <- res
		return
	}
	
	save := iter.Value.(string)
	iter = workers[id].sku1.Front()
	if iter == nil {
		res := RpcDcrmRes{Ret: "", Tip: "", Err: GetRetErr(ErrGetGenSaveDataFail)}
		ch <- res
		return
	}
	sku1 := iter.Value.(string)
	////////
	sk := KeyData{Key: ys, Data: sku1}
	SkU1Chan <- sk
	//save sku1
	//

	tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
	pubkeyhex := hex.EncodeToString(ys)
	pubs := &PubKeyData{Key:msgprex,Account: account, Pub: string(ys), Save: save, Nonce: nonce, GroupId: wk.groupid, LimitNum: wk.limitnum, Mode: mode,KeyGenTime:tt}
	epubs, err := Encode2(pubs)
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "", Err: err}
		ch <- res
		return
	}

	ss, err := Compress([]byte(epubs))
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "", Err: err}
		ch <- res
		return
	}

	tip, reply := AcceptReqAddr("",account, cointype, wk.groupid, nonce, wk.limitnum, mode, "true", "true", "Success", pubkeyhex, "", "", nil, id,"")
	if reply != nil {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("update keygen status error")}
		ch <- res
		return
	}

	if !strings.EqualFold(cointype, "ALL") {
		h := coins.NewCryptocoinHandler(cointype)
		if h == nil {
			res := RpcDcrmRes{Ret: "", Tip: "cointype is not supported", Err: fmt.Errorf("cointype is not supported.")}
			ch <- res
			return
		}

		ctaddr, err := h.PublicKeyToAddress(pubkeyhex)
		if err != nil {
			res := RpcDcrmRes{Ret: "", Tip: "get dcrm addr fail from pubkey:" + pubkeyhex, Err: err}
			ch <- res
			return
		}

		kd := KeyData{Key: ys, Data: ss}
		PubKeyDataChan <- kd

		key := Keccak256Hash([]byte(strings.ToLower(ctaddr))).Hex()
		kd = KeyData{Key: []byte(key), Data: ss}
		PubKeyDataChan <- kd
		
		sk = KeyData{Key: []byte(key), Data: sku1}
		SkU1Chan <- sk
	} else {
		kd := KeyData{Key: ys, Data: ss}
		PubKeyDataChan <- kd

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
			kd = KeyData{Key: []byte(key), Data: ss}
			PubKeyDataChan <- kd
			
			sk = KeyData{Key: []byte(key), Data: sku1}
			SkU1Chan <- sk
		}
	}

	res := RpcDcrmRes{Ret: pubkeyhex, Tip: "", Err: nil}
	ch <- res
}

//ed
//msgprex = hash
func KeyGenerate_ed(msgprex string, ch chan interface{}, id int, cointype string) bool {
	if id < 0 || id >= RPCMaxWorker || id >= len(workers) {
		res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("get worker ID fail")}
		ch <- res
		return false
	}

	w := workers[id]
	GroupId := w.groupid
	if GroupId == "" {
		res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("get group ID fail")}
		ch <- res
		return false
	}

	ns, _ := GetGroup(GroupId)
	if ns != w.NodeCnt {
		res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("get node count error")}
		ch <- res
		return false
	}

	rand := cryptorand.Reader
	var seed [32]byte

	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		log.Error("[KEYGEN] failed to generate random number","err",err,"key",msgprex)
		res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("failed to generate random number")}
		ch <- res
		return false
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

	ids := GetIds(cointype, GroupId)

	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "EDC11"
	s1 := string(CPk[:])
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr := GetChannelValue(ch_t, w.bedc11)
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"EDC11",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all pk commitment datas fail")}
		ch <- res
		return false
	}

	if w.msg_edc11.Len() != w.NodeCnt {
		res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("get pk commitment data error")}
		ch <- res
		return false
	}

	var cpks = make(map[string][32]byte)
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			cpks[cur_enode] = CPk
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edc11.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
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
	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr = GetChannelValue(ch_t, w.bedzk)
	/////////////////////////request data from dcrm group
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"EDZK",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all pk ZK datas fail")}
		ch <- res
		return false
	}

	if w.msg_edzk.Len() != w.NodeCnt {
		res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("get pk ZK data fail")}
		ch <- res
		return false
	}

	var zks = make(map[string][64]byte)
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			zks[cur_enode] = zkPk
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edzk.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
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
	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr = GetChannelValue(ch_t, w.bedd11)
	/////////////////////////request data from dcrm group
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"EDD11",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all pk commitment datas fail")}
		ch <- res
		return false
	}

	if w.msg_edd11.Len() != w.NodeCnt {
		res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("get pk commitment data error")}
		ch <- res
		return false
	}
	var dpks = make(map[string][64]byte)
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			dpks[cur_enode] = DPk
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edd11.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
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

	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		CPkFlag := ed.Verify(cpks[en[0]], dpks[en[0]])
		if !CPkFlag {
			log.Error("[KEYGEN] verify pk commitment data fail","key",msgprex)
			res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("verify pk commitment data fail")}
			ch <- res
			return false
		}
	}

	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		dpk := dpks[en[0]]
		var t [32]byte
		copy(t[:], dpk[32:])
		zkPkFlag := ed.Verify_zk(zks[en[0]], t)
		if !zkPkFlag {
			log.Error("[KEYGEN] verify pk ZK data fail","key",msgprex)
			res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("verify pk ZK data fail")}
			ch <- res
			return false
		}
	}

	// 2.5 calculate a = SHA256(PkU1, {PkU2, PkU3})
	var a [32]byte
	var aDigest [64]byte
	var PkSet []byte

	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		dpk := dpks[en[0]]
		PkSet = append(PkSet[:], (dpk[32:])...)
	}

	h := sha512.New()
	dpk := dpks[cur_enode]
	_,err := h.Write(dpk[32:])
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "", Err: err}
	    ch <- res
	    return false
	}

	_,err = h.Write(PkSet)
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "", Err: err}
	    ch <- res
	    return false
	}

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

	_, cfsBBytes, shares := ed.Vss2(ask, w.ThresHold, w.NodeCnt, uids)

	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)

		if enodes == "" {
			res := RpcDcrmRes{Ret: "", Tip: "get enode by uid fail", Err: fmt.Errorf("get enode by uid fail")}
			ch <- res
			return false
		}

		if IsCurNode(enodes, cur_enode) {
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")
		for k, v := range shares {
			if strings.EqualFold(k, en[0]) {
				s0 := "EDSHARE1"
				s1 := string(v[:])
				ss := enode + common.Sep + s0 + common.Sep + s1
				SendMsgToPeer(enodes, ss)
				break
			}
		}
	}

	_, tip, cherr = GetChannelValue(ch_t, w.bedshare1)
	/////////////////////////request data from dcrm group
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"EDSHARE1",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all vss shares fail")}
		ch <- res
		return false
	}

	if w.msg_edshare1.Len() != (w.NodeCnt-1) {
		res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("get vss share fail")}
		ch <- res
		return false
	}

	var edshares = make(map[string][32]byte)
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			edshares[cur_enode] = shares[cur_enode]
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edshare1.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
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
	for _, v := range cfsBBytes {
		vv := string(v[:])
		ss = ss + vv + common.Sep
	}
	ss = ss + "NULL"

	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr = GetChannelValue(ch_t, w.bedcfsb)
	/////////////////////////request data from dcrm group
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"EDCFSB",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all vss share fail")}
		ch <- res
		return false
	}

	if w.msg_edcfsb.Len() != w.NodeCnt {
		res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("get vss share fail")}
		ch <- res
		return false
	}
	var cfsbs = make(map[string][][32]byte)
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			cfsbs[cur_enode] = cfsBBytes
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edcfsb.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
				mm := m[2:]
				var cfs [][32]byte
				for _, tmp := range mm {
					if tmp == "NULL" {
						break
					}
					var t [32]byte
					va := []byte(tmp)
					copy(t[:], va[:32])
					cfs = append(cfs, t)
				}
				cfsbs[en[0]] = cfs
				break
			}
			iter = iter.Next()
		}
	}

	// 3.1 verify share
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")

		shareUFlag := ed.Verify_vss(edshares[en[0]], uids[cur_enode], cfsbs[en[0]])

		if !shareUFlag {
			res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("VSS Share Verification Not Pass")}
			ch <- res
			return false
		}
	}

	// 3.2 verify share2
	var a2 [32]byte
	var aDigest2 [64]byte

	var PkSet2 []byte
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		var temPk [32]byte
		t := dpks[en[0]]
		copy(temPk[:], t[32:])
		PkSet2 = append(PkSet2[:], (temPk[:])...)
	}

	h = sha512.New()
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		var temPk [32]byte
		t := dpks[en[0]]
		copy(temPk[:], t[32:])

		h.Reset()
		_,err = h.Write(temPk[:])
		if err != nil {
		    res := RpcDcrmRes{Ret: "", Tip:err.Error(), Err:err}
		    ch <- res
		    return false
		}
		_,err = h.Write(PkSet2)
		if err != nil {
		    res := RpcDcrmRes{Ret: "", Tip:err.Error(), Err:err}
		    ch <- res
		    return false
		}
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
			res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("VSS Coefficient Verification Not Pass")}
			ch <- res
			return false
		}
	}

	// 3.3 calculate tSk
	var tSk [32]byte
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		t := edshares[en[0]]
		ed.ScAdd(&tSk, &tSk, &t)
	}

	// 3.4 calculate pk
	var finalPk ed.ExtendedGroupElement
	var finalPkBytes [32]byte

	i := 0
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		var temPk [32]byte
		t := dpks[en[0]]
		copy(temPk[:], t[32:])

		h.Reset()
		_,err = h.Write(temPk[:])
		if err != nil {
		    res := RpcDcrmRes{Ret: "", Tip:err.Error(), Err:err}
		    ch <- res
		    return false
		}
		_,err = h.Write(PkSet2)
		if err != nil {
		    res := RpcDcrmRes{Ret: "", Tip:err.Error(), Err:err}
		    ch <- res
		    return false
		}
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
	//save := string(sk[:]) + common.Sep11 + string(pk[:]) + common.Sep11 + string(tSk[:]) + common.Sep11 + string(finalPkBytes[:])
	save := "XXX" + common.Sep11 + string(pk[:]) + common.Sep11 + string(tSk[:]) + common.Sep11 + string(finalPkBytes[:])

	w.edsave.PushBack(save)
	w.edsku1.PushBack(string(sk[:]))
	w.edpk.PushBack(string(finalPkBytes[:]))

	return true
}

func ReqDataFromGroup(msgprex string,wid int,datatype string,trytimes int,timeout int) bool {
	return false
}

func DECDSAGenKeyRoundOne(msgprex string, ch chan interface{}, w *RPCReqWorker) (*big.Int, *ec2.PolyStruct2, *ec2.PolyGStruct2, *ec2.Commitment, *ec2.PublicKey, *ec2.PrivateKey, bool) {
	if w == nil || msgprex == "" {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("No Found Worker")}
		ch <- res
		return nil, nil, nil, nil, nil, nil, false
	}

	u1, u1Poly, u1PolyG, commitU1G, u1PaillierPk, u1PaillierSk := keygen.DECDSA_Key_RoundOne(w.ThresHold, PaillierKeyLength)
	if u1PaillierPk == nil || u1PaillierSk == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("failed to generate paillier key")}
		ch <- res
		return nil, nil, nil, nil, nil, nil, false
	}

	///bug groupid == nil ???
	w, err := FindWorker(msgprex)
	if err != nil || w.groupid == "" {
	    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get group ID fail")}
	    ch <- res
	    return nil, nil, nil, nil, nil, nil, false
	}

	// 4. Broadcast
	// commitU1G.C, commitU2G.C, commitU3G.C, commitU4G.C, commitU5G.C
	// u1PaillierPk, u2PaillierPk, u3PaillierPk, u4PaillierPk, u5PaillierPk
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "C1"
	s1 := string(commitU1G.C.Bytes())
	s2 := u1PaillierPk.Length
	s3 := string(u1PaillierPk.N.Bytes())
	s4 := string(u1PaillierPk.G.Bytes())
	s5 := string(u1PaillierPk.N2.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2 + common.Sep + s3 + common.Sep + s4 + common.Sep + s5
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	_, enodestmp := GetGroup(w.groupid)
	nodestmp := strings.Split(enodestmp, common.Sep2)
	for _, node := range nodestmp {
	    node2 := ParseNode(node)
	    c1data := msgprex + "-" + node2 + common.Sep + "C1"
	    c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
	    if exist {
		DisMsg(c1.(string))
		go C1Data.DeleteMap(strings.ToLower(c1data))
	    }
	}

	// 1. Receive Broadcast
	// commitU1G.C, commitU2G.C, commitU3G.C, commitU4G.C, commitU5G.C
	// u1PaillierPk, u2PaillierPk, u3PaillierPk, u4PaillierPk, u5PaillierPk
	_, tip, cherr := GetChannelValue(ch_t, w.bc1)

	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"C1",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
	    /////check
	    ///bug groupid == nil ???
	    w, err := FindWorker(msgprex)
	    if err != nil || w.groupid == "" {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get group ID fail")}
		ch <- res
		return nil, nil, nil, nil, nil, nil, false
	    }
	    //////
	    
	    _, enodes := GetGroup(w.groupid)
	    nodes := strings.Split(enodes, common.Sep2)
	    for _, node := range nodes {
		    found := false
		    node2 := ParseNode(node)
		    if strings.EqualFold(cur_enode,node2) {
			continue
		    }

		    iter := w.msg_c1.Front()
		    for iter != nil {
			mdss := iter.Value.(string)
			ms := strings.Split(mdss, common.Sep)
			prexs := strings.Split(ms[0], "-")
			node3 := prexs[1]
			if strings.EqualFold(node3,node2) {
			    found = true
			    break
			}
			
			iter = iter.Next()
		    }

		    if !found {
			c1data := msgprex + "-" + node2 + common.Sep + "C1"
			log.Error("[KEYGEN] Not Reciving The Paillier PubKey Data","data header",c1data,"from Node",node2,"key",msgprex)
		    }
	    }
	    
	    res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("Not Reciving The Paillier PubKey Data")}
	    ch <- res
	    return nil, nil, nil, nil, nil, nil, false
	}

	//check paillier.N bitlen
	iter := w.msg_c1.Front()
	for iter != nil {
	    mdss := iter.Value.(string)
	    ms := strings.Split(mdss, common.Sep)
	    // key-enodeID:C1:com.C:pk.Len:pk.N:pk.G:pk.N2
	    if len(ms) < 7 {
		res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("got paillier pubkey data error")}
		ch <- res
		return nil, nil, nil, nil, nil, nil, false
	    }

	    // paillier.N
	    N := new(big.Int).SetBytes([]byte(ms[4]))
	    if N.BitLen() < paillierBitsLen {
		res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("got paillier N with not enough bits")}
		ch <- res
		return nil, nil, nil, nil, nil, nil, false
	    }

	    iter = iter.Next()
	}

	return u1, u1Poly, u1PolyG, commitU1G, u1PaillierPk, u1PaillierSk, true
}

func DECDSAGenKeyRoundTwo(msgprex string, cointype string, ch chan interface{}, w *RPCReqWorker, u1Poly *ec2.PolyStruct2, ids sortableIDSSlice) ([]*ec2.ShareStruct2, bool) {
	if w == nil || cointype == "" || msgprex == "" || u1Poly == nil || len(ids) == 0 {
		res := RpcDcrmRes{Ret:"", Err: fmt.Errorf("parameter error in the second round")}
		ch <- res
		return nil, false
	}

	// 2. generate their vss to get shares which is a set
	// [notes]
	// all nodes has their own id, in practival, we can take it as double hash of public key of fusion

	u1Shares, err := keygen.DECDSA_Key_Vss(u1Poly, ids)
	if err != nil {
		res := RpcDcrmRes{Ret: "", Err: err}
		ch <- res
		return nil, false
	}

	// 3. send the the proper share to proper node
	//example for u1:
	// Send u1Shares[0] to u1
	// Send u1Shares[1] to u2
	// Send u1Shares[2] to u3
	// Send u1Shares[3] to u4
	// Send u1Shares[4] to u5
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, w.groupid)

		if enodes == "" {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get node ID by UID fail")}
			ch <- res
			return nil, false
		}

		if IsCurNode(enodes, cur_enode) {
			continue
		}

		for _, v := range u1Shares {
			uid := keygen.DECDSA_Key_GetSharesId(v)
			if uid != nil && uid.Cmp(id) == 0 {
				mp := []string{msgprex, cur_enode}
				enode := strings.Join(mp, "-")
				s0 := "SHARE1"
				s2 := string(v.Id.Bytes())
				s3 := string(v.Share.Bytes())
				ss := enode + common.Sep + s0 + common.Sep + s2 + common.Sep + s3
				SendMsgToPeer(enodes, ss)
				break
			}
		}
	}

	return u1Shares, true
}

func DECDSAGenKeyRoundThree(msgprex string, cointype string, ch chan interface{}, w *RPCReqWorker, u1PolyG *ec2.PolyGStruct2, commitU1G *ec2.Commitment, ids sortableIDSSlice) bool {
	if w == nil || cointype == "" || msgprex == "" || u1PolyG == nil || len(ids) == 0 || commitU1G == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("parameter error in the third round")}
		ch <- res
		return false
	}

	// 4. Broadcast
	// commitU1G.D, commitU2G.D, commitU3G.D, commitU4G.D, commitU5G.D
	// u1PolyG, u2PolyG, u3PolyG, u4PolyG, u5PolyG
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "D1"
	dlen := len(commitU1G.D)
	s1 := strconv.Itoa(dlen)

	ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep
	for _, d := range commitU1G.D {
		ss += string(d.Bytes())
		ss += common.Sep
	}

	pglen := 2 * (len(u1PolyG.PolyG))
	s4 := strconv.Itoa(pglen)

	ss = ss + s4 + common.Sep

	for _, p := range u1PolyG.PolyG {
		for _, d := range p {
			ss += string(d.Bytes())
			ss += common.Sep
		}
	}
	ss = ss + "NULL"
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	// 1. Receive Broadcast
	// commitU1G.D, commitU2G.D, commitU3G.D, commitU4G.D, commitU5G.D
	// u1PolyG, u2PolyG, u3PolyG, u4PolyG, u5PolyG
	_, tip, cherr := GetChannelValue(ch_t, w.bd1_1)
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"D1",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
	    _, enodes := GetGroup(w.groupid)
	    nodes := strings.Split(enodes, common.Sep2)
	    for _, node := range nodes {
		    found := false
		    node2 := ParseNode(node)
		    if strings.EqualFold(cur_enode,node2) {
			continue
		    }

		    iter := w.msg_d1_1.Front()
		    for iter != nil {
			mdss := iter.Value.(string)
			ms := strings.Split(mdss, common.Sep)
			prexs := strings.Split(ms[0], "-")
			node3 := prexs[1]
			if strings.EqualFold(node3,node2) {
			    found = true
			    break
			}
			iter = iter.Next()
		    }

		    if !found {
			d1data := msgprex + "-" + node2 + common.Sep + "D1"
			log.Error("[KEYGEN] Not Reciving The u1 Commitment Data","data header",d1data,"from Node",node2,"key",msgprex)
		    }
	    }
	    
	    res := RpcDcrmRes{Ret: "", Tip: tip, Err: GetRetErr(ErrGetD1Timeout)}
	    ch <- res
	    return false
	}

	return true
}

func DECDSAGenKeyVerifyShareData(msgprex string, cointype string, ch chan interface{}, w *RPCReqWorker, u1PolyG *ec2.PolyGStruct2, u1Shares []*ec2.ShareStruct2, ids sortableIDSSlice) (map[string]*ec2.ShareStruct2, []string, bool) {
	if w == nil || cointype == "" || msgprex == "" || u1PolyG == nil || len(ids) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("parameter error while validating VSS share data")}
		ch <- res
		return nil, nil, false
	}

	// 2. Receive Personal Data
	_, tip, cherr := GetChannelValue(ch_t, w.bshare1)
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"SHARE1",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: GetRetErr(ErrGetSHARE1Timeout)}
		ch <- res
		return nil, nil, false
	}

	var sstruct = make(map[string]*ec2.ShareStruct2)
	shares := make([]string, w.NodeCnt-1)
	if w.msg_share1.Len() != (w.NodeCnt - 1) {
		res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetAllSHARE1Fail)}
		ch <- res
		return nil, nil, false
	}

	itmp := 0
	iter := w.msg_share1.Front()
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
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get vss share data fail")}
			ch <- res
			return nil, nil, false
		}
		//
		ushare := &ec2.ShareStruct2{Id: new(big.Int).SetBytes([]byte(mm[2])), Share: new(big.Int).SetBytes([]byte(mm[3]))}
		prex := mm[0]
		prexs := strings.Split(prex, "-")
		sstruct[prexs[len(prexs)-1]] = ushare
	}

	for _, v := range u1Shares {
		uid := keygen.DECDSA_Key_GetSharesId(v)
		if uid == nil {
			continue
		}

		enodes := GetEnodesByUid(uid, cointype, w.groupid)
		if IsCurNode(enodes, cur_enode) {
			sstruct[cur_enode] = v
			break
		}
	}

	ds := make([]string, w.NodeCnt)
	if w.msg_d1_1.Len() != w.NodeCnt {
		res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetAllD1Fail)}
		ch <- res
		return nil, nil, false
	}

	itmp = 0
	iter = w.msg_d1_1.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		if itmp < len(ds) {
		    ds[itmp] = mdss
		}
		iter = iter.Next()
		itmp++
	}

	var upg = make(map[string]*ec2.PolyGStruct2)
	for _, v := range ds {
		mm := strings.Split(v, common.Sep)
		if len(mm) < 3 {
		    res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetAllD1Fail)}
		    ch <- res
		    return nil, nil, false
		}
		dlen, _ := strconv.Atoi(mm[2])
		if len(mm) < (4 + dlen) {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get u1 commitment data error")}
			ch <- res
			return nil, nil, false
		}

		pglen, _ := strconv.Atoi(mm[3+dlen])
		pglen = (pglen / 2)
		var pgss = make([][]*big.Int, 0)
		l := 0
		for j := 0; j < pglen; j++ {
			l++
			var gg = make([]*big.Int, 0)
			if len(mm) < (4 + dlen + l) {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get u1 commitment data error")}
				ch <- res
				return nil, nil, false
			}

			gg = append(gg, new(big.Int).SetBytes([]byte(mm[3+dlen+l])))
			l++
			if len(mm) < (4 + dlen + l) {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get u1 commitment data error")}
				ch <- res
				return nil, nil, false
			}
			gg = append(gg, new(big.Int).SetBytes([]byte(mm[3+dlen+l])))
			pgss = append(pgss, gg)
		}

		ps := &ec2.PolyGStruct2{PolyG: pgss}
		prex := mm[0]
		prexs := strings.Split(prex, "-")
		upg[prexs[len(prexs)-1]] = ps
	}
	upg[cur_enode] = u1PolyG

	// 3. verify the share
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		//bug
		if len(en) == 0 || en[0] == "" || sstruct[en[0]] == nil || upg[en[0]] == nil {
			res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifySHARE1Fail)}
			ch <- res
			return nil, nil, false
		}
		//
		if !keygen.DECDSA_Key_Verify_Share(sstruct[en[0]], upg[en[0]]) {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify vss share data fail in keygen")}
			ch <- res
			return nil, nil, false
		}
	}

	return sstruct, ds, true
}

func DECDSAGenKeyCalcPubKey(msgprex string, cointype string, ch chan interface{}, w *RPCReqWorker, udecom map[string]*ec2.Commitment, ids sortableIDSSlice) (map[string][]*big.Int, bool) {
	if w == nil || cointype == "" || msgprex == "" || len(udecom) == 0 || len(ids) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("parameter error calculating public key")}
		ch <- res
		return nil, false
	}

	// for all nodes, de-commitment
	var ug = make(map[string][]*big.Int)
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		_, u1G := udecom[en[0]].DeCommit()
		ug[en[0]] = u1G
	}

	// for all nodes, calculate the public key
	var pkx *big.Int
	var pky *big.Int
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		pkx = (ug[en[0]])[0]
		pky = (ug[en[0]])[1]
		break
	}

	for k, id := range ids {
		if k == 0 {
			continue
		}

		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		pkx,pky = secp256k1.S256().Add(pkx, pky, (ug[en[0]])[0], (ug[en[0]])[1])
	}

	w.pkx.PushBack(string(pkx.Bytes()))
	w.pky.PushBack(string(pky.Bytes()))
	return ug, true
}

func DECDSAGenKeyCalcPrivKey(msgprex string, cointype string, ch chan interface{}, w *RPCReqWorker, sstruct map[string]*ec2.ShareStruct2, ids sortableIDSSlice) (*big.Int, bool) {
	if w == nil || cointype == "" || msgprex == "" || len(sstruct) == 0 || len(ids) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("error calculating private key" )}
		ch <- res
		return nil, false
	}

	// 5. calculate the share of private key
	var skU1 *big.Int
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		skU1 = sstruct[en[0]].Share
		break
	}

	for k, id := range ids {
		if k == 0 {
			continue
		}

		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		skU1 = new(big.Int).Add(skU1, sstruct[en[0]].Share)
	}
	skU1 = new(big.Int).Mod(skU1, secp256k1.S256().N)

	return skU1, true
}

func DECDSAGenKeyVerifyCommitment(msgprex string, cointype string, ch chan interface{}, w *RPCReqWorker, ds []string, commitU1G *ec2.Commitment, ids sortableIDSSlice) ([]string, map[string]*ec2.Commitment, bool) {
	if w == nil || cointype == "" || msgprex == "" || len(ds) == 0 || len(ids) == 0 || commitU1G == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("parameter error while validating u1 commitment data")}
		ch <- res
		return nil, nil, false
	}

	// 4.verify and de-commitment to get uG
	// for all nodes, construct the commitment by the receiving C and D
	cs := make([]string, w.NodeCnt)
	if w.msg_c1.Len() != w.NodeCnt {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all u1 commitment data fail")}
		ch <- res
		return nil, nil, false
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
	for _, v := range cs {
		mm := strings.Split(v, common.Sep)
		if len(mm) < 3 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("invalid u1 commitment data")}
			ch <- res
			return nil, nil, false
		}

		prex := mm[0]
		prexs := strings.Split(prex, "-")
		for _, vv := range ds {
			mmm := strings.Split(vv, common.Sep)
			//bug
			if len(mmm) < 3 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("invalid u1 commitment data")}
				ch <- res
				return nil, nil, false
			}

			prex2 := mmm[0]
			prexs2 := strings.Split(prex2, "-")
			if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
				dlen, _ := strconv.Atoi(mmm[2])
				var gg = make([]*big.Int, 0)
				l := 0
				for j := 0; j < dlen; j++ {
					l++
					//bug
					if len(mmm) < (3 + l) {
						res := RpcDcrmRes{Ret: "", Err:fmt.Errorf("invalid u1 commitment data")}
						ch <- res
						return nil, nil, false
					}

					gg = append(gg, new(big.Int).SetBytes([]byte(mmm[2+l])))
				}

				deCommit := &ec2.Commitment{C: new(big.Int).SetBytes([]byte(mm[2])), D: gg}
				udecom[prexs[len(prexs)-1]] = deCommit
				break
			}
		}
	}
	deCommit_commitU1G := &ec2.Commitment{C: commitU1G.C, D: commitU1G.D}
	udecom[cur_enode] = deCommit_commitU1G

	// for all nodes, verify the commitment
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		if len(en) == 0 || en[0] == "" || udecom[en[0]] == nil {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("data error while verifying the u1 commitment data")}
			ch <- res
			return nil, nil, false
		}
		if !keygen.DECDSA_Key_Commitment_Verify(udecom[en[0]]) {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("data error verifying the u1 commitment data")}
			ch <- res
			return nil, nil, false
		}
	}

	return cs, udecom, true
}

func DECDSAGenKeyRoundFour(msgprex string, ch chan interface{}, w *RPCReqWorker) (*ec2.NtildeH1H2, bool) {
	if w == nil || msgprex == "" {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("parameter error generating ntilde data")}
		ch <- res
		return nil, false
	}

	// 6. calculate the zk

	// zk of paillier key
	NtildeLength := 2048
	// for u1
	u1NtildeH1H2 := keygen.DECDSA_Key_GenerateNtildeH1H2(NtildeLength)
	if u1NtildeH1H2 == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("failed to generate ntilde data")}
		ch <- res
		return nil, false
	}

	// 7. Broadcast ntilde
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "NTILDEH1H2" //delete zkfactor add ntild h1 h2
	s1 := string(u1NtildeH1H2.Ntilde.Bytes())
	s2 := string(u1NtildeH1H2.H1.Bytes())
	s3 := string(u1NtildeH1H2.H2.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2 + common.Sep + s3
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	// 1. Receive Broadcast zk
	// u1zkFactProof, u2zkFactProof, u3zkFactProof, u4zkFactProof, u5zkFactProof
	_, tip, cherr := GetChannelValue(ch_t, w.bzkfact)
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"NTILDEH1H2",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
	    /////check
	    _, enodes := GetGroup(w.groupid)
	    nodes := strings.Split(enodes, common.Sep2)
	    for _, node := range nodes {
		    found := false
		    node2 := ParseNode(node)
		    if strings.EqualFold(cur_enode,node2) {
			continue
		    }

		    iter := w.msg_zkfact.Front()
		    for iter != nil {
			mdss := iter.Value.(string)
			ms := strings.Split(mdss, common.Sep)
			prexs := strings.Split(ms[0], "-")
			node3 := prexs[1]
			if strings.EqualFold(node3,node2) {
			    found = true
			    break
			}
			iter = iter.Next()
		    }

		    if !found {
			zkfactdata := msgprex + "-" + node2 + common.Sep + "NTILDEH1H2"
			log.Error("[KEYGEN] Not Reciving The Ntilde Data","data header",zkfactdata,"From Node",node2,"key",msgprex)
		    }
	    }
	    
	    res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("failed to receive the ntilde data")}
	    ch <- res
	    return nil, false
	}

	// check ntilde bitlen
	iter := w.msg_zkfact.Front()
	for iter != nil {
	    mdss := iter.Value.(string)
	    ms := strings.Split(mdss, common.Sep)
	    // key-enodeID:NTILDEH1H2:ntilde:h1:h2
	    if len(ms) < 5 {
		res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("got ntilde data error")}
		ch <- res
		return nil,false
	    }

	    // ntilde
	    Ntilde := new(big.Int).SetBytes([]byte(ms[2]))
	    if Ntilde.BitLen() < paillierBitsLen {
		res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("got ntilde with not enough bits")}
		ch <- res
		return nil,false
	    }

	    iter = iter.Next()
	}


	return u1NtildeH1H2, true
}

func DECDSAGenKeyRoundFive(msgprex string, ch chan interface{}, w *RPCReqWorker, u1 *big.Int) bool {
	if w == nil || msgprex == "" {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("parameter error in the five round")}
		ch <- res
		return false
	}

	// zk of u
	u1zkUProof := keygen.DECDSA_Key_ZkUProve(u1)

	// 8. Broadcast zk
	// u1zkUProof, u2zkUProof, u3zkUProof, u4zkUProof, u5zkUProof
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "ZKUPROOF"
	s1 := string(u1zkUProof.E.Bytes())
	s2 := string(u1zkUProof.S.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	// 9. Receive Broadcast zk
	// u1zkUProof, u2zkUProof, u3zkUProof, u4zkUProof, u5zkUProof
	_, tip, cherr := GetChannelValue(ch_t, w.bzku)
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"ZKUPROOF",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
	    /////check
	    _, enodes := GetGroup(w.groupid)
	    nodes := strings.Split(enodes, common.Sep2)
	    for _, node := range nodes {
		    found := false
		    node2 := ParseNode(node)
		    if strings.EqualFold(cur_enode,node2) {
			continue
		    }

		    iter := w.msg_zku.Front()
		    for iter != nil {
			mdss := iter.Value.(string)
			ms := strings.Split(mdss, common.Sep)
			prexs := strings.Split(ms[0], "-")
			node3 := prexs[1]
			if strings.EqualFold(node3,node2) {
			    found = true
			    break
			}
			iter = iter.Next()
		    }

		    if !found {
			zkudata := msgprex + "-" + node2 + common.Sep + "ZKUPROOF"
			log.Error("[KEYGEN] Not Receiving The u1 Zero Knowledge Proof Data","data header",zkudata,"From Node",node2,"key",msgprex)
		    }
	    }
	    
	    res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("failed to receive the u1 zero knowledge proof data")}
	    ch <- res
	    return false
	}

	return true
}

func DECDSAGenKeyVerifyZKU(msgprex string, cointype string, ch chan interface{}, w *RPCReqWorker, ids sortableIDSSlice, ug map[string][]*big.Int) bool {
	if w == nil || msgprex == "" || cointype == "" || len(ids) == 0 || len(ug) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("parameter error while validating u1 zero knowledge proof data")}
		ch <- res
		return false
	}

	// for all nodes, verify zk of u
	zku := make([]string, w.NodeCnt)
	if w.msg_zku.Len() != w.NodeCnt {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all u1 zero knowledge proof datas fail")}
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

	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		for _, v := range zku {
			mm := strings.Split(v, common.Sep)
			prex := mm[0]
			prexs := strings.Split(prex, "-")
			if prexs[len(prexs)-1] == en[0] {
				e := new(big.Int).SetBytes([]byte(mm[2]))
				s := new(big.Int).SetBytes([]byte(mm[3]))
				zkUProof := &ec2.ZkUProof{E: e, S: s}
				if !keygen.DECDSA_Key_ZkUVerify(ug[en[0]], zkUProof) {
					res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("failed to verify u1 zero knowledge proof data")}
					ch <- res
					return false
				}

				break
			}
		}
	}

	return true
}

func DECDSAGenKeySaveData(cointype string, ids sortableIDSSlice, w *RPCReqWorker, ch chan interface{}, skU1 *big.Int, u1PaillierPk *ec2.PublicKey, u1PaillierSk *ec2.PrivateKey, cs []string, u1NtildeH1H2 *ec2.NtildeH1H2) bool {
	if cointype == "" || len(ids) == 0 || w == nil || skU1 == nil || u1PaillierPk == nil || u1PaillierSk == nil || len(cs) == 0 || u1NtildeH1H2 == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("parameter error while save keygen data")}
		ch <- res
		return false
	}

	//save skU1/u1PaillierSk/u1PaillierPk/...
	//ss := string(skU1.Bytes())
	ss := "XXX"
	ss = ss + common.SepSave
	s1 := u1PaillierSk.Length
	s2 := string(u1PaillierSk.L.Bytes())
	s3 := string(u1PaillierSk.U.Bytes())
	ss = ss + s1 + common.SepSave + s2 + common.SepSave + s3 + common.SepSave

	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			s1 = u1PaillierPk.Length
			s2 = string(u1PaillierPk.N.Bytes())
			s3 = string(u1PaillierPk.G.Bytes())
			s4 := string(u1PaillierPk.N2.Bytes())
			ss = ss + s1 + common.SepSave + s2 + common.SepSave + s3 + common.SepSave + s4 + common.SepSave
			continue
		}
		for _, v := range cs {
			mm := strings.Split(v, common.Sep)
			prex := mm[0]
			prexs := strings.Split(prex, "-")
			if prexs[len(prexs)-1] == en[0] {
				s1 = mm[3]
				s2 = mm[4]
				s3 = mm[5]
				s4 := mm[6]
				ss = ss + s1 + common.SepSave + s2 + common.SepSave + s3 + common.SepSave + s4 + common.SepSave
				break
			}
		}
	}

	zkfacts := make([]string, w.NodeCnt)
	if w.msg_zkfact.Len() != w.NodeCnt {
		res := RpcDcrmRes{Ret: "", Err:fmt.Errorf("get ntilde data fail")}
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

	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
		    s1 = string(u1NtildeH1H2.Ntilde.Bytes())
		    s2 = string(u1NtildeH1H2.H1.Bytes())
		    s3 = string(u1NtildeH1H2.H2.Bytes())
		    ss = ss + s1 + common.SepSave + s2 + common.SepSave + s3 + common.SepSave
			continue
		}

		for _, v := range zkfacts {
			mm := strings.Split(v, common.Sep)
			prex := mm[0]
			prexs := strings.Split(prex, "-")
			if prexs[len(prexs)-1] == en[0] {
				ss = ss + mm[2] + common.SepSave + mm[3] + common.SepSave + mm[4] + common.SepSave //for ntilde
				break
			}
		}
	}

	ss = ss + "NULL"
	//w.save:  sku1:UiSK:U1PK:U2PK:U3PK:....:UnPK:U1H1:U1H2:U1Y:U1E:U1N:U2H1:U2H2:U2Y:U2E:U2N:U3H1:U3H2:U3Y:U3E:U3N:......:NULL
	//w.save:  sku1:UiSK.Len:UiSK.L:UiSK.U:U1PK.Len:U1PK.N:U1PK.G:U1PK.N2:U2PK.Len:U2PK.N:U2PK.G:U2PK.N2:....:UnPK.Len:UnPK.N:UnPK.G:UnPK.N2:U1Ntilde:U1H1:U1H2:U2Ntilde::U2H1:U2H2:......:UnNtilde:UnH1:UnH2:NULL
	w.save.PushBack(ss)
	w.sku1.PushBack(string(skU1.Bytes()))
	return true
}

//ec2
//msgprex = hash
func KeyGenerate_DECDSA(msgprex string, ch chan interface{}, id int, cointype string) bool {
	///////for test only
	/*u1,_ := new(big.Int).SetString("3334747394230983325243207970954899590842441253149295381558648242110081293330",10)
	u2,_ := new(big.Int).SetString("69039181184174029818470298267328820110013585784220774880124345655174594749061",10)
	u3,_ := new(big.Int).SetString("14867692866148859006086889155133300611365049455876397123617203957782293499325",10)
	u4,_ := new(big.Int).SetString("84793511064568272149980886713210270911035531383314504494511304398691848103881",10)
	u5,_ := new(big.Int).SetString("60841277345123397920834696016664146929546891435110670397947900149315293244142",10)

	id1,_ := new(big.Int).SetString("53618612272167874423319834687974778412293696801310558561041950376332309251074",10)
	id2,_ := new(big.Int).SetString("54921957341908846327991236707470353323420933608233375424223802952423356273424",10)
	id3,_ := new(big.Int).SetString("55554820072087080797082013913708076641941533809080830582031668626477915287514",10)
	id4,_ := new(big.Int).SetString("60318458834590464192620032882393176022119815649037676016914795650913223224233",10)
	id5,_ := new(big.Int).SetString("115787261728302521653708661579759215305126272044286142279837734005010875313981",10)

	sku1,_ := new(big.Int).SetString("31191155413895758490308293179882186383085667250661674133654187820857154180677",10)
	sku2,_ := new(big.Int).SetString("47074940619208118544250574667751837749046355150235507843803424053911198813112",10)
	sku3,_ := new(big.Int).SetString("64402190692031667657924912059763629636297143519526964063936831306627647090315",10)
	sku4,_ := new(big.Int).SetString("34772545226428570215016578677967881376777770447360028779798133967936336399940",10)
	sku5,_ := new(big.Int).SetString("79875137852131204821645001934236208017593200315324988641558008769062905261078",10)

	new1,_ := new(big.Int).SetString("90217780269633436353718649612716896878738939932682742626484292501596677805232",10)
	new2,_ := new(big.Int).SetString("93554831225468823981433198553360053376392622858513213953942577456307683005349",10)
	new3,_ := new(big.Int).SetString("67669551554355372044987661383284795264612007389379970801351296782109151089056",10)
	new4,_ := new(big.Int).SetString("109787550781396434316135992389074051324252963495214169195450555312304474730832",10)
	new5,_ := new(big.Int).SetString("48263283217198287895944974605412009346944799039902513035658396575677600708148",10)
	sk := u1
	sk = new(big.Int).Add(sk, u2)
	sk = new(big.Int).Add(sk, u3)
	sk = new(big.Int).Add(sk, u4)
	sk = new(big.Int).Add(sk, u5)
	sk = new(big.Int).Mod(sk, secp256k1.S256().N)

	shareU1 := &ec2.ShareStruct2{Id: id1, Share: sku1}
	shareU2 := &ec2.ShareStruct2{Id: id2, Share: sku2}
	shareU3 := &ec2.ShareStruct2{Id: id3, Share: sku3}
	shareU4 := &ec2.ShareStruct2{Id: id4, Share: sku4}
	shareU5 := &ec2.ShareStruct2{Id: id5, Share: sku5}

	shares := []*ec2.ShareStruct2{shareU1, shareU2, shareU3, shareU4, shareU5}
	computeSK, _ := ec2.Combine2(shares[:3])

	fmt.Println("")
	fmt.Println("[Key Generation][Test] verify vss.Combine:")
	fmt.Println(sk)
	fmt.Println(computeSK)

	//newskU1 := new(big.Int).Mod(new1, secp256k1.S256().N)
	//newskU2 := new(big.Int).Mod(new2, secp256k1.S256().N)
	//newskU3 := new(big.Int).Mod(new3, secp256k1.S256().N)
	//newskU4 := new(big.Int).Mod(new4, secp256k1.S256().N)
	//newskU5 := new(big.Int).Mod(new5, secp256k1.S256().N)
	
	shareNewSkU1 := &ec2.ShareStruct2{Id: id1, Share: new1}
	shareNewSkU2 := &ec2.ShareStruct2{Id: id2, Share: new2}
	shareNewSkU3 := &ec2.ShareStruct2{Id: id3, Share: new3}
	shareNewSkU4 := &ec2.ShareStruct2{Id: id4, Share: new4}
	shareNewSkU5 := &ec2.ShareStruct2{Id: id5, Share: new5}

	sharesNewSkU := []*ec2.ShareStruct2{shareNewSkU1, shareNewSkU2, shareNewSkU3, shareNewSkU4, shareNewSkU5}
	computeNewSK, _ := ec2.Combine2(sharesNewSkU[:4])

	fmt.Println("")
	fmt.Println("测试,新的私钥分片，合起来，是否等于原来的私钥:")
	fmt.Println(sk)
	fmt.Println(computeNewSK)*/
	////////////////////

	if id < 0 || id >= RPCMaxWorker || id >= len(workers) {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get worker ID fail")}
		ch <- res
		return false
	}

	w := workers[id]
	if w.groupid == "" {
		///bug groupid == nil ???
		w, err := FindWorker(msgprex)
		if err != nil || w.groupid == "" {
		    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get group ID fail")}
		    ch <- res
		    return false
		}
		//////
	}

	ns, _ := GetGroup(w.groupid)
	if ns != w.NodeCnt {
		res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGroupNotReady)}
		ch <- res
		return false
	}

	ids := GetIds(cointype, w.groupid)

	//*******************!!!Distributed ECDSA Start!!!**********************************
	u1, u1Poly, u1PolyG, commitU1G, u1PaillierPk, u1PaillierSk, status := DECDSAGenKeyRoundOne(msgprex, ch, w)
	if !status {
		return status
	}

	u1Shares, status := DECDSAGenKeyRoundTwo(msgprex, cointype, ch, w, u1Poly, ids)
	if !status {
		return status
	}

	if !DECDSAGenKeyRoundThree(msgprex, cointype, ch, w, u1PolyG, commitU1G, ids) {
		return false
	}

	sstruct, ds, status := DECDSAGenKeyVerifyShareData(msgprex, cointype, ch, w, u1PolyG, u1Shares, ids)
	if !status {
		return status
	}

	cs, udecom, status := DECDSAGenKeyVerifyCommitment(msgprex, cointype, ch, w, ds, commitU1G, ids)
	if !status {
		return false
	}

	ug, status := DECDSAGenKeyCalcPubKey(msgprex, cointype, ch, w, udecom, ids)
	if !status {
		return false
	}

	skU1, status := DECDSAGenKeyCalcPrivKey(msgprex, cointype, ch, w, sstruct, ids)
	if !status {
		return false
	}

	u1NtildeH1H2, status := DECDSAGenKeyRoundFour(msgprex, ch, w)
	if !status {
		return false
	}

	if !DECDSAGenKeyRoundFive(msgprex, ch, w, u1) {
		return false
	}

	if !DECDSAGenKeyVerifyZKU(msgprex, cointype, ch, w, ids, ug) {
		return false
	}

	if !DECDSAGenKeySaveData(cointype, ids, w, ch, skU1, u1PaillierPk, u1PaillierSk, cs, u1NtildeH1H2) {
		return false
	}
	//*******************!!!Distributed ECDSA End!!!**********************************
	return true
}

