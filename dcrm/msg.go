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
	"github.com/anyswap/Anyswap-MPCNode/internal/common"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"strings"
	"math/big"
	"encoding/hex"
	"fmt"
	"time"
	"container/list"
	"github.com/fsn-dev/cryptoCoins/coins"
	"crypto/ecdsa"
	"github.com/anyswap/Anyswap-MPCNode/crypto"
	"github.com/anyswap/Anyswap-MPCNode/crypto/ecies"
	"strconv"
	"github.com/anyswap/Anyswap-MPCNode/p2p/discover"
	crand "crypto/rand"
	"github.com/fsn-dev/cryptoCoins/coins/types"
	"github.com/fsn-dev/cryptoCoins/tools/rlp"
	"encoding/json"
	"runtime/debug"
	"github.com/anyswap/Anyswap-MPCNode/log"
)

var (
	C1Data  = common.NewSafeMap(10)
	ch_t                     = 300 
	WaitMsgTimeGG20                     = 100
	waitall                     = ch_t * recalc_times
	waitallgg20                     = WaitMsgTimeGG20 * recalc_times
	AgreeWait = 2
	
	//callback
	GetGroup               func(string) (int, string)
	SendToGroupAllNodes    func(string, string) (string, error)
	GetSelfEnode           func() string
	BroadcastInGroupOthers func(string, string) (string, error)
	SendToPeer             func(string, string) error
	ParseNode              func(string) string
	GetEosAccount          func() (string, string, string)
)

//p2p callback
func RegP2pGetGroupCallBack(f func(string) (int, string)) {
	GetGroup = f
}

func RegP2pSendToGroupAllNodesCallBack(f func(string, string) (string, error)) {
	SendToGroupAllNodes = f
}

func RegP2pGetSelfEnodeCallBack(f func() string) {
	GetSelfEnode = f
}

func RegP2pBroadcastInGroupOthersCallBack(f func(string, string) (string, error)) {
	BroadcastInGroupOthers = f
}

func RegP2pSendMsgToPeerCallBack(f func(string, string) error) {
	SendToPeer = f
}

func RegP2pParseNodeCallBack(f func(string) string) {
	ParseNode = f
}

func RegDcrmGetEosAccountCallBack(f func() (string, string, string)) {
	GetEosAccount = f
}

////////////////////////////////

func SendMsgToDcrmGroup(msg string, groupid string) {
	_,err := BroadcastInGroupOthers(groupid, msg)
	if err != nil {
	    hash := Keccak256Hash([]byte(msg)).Hex()
	    log.Error("send msg to group fail","msg hash",hash,"gid",groupid,"err",err)
	}
}

func EncryptMsg(msg string, enodeID string) (string, error) {
	hprv, err1 := hex.DecodeString(enodeID)
	if err1 != nil {
	    return "", err1
	}

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
	    hash := Keccak256Hash([]byte(msg)).Hex()
	    log.Error("encrypt msg fail","msg hash",hash,"err",err)
	    return "", err
	}

	return string(cm), nil
}

func DecryptMsg(cm string) (string, error) {
	nodeKey, errkey := crypto.LoadECDSA(KeyFile)
	if errkey != nil {
		return "", errkey
	}

	prv := ecies.ImportECDSA(nodeKey)
	var m []byte
	m, err := prv.Decrypt([]byte(cm), nil, nil)
	if err != nil {
		return "", err
	}

	return string(m), nil
}

func SendMsgToPeer(enodes string, msg string) {
	en := strings.Split(string(enodes[8:]), "@")
	cm, err := EncryptMsg(msg, en[0])
	if err != nil {
	    return
	}

	err = SendToPeer(enodes, cm)
	if err != nil {
	    hash := Keccak256Hash([]byte(msg)).Hex()
	    log.Error("send msg to peer fail","msg hash",hash,"enode",enodes,"err",err)
	    return
	}
}

type RawReply struct {
    From string
    Accept string
    TimeStamp string
}

func GetRawReply(l *list.List) map[string]*RawReply {
    ret := make(map[string]*RawReply)
    if l == nil {
	return ret
    }

    var next *list.Element
    for e := l.Front(); e != nil; e = next {
	next = e.Next()

	if e.Value == nil {
		continue
	}

	s := e.Value.(string)

	if s == "" {
		continue
	}

	raw := s 
	_,from,_,txdata,err := CheckRaw(raw)
	if err != nil {
	    continue
	}
	
	req,ok := txdata.(*TxDataReqAddr)
	if ok {
	    reply := &RawReply{From:from,Accept:"true",TimeStamp:req.TimeStamp}
	    tmp,ok := ret[from]
	    if !ok {
		ret[from] = reply
	    } else {
		t1,_ := new(big.Int).SetString(reply.TimeStamp,10)
		t2,_ := new(big.Int).SetString(tmp.TimeStamp,10)
		if t1.Cmp(t2) > 0 {
		    ret[from] = reply
		}

	    }

	    continue
	}
	
	lo,ok := txdata.(*TxDataLockOut)
	if ok {
	    reply := &RawReply{From:from,Accept:"true",TimeStamp:lo.TimeStamp}
	    tmp,ok := ret[from]
	    if !ok {
		ret[from] = reply
	    } else {
		t1,_ := new(big.Int).SetString(reply.TimeStamp,10)
		t2,_ := new(big.Int).SetString(tmp.TimeStamp,10)
		if t1.Cmp(t2) > 0 {
		    ret[from] = reply
		}

	    }

	    continue
	}
	
	sig,ok := txdata.(*TxDataSign)
	if ok {
	    reply := &RawReply{From:from,Accept:"true",TimeStamp:sig.TimeStamp}
	    tmp,ok := ret[from]
	    if !ok {
		ret[from] = reply
	    } else {
		t1,_ := new(big.Int).SetString(reply.TimeStamp,10)
		t2,_ := new(big.Int).SetString(tmp.TimeStamp,10)
		if t1.Cmp(t2) > 0 {
		    ret[from] = reply
		}
	    }

	    continue
	}
	
	rh,ok := txdata.(*TxDataReShare)
	if ok {
	    reply := &RawReply{From:from,Accept:"true",TimeStamp:rh.TimeStamp}
	    tmp,ok := ret[from]
	    if !ok {
		ret[from] = reply
	    } else {
		t1,_ := new(big.Int).SetString(reply.TimeStamp,10)
		t2,_ := new(big.Int).SetString(tmp.TimeStamp,10)
		if t1.Cmp(t2) > 0 {
		    ret[from] = reply
		}
	    }

	    continue
	}
	
	acceptreq,ok := txdata.(*TxDataAcceptReqAddr)
	if ok {
	    accept := "false"
	    if acceptreq.Accept == "AGREE" {
		    accept = "true"
	    }

	    reply := &RawReply{From:from,Accept:accept,TimeStamp:acceptreq.TimeStamp}
	    tmp,ok := ret[from]
	    if !ok {
		ret[from] = reply
	    } else {
		t1,_ := new(big.Int).SetString(reply.TimeStamp,10)
		t2,_ := new(big.Int).SetString(tmp.TimeStamp,10)
		if t1.Cmp(t2) > 0 {
		    ret[from] = reply
		}

	    }
	}
	
	acceptlockout,ok := txdata.(*TxDataAcceptLockOut)
	if ok {
	    accept := "false"
	    if acceptlockout.Accept == "AGREE" {
		    accept = "true"
	    }

	    reply := &RawReply{From:from,Accept:accept,TimeStamp:acceptlockout.TimeStamp}
	    tmp,ok := ret[from]
	    if !ok {
		ret[from] = reply
	    } else {
		t1,_ := new(big.Int).SetString(reply.TimeStamp,10)
		t2,_ := new(big.Int).SetString(tmp.TimeStamp,10)
		if t1.Cmp(t2) > 0 {
		    ret[from] = reply
		}

	    }
	}
	
	acceptsig,ok := txdata.(*TxDataAcceptSign)
	if ok {
	    accept := "false"
	    if acceptsig.Accept == "AGREE" {
		    accept = "true"
	    }

	    reply := &RawReply{From:from,Accept:accept,TimeStamp:acceptsig.TimeStamp}
	    tmp,ok := ret[from]
	    if !ok {
		ret[from] = reply
	    } else {
		t1,_ := new(big.Int).SetString(reply.TimeStamp,10)
		t2,_ := new(big.Int).SetString(tmp.TimeStamp,10)
		if t1.Cmp(t2) > 0 {
		    ret[from] = reply
		}

	    }
	}
	
	acceptrh,ok := txdata.(*TxDataAcceptReShare)
	if ok {
	    accept := "false"
	    if acceptrh.Accept == "AGREE" {
		    accept = "true"
	    }

	    reply := &RawReply{From:from,Accept:accept,TimeStamp:acceptrh.TimeStamp}
	    tmp,ok := ret[from]
	    if !ok {
		ret[from] = reply
	    } else {
		t1,_ := new(big.Int).SetString(reply.TimeStamp,10)
		t2,_ := new(big.Int).SetString(tmp.TimeStamp,10)
		if t1.Cmp(t2) > 0 {
		    ret[from] = reply
		}

	    }
	}
    }

    return ret
}

func CheckReply(l *list.List,rt RpcType,key string) bool {
    if l == nil || key == "" {
	return false
    }

    /////reshare only
    if rt == Rpc_RESHARE {
	exsit,da := GetValueFromPubKeyData(key)
	if !exsit {
	    return false
	}

	ac,ok := da.(*AcceptReShareData)
	if !ok || ac == nil {
	    return false
	}

	ret := GetRawReply(l)
	_, enodes := GetGroup(ac.GroupId)
	nodes := strings.Split(enodes, common.Sep2)
	for _, node := range nodes {
	    node2 := ParseNode(node)
	    pk := "04" + node2 
	     h := coins.NewCryptocoinHandler("FSN")
	     if h == nil {
		continue
	     }

	    fr, err := h.PublicKeyToAddress(pk)
	    if err != nil {
		return false
	    }

	    found := false
	    for _,v := range ret {
		if strings.EqualFold(v.From,fr) {
		    found = true
		    break
		}
	    }

	    if !found {
		return false
	    }
	}

	return true
    }
    /////////////////

    k := ""
    if rt == Rpc_REQADDR {
	k = key
    } else {
	k = GetReqAddrKeyByOtherKey(key,rt)
    }

    if k == "" {
	return false
    }

    exsit,da := GetValueFromPubKeyData(k)
    if !exsit {
	return false
    }

    ac,ok := da.(*AcceptReqAddrData)
    if !ok {
	return false
    }

    if ac == nil {
	return false
    }

    ret := GetRawReply(l)

    if rt == Rpc_REQADDR {
	//sigs:  5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
	mms := strings.Split(ac.Sigs, common.Sep)
	count := (len(mms) - 1)/2
	if count <= 0 {
	    return false
	}

	for j:=0;j<count;j++ {
	    found := false
	    for _,v := range ret {
		if strings.EqualFold(v.From,mms[2*j+2]) { //allow user login diffrent node
		    found = true
		    break
		}
	    }

	    if !found {
		return false
	    }
	}

	return true
    }

    if rt == Rpc_LOCKOUT {
	exsit,data := GetValueFromPubKeyData(key)
	if !exsit {
	    return false
	}

	lo,ok := data.(*AcceptLockOutData)
	if !ok || lo == nil {
	    return false
	}

	mms := strings.Split(ac.Sigs, common.Sep)
	_, enodes := GetGroup(lo.GroupId)
	nodes := strings.Split(enodes, common.Sep2)
	for _, node := range nodes {
	    node2 := ParseNode(node)
	    foundeid := false
	    for kk,v := range mms {
		if strings.EqualFold(v,node2) {
		    foundeid = true
		    found := false
		    for _,vv := range ret {
			if strings.EqualFold(vv.From,mms[kk+1]) { //allow user login diffrent node
			    found = true
			    break
			}
		    }

		    if !found {
			return false
		    }

		    break
		}
	    }

	    if !foundeid {
		return false
	    }
	}

	return true
    }

    if rt == Rpc_SIGN {
	exsit,data := GetValueFromPubKeyData(key)
	if !exsit {
	    return false
	}

	sig,ok := data.(*AcceptSignData)
	if !ok || sig == nil {
	    return false
	}

	mms := strings.Split(ac.Sigs, common.Sep)
	_, enodes := GetGroup(sig.GroupId)
	nodes := strings.Split(enodes, common.Sep2)
	for _, node := range nodes {
	    node2 := ParseNode(node)
	    foundeid := false
	    for kk,v := range mms {
		if strings.EqualFold(v,node2) {
		    foundeid = true
		    found := false
		    for _,vv := range ret {
			if strings.EqualFold(vv.From,mms[kk+1]) { //allow user login diffrent node
			    found = true
			    break
			}
		    }

		    if !found {
			return false
		    }

		    break
		}
	    }

	    if !foundeid {
		return false
	    }
	}

	return true
    }

    return false 
}

//-------------------------------------------------------------------------

func Call(msg interface{}, enode string) {
	s := msg.(string)
	if s == "" {
	    return
	}
	
	hash := Keccak256Hash([]byte(s)).Hex()
	log.Info("GET P2P MSG","msg hash",hash,"sender's enode ID",enode)

	raw,err := UnCompress(s)
	if err == nil {
		s = raw
	}
	
	SetUpMsgList(s, enode)
}

func SetUpMsgList(msg string, enode string) {

	v := RecvMsg{msg: msg, sender: enode}
	//rpc-req
	rch := make(chan interface{}, 1)
	req := RPCReq{rpcdata: &v, ch: rch}
	RPCReqQueue <- req
}

func SetUpMsgList3(msg string, enode string,rch chan interface{}) {

	v := RecvMsg{msg: msg, sender: enode}
	//rpc-req
	req := RPCReq{rpcdata: &v, ch: rch}
	RPCReqQueue <- req
}

//---------------------------------------------------------------------------------

type WorkReq interface {
    Run(workid int, ch chan interface{}) bool
}

type RecvMsg struct {
	msg    string
	sender string
}

type SendMsg struct {
	MsgType string
	Nonce   string
	WorkId  int
	Msg     string
}

func (self *RecvMsg) Run(workid int, ch chan interface{}) bool {
	if workid < 0 || workid >= RPCMaxWorker {
		res := RpcDcrmRes{Ret: "", Tip: "get worker ID error", Err: fmt.Errorf("get worker ID error")}
		ch <- res
		return false
	}

	res := self.msg
	if res == "" {
		res2 := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("invalid msg")}
		ch <- res2
		return false
	}

	msgdata, errdec := DecryptMsg(res)
	if errdec == nil {
		res = msgdata
	}
	mm := strings.Split(res, common.Sep)
	if len(mm) >= 2 {
		//msg:  key-enode:C1:X1:X2....:Xn
		//msg:  key-enode1:NoReciv:enode2:C1
		DisMsg(res)
		return true
	}

	msgmap := make(map[string]string)
	err := json.Unmarshal([]byte(res), &msgmap)
	if err == nil {
	    // presign
	    if msgmap["Type"] == "PreSign" {
		ps := &PreSign{}
		if err = ps.UnmarshalJSON([]byte(msgmap["PreSign"]));err == nil {
		    w := workers[workid]
		    w.sid = ps.Nonce 
		    w.groupid = ps.Gid
		    w.DcrmFrom = ps.Pub
		    gcnt, _ := GetGroup(w.groupid)
		    w.NodeCnt = gcnt
		    w.ThresHold = gcnt

		    dcrmpks, _ := hex.DecodeString(ps.Pub)
		    exsit,da := GetPubKeyDataFromLocalDb(string(dcrmpks[:]))
		    if !exsit {
			res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("get pubkey data from db fail")}
			ch <- res
			return false
		    }

		    pd,ok := da.(*PubKeyData)
		    if !ok {
			res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("get pubkey data from db error")}
			ch <- res
			return false
		    }

		    save := (da.(*PubKeyData)).Save
		    ///sku1
		    da2 := GetSkU1FromLocalDb(string(dcrmpks[:]))
		    if da2 == nil {
			    res := RpcDcrmRes{Ret: "", Tip: "get private share fail", Err: fmt.Errorf("get private  share fail")}
			    ch <- res
			    return false
		    }
		    sku1 := new(big.Int).SetBytes(da2)
		    if sku1 == nil {
			    res := RpcDcrmRes{Ret: "", Tip: "get private share fail", Err: fmt.Errorf("get private share fail")}
			    ch <- res
			    return false
		    }
		    //

		    exsit,da3 := GetValueFromPubKeyData(pd.Key)
		    ac,ok := da3.(*AcceptReqAddrData)
		    if ok {
			HandleC1Data(ac,w.sid,workid)
		    }

			var ch1 = make(chan interface{}, 1)
			pre := PreSign_ec3(w.sid,save,sku1,"ECDSA",ch1,workid)
			if pre == nil {
			    tmp := <-ch1
			    ret,ok := tmp.(RpcDcrmRes)
			    if ok {
				ch <-ret
			    } else {
				res := RpcDcrmRes{Ret: "", Tip: "presign fail", Err:fmt.Errorf("presign fail")}
				ch <- res
			    }
			    
			    return false
			}

			pre.Key = w.sid
			pre.Gid = w.groupid
			pre.Used = false
			
			DtPreSign.Lock()
			pub := Keccak256Hash([]byte(strings.ToLower(ps.Pub + ":" + ps.Gid))).Hex()
			err := PutPreSignDataIntoDb(strings.ToLower(pub),pre)
			if err != nil {
			    log.Error("[PRESIGN] failed to generate the presign data","pubkey",ps.Pub,"gid",ps.Gid,"presign data key",w.sid,"err",err)
			    DtPreSign.Unlock()
			    res := RpcDcrmRes{Ret: "", Tip: "presign fail", Err: err}
			    ch <- res
			    return false
			}

			PutPreSign(pub,pre)
			DtPreSign.Unlock()
			
			log.Info("[PRESIGN] pre-generated sign data succeeded","pubkey",ps.Pub,"gid",ps.Gid,"presign data key",w.sid)
			res := RpcDcrmRes{Ret: "success", Tip: "", Err: nil}
			ch <- res
			return true
		}
	    }

	    if msgmap["Type"] == "SignData" {
		sd := &SignData{}
		if err = sd.UnmarshalJSON([]byte(msgmap["SignData"]));err == nil {
		    ys := secp256k1.S256().Marshal(sd.Pkx, sd.Pky)
		    pubkeyhex := hex.EncodeToString(ys)
		    pub := Keccak256Hash([]byte(strings.ToLower(pubkeyhex + ":" + sd.GroupId))).Hex()
		    pre := GetPrePubDataBak(pub,sd.PickKey)
		    if pre == nil {
			log.Error("[SIGN] get pre-sign data fail","key",sd.MsgPrex,"sub-key",sd.Key,"picked key",sd.PickKey,"pre-sign pubkey",pubkeyhex,"pre-sign gid",sd.GroupId,"group nodes",getGroupNodes(sd.GroupId),"unsign tx hash",sd.Txhash)
			res2 := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("get pre sign data fail")}
			ch <- res2
			return false
		    }

		    w := workers[workid]
		    w.sid = sd.Key
		    w.groupid = sd.GroupId
		    
		    w.NodeCnt = sd.NodeCnt
		    w.ThresHold = sd.ThresHold
		    
		    w.DcrmFrom = sd.DcrmFrom

		    dcrmpks, _ := hex.DecodeString(pubkeyhex)
		    exsit,da := GetPubKeyDataFromLocalDb(string(dcrmpks[:]))
		    if exsit {
			    pd,ok := da.(*PubKeyData)
			    if ok {
				exsit,da2 := GetValueFromPubKeyData(pd.Key)
				if exsit {
					ac,ok := da2.(*AcceptReqAddrData)
					if ok {
					    HandleC1Data(ac,sd.Key,workid)
					}
				}

			    }
		    }

		    var ch1 = make(chan interface{}, 1)
		    var reterr error
		    for i:=0;i < recalc_times;i++ {
			if len(ch1) != 0 {
			    <-ch1
			}

			Sign_ec3(sd.Key,sd.Txhash,sd.Keytype,sd.Pkx,sd.Pky,ch1,workid,pre)
			ret, _, cherr := GetChannelValue(WaitMsgTimeGG20 + 10, ch1)
			log.Info("[SIGN] end of running GG20 protocol","key",sd.MsgPrex,"sub-key",sd.Key,"picked key",sd.PickKey,"pre-sign pubkey",pubkeyhex,"pre-sign gid",sd.GroupId,"group nodes",getGroupNodes(sd.GroupId),"unsign tx hash",sd.Txhash,"rsv",ret,"err",cherr)
			if ret != "" && cherr == nil {
			    ww, err2 := FindWorker(sd.MsgPrex)
			    if err2 != nil || ww == nil {
				res2 := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("Not Found Worker")}
				ch <- res2
				return false
			    }

			    ww.rsv.PushBack(ret)
			    res2 := RpcDcrmRes{Ret: ret, Tip: "", Err: nil}
			    ch <- res2
			    return true
			}

			reterr = cherr
		    }

		    res2 := RpcDcrmRes{Ret: "", Tip: "", Err: reterr}
		    ch <- res2
		    return false 
		}
	    }
	}

	signbrocast,err := UnCompressSignBrocastData(res)
	if err == nil {
		errtmp := InitAcceptData2(signbrocast,workid,self.sender,ch)
		if errtmp == nil {
			return true
		}

		return false
	}

	errtmp := InitAcceptData(res,workid,self.sender,ch)
	if errtmp == nil {
	    return true
	}

	return false 
}

func HandleC1Data(ac *AcceptReqAddrData,key string,workid int) {
    //reshare only
    if ac == nil {
	exsit,da := GetValueFromPubKeyData(key)
	if !exsit {
	    return
	}

	ac,ok := da.(*AcceptReShareData)
	if !ok || ac == nil {
	    return
	}

	_, enodes := GetGroup(ac.GroupId)
	nodes := strings.Split(enodes, common.Sep2)
	for _, node := range nodes {
	    node2 := ParseNode(node)
	    pk := "04" + node2 
	     h := coins.NewCryptocoinHandler("FSN")
	     if h == nil {
		continue
	     }

	    fr, err := h.PublicKeyToAddress(pk)
	    if err != nil {
		continue
	    }

	    c1data := key + "-" + fr
	    c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
	    if exist {
		DisAcceptMsg(c1.(string),workid)
		go C1Data.DeleteMap(strings.ToLower(c1data))
	    }
	}

	return
    }
    //reshare only

    if key == "" || workid < 0 || workid >= len(workers) {
	return
    }
   
	_, enodes := GetGroup(ac.GroupId)
	nodes := strings.Split(enodes, common.Sep2)
	for _, node := range nodes {
	    node2 := ParseNode(node)
		c1data := key + "-" + node2 + common.Sep + "SS1"
		c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
		if exist {
		    DisMsg(c1.(string))
		    go C1Data.DeleteMap(strings.ToLower(c1data))
		}
    }
	for _, node := range nodes {
	    node2 := ParseNode(node)
		c1data := key + "-" + node2 + common.Sep + "C11" 
		c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
		if exist {
		    DisMsg(c1.(string))
		    go C1Data.DeleteMap(strings.ToLower(c1data))
		}
    }
	for _, node := range nodes {
	    node2 := ParseNode(node)
		c1data := key + "-" + node2 + common.Sep + "CommitBigVAB" 
		c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
		if exist {
		    DisMsg(c1.(string))
		    go C1Data.DeleteMap(strings.ToLower(c1data))
		}
    }
	for _, node := range nodes {
	    node2 := ParseNode(node)
		c1data := key + "-" + node2 + common.Sep + "C1" 
		c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
		if exist {
		    DisMsg(c1.(string))
		    go C1Data.DeleteMap(strings.ToLower(c1data))
		}
    }
 
    mms := strings.Split(ac.Sigs, common.Sep)
    if len(mms) < 3 { //1:eid1:acc1
	return
    }

    count := (len(mms)-1)/2
    for j := 0;j<count;j++ {
	from := mms[2*j+2]
	c1data := key + "-" + from
	c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
	if exist {
	    DisAcceptMsg(c1.(string),workid)
	    go C1Data.DeleteMap(strings.ToLower(c1data))
	}
    }
}

func GetReqAddrRawValue(raw string) (string,string,string) {
    if raw == "" {
	return "","",""
    }

    tx := new(types.Transaction)
    raws := common.FromHex(raw)
    if err := rlp.DecodeBytes(raws, tx); err != nil {
	return "","",""
    }

    signer := types.NewEIP155Signer(big.NewInt(30400))
    from, err := types.Sender(signer,tx)
    if err != nil {
	return "","",""
    }

    var txtype string
    var timestamp string

    req := TxDataReqAddr{}
    err = json.Unmarshal(tx.Data(), &req)
    if err == nil && req.TxType == "REQDCRMADDR" {
	txtype = "REQDCRMADDR"
	timestamp = req.TimeStamp
    } else {
	acceptreq := TxDataAcceptReqAddr{}
	err = json.Unmarshal(tx.Data(), &acceptreq)
	if err == nil && acceptreq.TxType == "ACCEPTREQADDR" {
	    txtype = "ACCEPTREQADDR"
	    timestamp = acceptreq.TimeStamp
	}
    }

    return from.Hex(),txtype,timestamp
}

func CheckReqAddrDulpRawReply(raw string,l *list.List) bool {
    if l == nil || raw == "" {
	return false
    }
   
    from,txtype,timestamp := GetReqAddrRawValue(raw)

    if from == "" || txtype == "" || timestamp == "" {
	return false
    }
    
    var next *list.Element
    for e := l.Front(); e != nil; e = next {
	next = e.Next()

	if e.Value == nil {
		continue
	}

	s := e.Value.(string)

	if s == "" {
		continue
	}

	if strings.EqualFold(raw,s) {
	   return false 
	}
	
	from2,txtype2,timestamp2 := GetReqAddrRawValue(s)
	if strings.EqualFold(from,from2) && strings.EqualFold(txtype,txtype2) {
	    t1,_ := new(big.Int).SetString(timestamp,10)
	    t2,_ := new(big.Int).SetString(timestamp2,10)
	    if t1.Cmp(t2) > 0 {
		l.Remove(e)
	    } else {
		return false
	    }
	}
    }

    return true
}

func GetReshareRawValue(raw string) (string,string,string) {
    if raw == "" {
	return "","",""
    }

    tx := new(types.Transaction)
    raws := common.FromHex(raw)
    if err := rlp.DecodeBytes(raws, tx); err != nil {
	return "","",""
    }

    signer := types.NewEIP155Signer(big.NewInt(30400))
    from, err := types.Sender(signer,tx)
    if err != nil {
	return "","",""
    }

    var txtype string
    var timestamp string
    
    rh := TxDataReShare{}
    err = json.Unmarshal(tx.Data(), &rh)
    if err == nil && rh.TxType == "RESHARE" {
	txtype = "RESHARE"
	timestamp = rh.TimeStamp
    } else {
	acceptrh := TxDataAcceptReShare{}
	err = json.Unmarshal(tx.Data(), &acceptrh)
	if err == nil && acceptrh.TxType == "ACCEPTRESHARE" {
	    txtype = "ACCEPTRESHARE"
	    timestamp = acceptrh.TimeStamp
	} 
    }

    return from.Hex(),txtype,timestamp
}

func CheckReshareDulpRawReply(raw string,l *list.List) bool {
    if l == nil || raw == "" {
	return false
    }
   
    from,txtype,timestamp := GetReshareRawValue(raw)

    if from == "" || txtype == "" || timestamp == "" {
	return false
    }
    
    var next *list.Element
    for e := l.Front(); e != nil; e = next {
	next = e.Next()

	if e.Value == nil {
		continue
	}

	s := e.Value.(string)

	if s == "" {
		continue
	}

	if strings.EqualFold(raw,s) {
	    return false 
	}
	
	from2,txtype2,timestamp2 := GetReshareRawValue(s)
	if strings.EqualFold(from,from2) && strings.EqualFold(txtype,txtype2) {
	    t1,_ := new(big.Int).SetString(timestamp,10)
	    t2,_ := new(big.Int).SetString(timestamp2,10)
	    if t1.Cmp(t2) > 0 {
		l.Remove(e)
	    } else {
		return false
	    }
	}
    }

    return true
}

func GetSignRawValue(raw string) (string,string,string) {
    if raw == "" {
	return "","",""
    }

    tx := new(types.Transaction)
    raws := common.FromHex(raw)
    if err := rlp.DecodeBytes(raws, tx); err != nil {
	return "","",""
    }

    signer := types.NewEIP155Signer(big.NewInt(30400))
    from, err := types.Sender(signer,tx)
    if err != nil {
	return "","",""
    }

    var txtype string
    var timestamp string
    
    sig := TxDataSign{}
    err = json.Unmarshal(tx.Data(), &sig)
    if err == nil && sig.TxType == "SIGN" {
	txtype = "SIGN"
	timestamp = sig.TimeStamp
    } else {
	pre := TxDataPreSignData{}
	err = json.Unmarshal(tx.Data(), &pre)
	if err == nil && pre.TxType == "PRESIGNDATA" {
	    txtype = "PRESIGNDATA"
	    //timestamp = pre.TimeStamp
	} else {
	    acceptsig := TxDataAcceptSign{}
	    err = json.Unmarshal(tx.Data(), &acceptsig)
	    if err == nil && acceptsig.TxType == "ACCEPTSIGN" {
		txtype = "ACCEPTSIGN"
		timestamp = acceptsig.TimeStamp
	    }
	}
    }

    return from.Hex(),txtype,timestamp
}

func CheckSignDulpRawReply(raw string,l *list.List) bool {
    if l == nil || raw == "" {
	return false
    }
   
    from,txtype,timestamp := GetSignRawValue(raw)

    if from == "" || txtype == "" || timestamp == "" {
	return false
    }
    
    var next *list.Element
    for e := l.Front(); e != nil; e = next {
	next = e.Next()

	if e.Value == nil {
		continue
	}

	s := e.Value.(string)

	if s == "" {
		continue
	}

	if strings.EqualFold(raw,s) {
	   return false 
	}
	
	from2,txtype2,timestamp2 := GetSignRawValue(s)
	if strings.EqualFold(from,from2) && strings.EqualFold(txtype,txtype2) {
	    t1,_ := new(big.Int).SetString(timestamp,10)
	    t2,_ := new(big.Int).SetString(timestamp2,10)
	    if t1.Cmp(t2) > 0 {
		l.Remove(e)
	    } else {
		return false
	    }
	}
    }

    return true
}

func DisAcceptMsg(raw string,workid int) {
    defer func() {
        if r := recover(); r != nil {
	    fmt.Errorf("DisAcceptMsg Runtime error: %v\n%v", r, string(debug.Stack()))
	    return
        }
    }()

    if raw == "" || workid < 0 || workid >= len(workers) {
	return
    }

    w := workers[workid]
    if w == nil {
	return
    }

    key,_,_,txdata,err := CheckRaw(raw)
    if err != nil {
	return
    }
    
    _,ok := txdata.(*TxDataReqAddr)
    if ok {
	if Find(w.msg_acceptreqaddrres,raw) {
		return
	}

	if !CheckReqAddrDulpRawReply(raw,w.msg_acceptreqaddrres) {
	    return
	}

	w.msg_acceptreqaddrres.PushBack(raw)
	if w.msg_acceptreqaddrres.Len() >= w.NodeCnt {
	    if !CheckReply(w.msg_acceptreqaddrres,Rpc_REQADDR,key) {
		return
	    }

	    w.bacceptreqaddrres <- true
	    exsit,da := GetValueFromPubKeyData(key)
	    if !exsit {
		return
	    }

	    ac,ok := da.(*AcceptReqAddrData)
	    if !ok || ac == nil {
		return
	    }

	    workers[ac.WorkId].acceptReqAddrChan <- "go on"
	}
    }
    
    _,ok = txdata.(*TxDataLockOut)
    if ok {
	if Find(w.msg_acceptlockoutres, raw) {
	    return
	}

	w.msg_acceptlockoutres.PushBack(raw)
	if w.msg_acceptlockoutres.Len() >= w.ThresHold {
	    if !CheckReply(w.msg_acceptlockoutres,Rpc_LOCKOUT,key) {
		return
	    }

	    w.bacceptlockoutres <- true
	    exsit,da := GetValueFromPubKeyData(key)
	    if !exsit {
		return
	    }

	    ac,ok := da.(*AcceptLockOutData)
	    if !ok || ac == nil {
		return
	    }

	    workers[ac.WorkId].acceptLockOutChan <- "go on"
	}
    }
    
    _,ok = txdata.(*TxDataSign)
    if ok {
	if Find(w.msg_acceptsignres, raw) {
	    return
	}

	if !CheckSignDulpRawReply(raw,w.msg_acceptsignres) {
	    return
	}

	w.msg_acceptsignres.PushBack(raw)
	if w.msg_acceptsignres.Len() >= w.ThresHold {
	    if !CheckReply(w.msg_acceptsignres,Rpc_SIGN,key) {
		return
	    }

	    w.bacceptsignres <- true
	    exsit,da := GetValueFromPubKeyData(key)
	    if !exsit {
		return
	    }

	    ac,ok := da.(*AcceptSignData)
	    if !ok || ac == nil {
		return
	    }

	    workers[ac.WorkId].acceptSignChan <- "go on"
	}
    }
    
    _,ok = txdata.(*TxDataReShare)
    if ok {
	if Find(w.msg_acceptreshareres, raw) {
	    return
	}

	if !CheckReshareDulpRawReply(raw,w.msg_acceptreshareres) {
	    return
	}

	w.msg_acceptreshareres.PushBack(raw)
	if w.msg_acceptreshareres.Len() >= w.NodeCnt {
	    if !CheckReply(w.msg_acceptreshareres,Rpc_RESHARE,key) {
		return
	    }

	    w.bacceptreshareres <- true
	    exsit,da := GetValueFromPubKeyData(key)
	    if !exsit {
		return
	    }

	    ac,ok := da.(*AcceptReShareData)
	    if !ok || ac == nil {
		return
	    }

	    workers[ac.WorkId].acceptReShareChan <- "go on"
	}
    }
    
    acceptreq,ok := txdata.(*TxDataAcceptReqAddr)
    if ok {
	if Find(w.msg_acceptreqaddrres,raw) {
		return
	}

	if !CheckReqAddrDulpRawReply(raw,w.msg_acceptreqaddrres) {
	    return
	}

	w.msg_acceptreqaddrres.PushBack(raw)
	if w.msg_acceptreqaddrres.Len() >= w.NodeCnt {
	    if !CheckReply(w.msg_acceptreqaddrres,Rpc_REQADDR,acceptreq.Key) {
		return
	    }

	    w.bacceptreqaddrres <- true
	    exsit,da := GetValueFromPubKeyData(acceptreq.Key)
	    if !exsit {
		return
	    }

	    ac,ok := da.(*AcceptReqAddrData)
	    if !ok || ac == nil {
		return
	    }

	    workers[ac.WorkId].acceptReqAddrChan <- "go on"
	}
    }
    
    acceptlockout,ok := txdata.(*TxDataAcceptLockOut)
    if ok {
	if Find(w.msg_acceptlockoutres, raw) {
	    return
	}

	w.msg_acceptlockoutres.PushBack(raw)
	if w.msg_acceptlockoutres.Len() >= w.ThresHold {
	    if !CheckReply(w.msg_acceptlockoutres,Rpc_LOCKOUT,acceptlockout.Key) {
		return
	    }

	    w.bacceptlockoutres <- true
	    exsit,da := GetValueFromPubKeyData(acceptlockout.Key)
	    if !exsit {
		return
	    }

	    ac,ok := da.(*AcceptLockOutData)
	    if !ok || ac == nil {
		return
	    }

	    workers[ac.WorkId].acceptLockOutChan <- "go on"
	}
    }
    
    acceptsig,ok := txdata.(*TxDataAcceptSign)
    if ok {
	if Find(w.msg_acceptsignres, raw) {
	    return
	}

	if !CheckSignDulpRawReply(raw,w.msg_acceptsignres) {
	    return
	}

	w.msg_acceptsignres.PushBack(raw)
	if w.msg_acceptsignres.Len() >= w.ThresHold {
	    if !CheckReply(w.msg_acceptsignres,Rpc_SIGN,acceptsig.Key) {
		return
	    }

	    w.bacceptsignres <- true
	    exsit,da := GetValueFromPubKeyData(acceptsig.Key)
	    if !exsit {
		return
	    }

	    ac,ok := da.(*AcceptSignData)
	    if !ok || ac == nil {
		return
	    }

	    workers[ac.WorkId].acceptSignChan <- "go on"
	}
    }
    
    acceptreshare,ok := txdata.(*TxDataAcceptReShare)
    if ok {
	if Find(w.msg_acceptreshareres, raw) {
	    return
	}

	if !CheckReshareDulpRawReply(raw,w.msg_acceptreshareres) {
	    return
	}

	w.msg_acceptreshareres.PushBack(raw)
	if w.msg_acceptreshareres.Len() >= w.NodeCnt {
	    if !CheckReply(w.msg_acceptreshareres,Rpc_RESHARE,acceptreshare.Key) {
		return
	    }

	    w.bacceptreshareres <- true
	    exsit,da := GetValueFromPubKeyData(acceptreshare.Key)
	    if !exsit {
		return
	    }

	    ac,ok := da.(*AcceptReShareData)
	    if !ok || ac == nil {
		return
	    }

	    workers[ac.WorkId].acceptReShareChan <- "go on"
	}
    }
}

func InitAcceptData(raw string,workid int,sender string,ch chan interface{}) error {
    if raw == "" || workid < 0 || sender == "" {
	res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("parameter error")}
	ch <- res
	return fmt.Errorf("parameter error")
    }

    key,from,nonce,txdata,err := CheckRaw(raw)
    if err != nil {
	res := RpcDcrmRes{Ret: "", Tip: err.Error(), Err: err}
	ch <- res
	return err
    }

    hash := Keccak256Hash([]byte(raw)).Hex()
    req,ok := txdata.(*TxDataReqAddr)
    if ok {
	exsit,_ := GetValueFromPubKeyData(key)
	if !exsit {
	    cur_nonce, _, _ := GetReqAddrNonce(from)
	    cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
	    new_nonce_num, _ := new(big.Int).SetString(nonce, 10)
	    if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
		_, err := SetReqAddrNonce(from,nonce)
		if err == nil {
		    ars := GetAllReplyFromGroup(workid,req.GroupId,Rpc_REQADDR,sender)
		    sigs,err := GetGroupSigsDataByRaw(raw) 
		    if err != nil {
			log.Error("[KEYGEN] failed to get the signature of node ID from raw data","err",err,"key",key,"raw data hash",hash)
			res := RpcDcrmRes{Ret: "", Tip: err.Error(), Err: err}
			ch <- res
			return err
		    }

		    ac := &AcceptReqAddrData{Initiator:sender,Account: from, Cointype: "ALL", GroupId: req.GroupId, Nonce: nonce, LimitNum: req.ThresHold, Mode: req.Mode, TimeStamp: req.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", PubKey: "", Tip: "", Error: "", AllReply: ars, WorkId: workid,Sigs:sigs}
		    err = SaveAcceptReqAddrData(ac)
		   if err == nil {
			log.Info("[KEYGEN] save data to be approved","from",from,"key",key,"raw data hash",hash)
			rch := make(chan interface{}, 1)
			w := workers[workid]
			w.sid = key 
			w.groupid = req.GroupId
			w.limitnum = req.ThresHold
			gcnt, _ := GetGroup(w.groupid)
			w.NodeCnt = gcnt
			w.ThresHold = w.NodeCnt

			nums := strings.Split(w.limitnum, "/")
			if len(nums) == 2 {
			    nodecnt, err := strconv.Atoi(nums[1])
			    if err == nil {
				w.NodeCnt = nodecnt
			    }

			    th, err := strconv.Atoi(nums[0])
			    if err == nil {
				w.ThresHold = th 
			    }
			}

			if req.Mode == "0" { // self-group
				var reply bool
				var tip string
				timeout := make(chan bool, 1)
				go func(wid int) {
					cur_enode = discover.GetLocalID().String() //GetSelfEnode()
					agreeWaitTime := 10 * time.Minute
					agreeWaitTimeOut := time.NewTicker(agreeWaitTime)
					if wid < 0 || wid >= len(workers) || workers[wid] == nil {
						ars := GetAllReplyFromGroup(w.id,req.GroupId,Rpc_REQADDR,sender)	
						_,err = AcceptReqAddr(sender,from, "ALL", req.GroupId, nonce, req.ThresHold, req.Mode, "false", "false", "Failure", "", "workid error", "workid error", ars, wid,"")
						if err != nil {
						    tip = "accept reqaddr error"
						    reply = false
						    timeout <- true
						    return
						}

						tip = "worker id error"
						reply = false
						timeout <- true
						return
					}

					wtmp2 := workers[wid]
					for {
						select {
						case account := <-wtmp2.acceptReqAddrChan:
							log.Debug("(self *RecvMsg) Run(),", "account", account, "key", key)
							ars := GetAllReplyFromGroup(w.id,req.GroupId,Rpc_REQADDR,sender)
							log.Info("[KEYGEN] get approval replies from all nodes in the group","raw data hash",hash,"replies",ars,"key",key)

							reply = true
							for _,nr := range ars {
							    if !strings.EqualFold(nr.Status,"Agree") {
								reply = false
								break
							    }
							}

							if !reply {
								tip = "don't accept req addr"
								_,err = AcceptReqAddr(sender,from, "ALL", req.GroupId,nonce, req.ThresHold, req.Mode, "false", "false", "Failure", "", "don't accept req addr", "don't accept req addr", ars, wid,"")
								if err != nil {
								    tip = "don't accept req addr and accept reqaddr error"
								    timeout <- true
								    return
								}
							} else {
								tip = ""
								_,err = AcceptReqAddr(sender,from, "ALL", req.GroupId,nonce, req.ThresHold, req.Mode, "false", "true", "Pending", "", "", "", ars, wid,"")
								if err != nil {
								    tip = "accept reqaddr error"
								    timeout <- true
								    return
								}
							}
							
							timeout <- true
							return
						case <-agreeWaitTimeOut.C:
							ars := GetAllReplyFromGroup(w.id,req.GroupId,Rpc_REQADDR,sender)
							for _,v := range ars {
							    if !strings.EqualFold(v.Status,"Agree") {
								log.Error("[KEYGEN] agree wait timeout","raw data hash",hash,"key",key,"node ID",v.Enode,"approval replie",v.Status)
							    }
							}

							//bug: if self not accept and timeout
							_,err = AcceptReqAddr(sender,from, "ALL", req.GroupId, nonce, req.ThresHold, req.Mode, "false", "false", "Timeout", "", "get other node accept req addr result timeout", "get other node accept req addr result timeout", ars, wid,"")
							if err != nil {
							    tip = "get other node accept req addr result timeout and accept reqaddr fail"
							    reply = false
							    timeout <- true
							    return
							}

							tip = "get other node accept req addr result timeout"
							reply = false
							//

							timeout <- true
							return
						}
					}
				}(workid)

				if len(workers[workid].acceptWaitReqAddrChan) == 0 {
					workers[workid].acceptWaitReqAddrChan <- "go on"
				}

				DisAcceptMsg(raw,workid)
				HandleC1Data(ac,key,workid)

				<-timeout

				ars := GetAllReplyFromGroup(w.id,req.GroupId,Rpc_REQADDR,sender)
				if !reply {
					log.Error("[KEYGEN] get approval replies from all nodes in the group,not all agree,keygen fail","raw data hash",hash,"key",key,"replies",ars)
					if tip == "get other node accept req addr result timeout" {
						_,err = AcceptReqAddr(sender,from, "ALL", req.GroupId, nonce, req.ThresHold, req.Mode, "false", "", "Timeout", "", tip, "don't accept req addr.", ars, workid,"")
					} else {
						_,err = AcceptReqAddr(sender,from, "ALL", req.GroupId, nonce, req.ThresHold, req.Mode, "false", "", "Failure", "", tip, "don't accept req addr.", ars, workid,"")
					}

					if err != nil {
					    res := RpcDcrmRes{Ret:"", Tip: tip, Err: fmt.Errorf("don't accept req addr.")}
					    ch <- res
					    return fmt.Errorf("don't accept req addr.")
					}

					res := RpcDcrmRes{Ret: strconv.Itoa(workid) + common.Sep + "rpc_req_dcrmaddr", Tip: tip, Err: fmt.Errorf("don't accept req addr.")}
					ch <- res
					return fmt.Errorf("don't accept req addr.")
				}
			} else {
				if len(workers[workid].acceptWaitReqAddrChan) == 0 {
					workers[workid].acceptWaitReqAddrChan <- "go on"
				}

				ars := GetAllReplyFromGroup(w.id,req.GroupId,Rpc_REQADDR,sender)
				_,err = AcceptReqAddr(sender,from, "ALL", req.GroupId,nonce, req.ThresHold, req.Mode, "false", "true", "Pending", "", "", "", ars, workid,"")
				if err != nil {
				    res := RpcDcrmRes{Ret:"", Tip: err.Error(), Err: err}
				    ch <- res
				    return err
				}
			}

			dcrm_genPubKey(w.sid, from, "ALL", rch, req.Mode, nonce)
			chret, tip, cherr := GetChannelValue(waitall, rch)
			if cherr != nil {
				log.Error("[KEYGEN] keygen fail","err",cherr,"key",key,"raw data hash",hash)
				ars := GetAllReplyFromGroup(w.id,req.GroupId,Rpc_REQADDR,sender)
				_,err = AcceptReqAddr(sender,from, "ALL", req.GroupId, nonce, req.ThresHold, req.Mode, "false", "", "Failure", "", tip, cherr.Error(), ars, workid,"")
				if err != nil {
				    res := RpcDcrmRes{Ret:"", Tip:err.Error(), Err:err}
				    ch <- res
				    return err
				}

				res := RpcDcrmRes{Ret: strconv.Itoa(workid) + common.Sep + "rpc_req_dcrmaddr", Tip: tip, Err: cherr}
				ch <- res
				return cherr 
			}

			log.Info("[KEYGEN] keygen successfully","pubkey",chret,"key",key,"raw data hash",hash)
			res := RpcDcrmRes{Ret: strconv.Itoa(workid) + common.Sep + "rpc_req_dcrmaddr" + common.Sep + chret, Tip: "", Err: nil}
			ch <- res
			return nil
		   }
		}
	    }
	}
    }

    rh,ok := txdata.(*TxDataReShare)
    if ok {
	ars := GetAllReplyFromGroup(workid,rh.GroupId,Rpc_RESHARE,sender)
	sigs,err := GetGroupSigsDataByRaw(raw) 
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: err.Error(), Err: err}
	    ch <- res
	    return err
	}

	ac := &AcceptReShareData{Initiator:sender,Account: from, GroupId: rh.GroupId, TSGroupId:rh.TSGroupId, PubKey: rh.PubKey, LimitNum: rh.ThresHold, PubAccount:rh.Account, Mode:rh.Mode, Sigs:sigs, TimeStamp: rh.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", NewSk: "", Tip: "", Error: "", AllReply: ars, WorkId:workid}
	err = SaveAcceptReShareData(ac)
	if err == nil {
	    log.Info("[RESHARE] save data to be approved","from",from,"key",key,"raw data hash",hash)
	    w := workers[workid]
	    w.sid = key 
	    w.groupid = rh.TSGroupId 
	    w.limitnum = rh.ThresHold
	    gcnt, _ := GetGroup(w.groupid)
	    w.NodeCnt = gcnt
	    w.ThresHold = w.NodeCnt

	    nums := strings.Split(w.limitnum, "/")
	    if len(nums) == 2 {
		nodecnt, err := strconv.Atoi(nums[1])
		if err == nil {
		    w.NodeCnt = nodecnt
		}

		w.ThresHold = gcnt
	    }

	    w.DcrmFrom = rh.PubKey  // pubkey replace dcrmfrom in reshare 

	    var reply bool
	    var tip string
	    timeout := make(chan bool, 1)
	    go func(wid int) {
		    cur_enode = discover.GetLocalID().String() //GetSelfEnode()
		    agreeWaitTime := 10 * time.Minute
		    agreeWaitTimeOut := time.NewTicker(agreeWaitTime)

		    wtmp2 := workers[wid]

		    for {
			    select {
			    case account := <-wtmp2.acceptReShareChan:
				    log.Debug("(self *RecvMsg) Run(),", "account", account, "key", key)
				    ars := GetAllReplyFromGroup(w.id,rh.GroupId,Rpc_RESHARE,sender)
				    log.Info("[RESHARE] get approval replies from all nodes in the group","raw data hash",hash,"replies",ars,"key",key)
				    //bug
				    reply = true
				    for _,nr := range ars {
					if !strings.EqualFold(nr.Status,"Agree") {
					    reply = false
					    break
					}
				    }
				    //

				    if !reply {
					    tip = "don't accept reshare"
					    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "false", "Failure", "", "don't accept reshare", "don't accept reshare", nil, wid)
				    } else {
					    tip = ""
					    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "false", "pending", "", "", "", ars, wid)
				    }

				    if err != nil {
					tip = tip + " and accept reshare data fail"
				    }

				    ///////
				    timeout <- true
				    return
			    case <-agreeWaitTimeOut.C:
				    ars := GetAllReplyFromGroup(w.id,rh.GroupId,Rpc_RESHARE,sender)
				    for _,v := range ars {
					if !strings.EqualFold(v.Status,"Agree") {
					    log.Error("[RESHARE] agree wait timeout","raw data hash",hash,"key",key,"node ID",v.Enode,"approval replie",v.Status)
					}
				    }

				    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "false", "Timeout", "", "get other node accept reshare result timeout", "get other node accept reshare result timeout", ars, wid)
				    reply = false
				    tip = "get other node accept reshare result timeout"
				    if err != nil {
					tip = tip + " and accept reshare data fail"
				    }
				    //

				    timeout <- true
				    return
			    }
		    }
	    }(workid)

	    if len(workers[workid].acceptWaitReShareChan) == 0 {
		    workers[workid].acceptWaitReShareChan <- "go on"
	    }

	    DisAcceptMsg(raw,workid)
	    HandleC1Data(nil,key,workid)
	    
	    <-timeout

	    if !reply {
		    //////////////////////reshare result start/////////////////////////
		    if tip == "get other node accept reshare result timeout" {
			    ars := GetAllReplyFromGroup(workid,rh.GroupId,Rpc_RESHARE,sender)
			    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold, rh.Mode,"false", "", "Timeout", "", "get other node accept reshare result timeout", "get other node accept reshare result timeout", ars,workid)
		    } else {
			    /////////////TODO tmp
			    //sid-enode:SendReShareRes:Success:rsv
			    //sid-enode:SendReShareRes:Fail:err
			    mp := []string{w.sid, cur_enode}
			    enode := strings.Join(mp, "-")
			    s0 := "SendReShareRes"
			    s1 := "Fail"
			    s2 := "don't accept reshare."
			    ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
			    SendMsgToDcrmGroup(ss, rh.GroupId)
			    DisMsg(ss)
			    _, _, err := GetChannelValue(ch_t, w.bsendreshareres)
			    ars := GetAllReplyFromGroup(w.id,rh.GroupId,Rpc_RESHARE,sender)
			    if err != nil {
				    tip = "get other node terminal accept reshare result timeout" ////bug
				    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "", "Timeout", "", tip,tip, ars, workid)
				    if err != nil {
					tip = tip + " and accept reshare data fail"
				    }

			    } else if w.msg_sendreshareres.Len() != w.ThresHold {
				    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold, rh.Mode,"false", "", "Failure", "", "get other node reshare result fail","get other node reshare result fail",ars, workid)
				    if err != nil {
					tip = tip + " and accept reshare data fail"
				    }
			    } else {
				    reply2 := "false"
				    lohash := ""
				    iter := w.msg_sendreshareres.Front()
				    for iter != nil {
					    mdss := iter.Value.(string)
					    ms := strings.Split(mdss, common.Sep)
					    if strings.EqualFold(ms[2], "Success") {
						    reply2 = "true"
						    lohash = ms[3]
						    break
					    }

					    lohash = ms[3]
					    iter = iter.Next()
				    }

				    if reply2 == "true" {
					    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold, rh.Mode,"true", "true", "Success", lohash," "," ",ars, workid)
					    if err != nil {
						tip = tip + " and accept reshare data fail"
					    }
				    } else {
					    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "", "Failure", "",lohash,lohash,ars, workid)
					    if err != nil {
						tip = tip + " and accept reshare data fail"
					    }
				    }
			    }
		    }

		    res2 := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("don't accept reshare.")}
		    ch <- res2
		    return fmt.Errorf("don't accept reshare.")
	    }

	    rch := make(chan interface{}, 1)
	    reshare(w.sid,from,rh.GroupId,rh.PubKey,rh.Account,rh.Mode,sigs,rch)
	    chret, tip, cherr := GetChannelValue(ch_t, rch)
	    if chret != "" {
		    res2 := RpcDcrmRes{Ret: chret, Tip: "", Err: nil}
		    ch <- res2
		    return nil 
	    }

	    if tip == "get other node accept reshare result timeout" {
		    ars := GetAllReplyFromGroup(workid,rh.GroupId,Rpc_RESHARE,sender)
		    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "", "Timeout", "", "get other node accept reshare result timeout", "get other node accept reshare result timeout", ars,workid)
	    } else {
		    /////////////TODO tmp
		    //sid-enode:SendReShareRes:Success:rsv
		    //sid-enode:SendReShareRes:Fail:err
		    mp := []string{w.sid, cur_enode}
		    enode := strings.Join(mp, "-")
		    s0 := "SendReShareRes"
		    s1 := "Fail"
		    s2 := "don't accept reshare."
		    ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
		    SendMsgToDcrmGroup(ss, rh.GroupId)
		    DisMsg(ss)
		    _, _, err := GetChannelValue(ch_t, w.bsendreshareres)
		    ars := GetAllReplyFromGroup(w.id,rh.GroupId,Rpc_RESHARE,sender)
		    if err != nil {
			    tip = "get other node terminal accept reshare result timeout" ////bug
			    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "", "Timeout", "", tip,tip, ars, workid)
			    if err != nil {
				tip = tip + " and accept reshare data fail"
			    }
		    } else if w.msg_sendsignres.Len() != w.ThresHold {
			    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "", "Failure", "", "get other node reshare result fail","get other node reshare result fail",ars, workid)
			    if err != nil {
				tip = tip + " and accept reshare data fail"
			    }
		    } else {
			    reply2 := "false"
			    lohash := ""
			    iter := w.msg_sendreshareres.Front()
			    for iter != nil {
				    mdss := iter.Value.(string)
				    ms := strings.Split(mdss, common.Sep)
				    if strings.EqualFold(ms[2], "Success") {
					    reply2 = "true"
					    lohash = ms[3]
					    break
				    }

				    lohash = ms[3]
				    iter = iter.Next()
			    }

			    if reply2 == "true" {
				    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"true", "true", "Success", lohash," "," ",ars, workid)
				    if err != nil {
					tip = tip + " and accept reshare data fail"
				    }
			    } else {
				    _,err = AcceptReShare(sender,from, rh.GroupId,rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "", "Failure", "",lohash,lohash,ars,workid)
				    if err != nil {
					tip = tip + " and accept reshare data fail"
				    }
			    }
		    }
	    }

	    if cherr != nil {
		    res2 := RpcDcrmRes{Ret:"", Tip: tip, Err: cherr}
		    ch <- res2
		    return cherr 
	    }

	    res2 := RpcDcrmRes{Ret:"", Tip: tip, Err: fmt.Errorf("reshare fail.")}
	    ch <- res2
	    return fmt.Errorf("reshare fail.")
	}
    }

    acceptreq,ok := txdata.(*TxDataAcceptReqAddr)
    if ok {
	w, err := FindWorker(acceptreq.Key)
	if err != nil || w == nil {
	    c1data := acceptreq.Key + "-" + from
	    C1Data.WriteMap(strings.ToLower(c1data),raw)
	    res := RpcDcrmRes{Ret:"Failure", Tip: "", Err: fmt.Errorf("get worker fail")}
	    ch <- res
	    return fmt.Errorf("get worker fail")
	}

	exsit,da := GetValueFromPubKeyData(acceptreq.Key)
	if !exsit {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "", Err: fmt.Errorf("get pubkey data fail")}
	    ch <- res
	    return fmt.Errorf("get pubkey data fail")
	}

	ac,ok := da.(*AcceptReqAddrData)
	if !ok || ac == nil {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "get pubkey data fail", Err: fmt.Errorf("get pubkey data fail")}
	    ch <- res
	    return fmt.Errorf("get pubkey data fail")
	}

	status := "Pending"
	accept := "false"
	if acceptreq.Accept == "AGREE" {
		accept = "true"
	} else {
		status = "Failure"
	}

	id,_ := GetWorkerId(w)
	DisAcceptMsg(raw,id)
	HandleC1Data(ac,acceptreq.Key,id)

	ars := GetAllReplyFromGroup(id,ac.GroupId,Rpc_REQADDR,ac.Initiator)
	tip, err := AcceptReqAddr(ac.Initiator,ac.Account, ac.Cointype, ac.GroupId, ac.Nonce, ac.LimitNum, ac.Mode, "false", accept, status, "", "", "", ars, ac.WorkId,"")
	if err != nil {
	    res := RpcDcrmRes{Ret:"Failure", Tip: tip, Err: err}
	    ch <- res
	    return err 
	}

	res := RpcDcrmRes{Ret:"Success", Tip: "", Err: nil}
	ch <- res
	return nil
    }

    acceptsig,ok := txdata.(*TxDataAcceptSign)
    if ok {
	log.Info("[ACCEPT SIGN] get sign accept data","key ",acceptsig.Key,"from ",from,"accept",acceptsig.Accept,"raw data hash",hash)
	w, err := FindWorker(acceptsig.Key)
	if err != nil || w == nil {
	    c1data := acceptsig.Key + "-" + from
	    C1Data.WriteMap(strings.ToLower(c1data),raw)
	    res := RpcDcrmRes{Ret:"Failure", Tip: "", Err: fmt.Errorf("get worker fail")}
	    ch <- res
	    return fmt.Errorf("get worker fail")
	}

	exsit,da := GetValueFromPubKeyData(acceptsig.Key)
	if !exsit {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "", Err: fmt.Errorf("get pubkey data from db fail")}
	    ch <- res
	    return fmt.Errorf("get pubkey data from db fail")
	}

	ac,ok := da.(*AcceptSignData)
	if !ok || ac == nil {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "", Err: fmt.Errorf("get pubkey data from db fail")}
	    ch <- res
	    return fmt.Errorf("get pubkey data from db fail")
	}

	if ac.Deal == "true" || ac.Status == "Success" || ac.Status == "Failure" || ac.Status == "Timeout" {
	    res := RpcDcrmRes{Ret:"", Tip: "", Err: fmt.Errorf("the signature has been processed")}
	    ch <- res
	    return fmt.Errorf("the signature has been processed")
	}

	status := "Pending"
	accept := "false"
	if acceptsig.Accept == "AGREE" {
		accept = "true"
	} else {
		status = "Failure"
	}

	id,_ := GetWorkerId(w)
	DisAcceptMsg(raw,id)
	reqaddrkey := GetReqAddrKeyByOtherKey(acceptsig.Key,Rpc_SIGN)
	exsit,da = GetValueFromPubKeyData(reqaddrkey)
	if !exsit {
	    res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("get keygen info from db fail")}
	    ch <- res
	    return fmt.Errorf("get keygen info from db fail")
	}

	acceptreqdata,ok := da.(*AcceptReqAddrData)
	if !ok || acceptreqdata == nil {
	    res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("get keygen info from db fail")}
	    ch <- res
	    return fmt.Errorf("get keygen info from db fail")
	}

	HandleC1Data(acceptreqdata,acceptsig.Key,id)

	ars := GetAllReplyFromGroup(id,ac.GroupId,Rpc_SIGN,ac.Initiator)
	if ac.Deal == "true" || ac.Status == "Success" || ac.Status == "Failure" || ac.Status == "Timeout" {
	    res := RpcDcrmRes{Ret:"", Tip: "the signature has been processed", Err: fmt.Errorf("the signature has been processed")}
	    ch <- res
	    return fmt.Errorf("the signature has been processed")
	}

	tip, err := AcceptSign(ac.Initiator,ac.Account, ac.PubKey, ac.MsgHash, ac.Keytype, ac.GroupId, ac.Nonce,ac.LimitNum,ac.Mode,"false", accept, status, "", "", "", ars, ac.WorkId)
	if err != nil {
	    res := RpcDcrmRes{Ret:"Failure", Tip: tip, Err: err}
	    ch <- res
	    return err 
	}

	res := RpcDcrmRes{Ret:"Success", Tip: "", Err: nil}
	ch <- res
	return nil
    }

    acceptrh,ok := txdata.(*TxDataAcceptReShare)
    if ok {
	w, err := FindWorker(acceptrh.Key)
	if err != nil || w == nil {
	    c1data := acceptrh.Key + "-" + from
	    C1Data.WriteMap(strings.ToLower(c1data),raw)
	    res := RpcDcrmRes{Ret:"Failure", Tip: "", Err: fmt.Errorf("get reshare accept data fail from db")}
	    ch <- res
	    return fmt.Errorf("get reshare accept data fail from db")
	}

	exsit,da := GetValueFromPubKeyData(acceptrh.Key)
	if !exsit {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "", Err: fmt.Errorf("get reshare accept data fail from db")}
	    ch <- res
	    return fmt.Errorf("get reshare accept data fail from db")
	}

	ac,ok := da.(*AcceptReShareData)
	if !ok || ac == nil {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "", Err: fmt.Errorf("get reshare accept data fail from db")}
	    ch <- res
	    return fmt.Errorf("get reshare accept data fail from db")
	}

	status := "Pending"
	accept := "false"
	if acceptrh.Accept == "AGREE" {
		accept = "true"
	} else {
		status = "Failure"
	}

	id,_ := GetWorkerId(w)
	DisAcceptMsg(raw,id)
	HandleC1Data(nil,acceptrh.Key,id)

	ars := GetAllReplyFromGroup(id,ac.GroupId,Rpc_RESHARE,ac.Initiator)
	tip,err := AcceptReShare(ac.Initiator,ac.Account, ac.GroupId, ac.TSGroupId,ac.PubKey, ac.LimitNum, ac.Mode,"false", accept, status, "", "", "", ars,ac.WorkId)
	if err != nil {
	    res := RpcDcrmRes{Ret:"Failure", Tip: tip, Err: err}
	    ch <- res
	    return err 
	}

	res := RpcDcrmRes{Ret:"Success", Tip: "", Err: nil}
	ch <- res
	return nil
    }
	
    res := RpcDcrmRes{Ret: "", Tip: "", Err: fmt.Errorf("unknown error")}
    ch <- res
    return fmt.Errorf("unknown error")
}

//-------------------------------------------------------------------------------------

func GetGroupSigsDataByRaw(raw string) (string,error) {
    if raw == "" {
	return "",fmt.Errorf("raw data empty")
    }
    
    tx := new(types.Transaction)
    raws := common.FromHex(raw)
    if err := rlp.DecodeBytes(raws, tx); err != nil {
	    return "",err
    }

    signer := types.NewEIP155Signer(big.NewInt(30400)) //
    _, err := types.Sender(signer, tx)
    if err != nil {
	return "",err
    }

    var threshold string
    var mode string
    var groupsigs string
    var groupid string

    req := TxDataReqAddr{}
    err = json.Unmarshal(tx.Data(), &req)
    if err == nil && req.TxType == "REQDCRMADDR" {
	threshold = req.ThresHold
	mode = req.Mode
	groupsigs = req.Sigs
	groupid = req.GroupId
    } else {
	rh := TxDataReShare{}
	err = json.Unmarshal(tx.Data(), &rh)
	if err == nil && rh.TxType == "RESHARE" {
	    threshold = rh.ThresHold
	    mode = rh.Mode
	    groupsigs = rh.Sigs
	    groupid = rh.GroupId
	}
    }

    if threshold == "" || mode == "" || groupid == "" {
	return "",fmt.Errorf("raw data error,it is not REQDCRMADDR tx or RESHARE tx")
    }

    if mode == "1" {
	return "",nil
    }

    if mode == "0" && groupsigs == "" {
	return "",fmt.Errorf("raw data error,must have sigs data when mode = 0")
    }

    nums := strings.Split(threshold, "/")
    nodecnt, _ := strconv.Atoi(nums[1])
    if nodecnt <= 1 {
	return "",fmt.Errorf("threshold error")
    }

    sigs := strings.Split(groupsigs,"|")
    //SigN = enode://xxxxxxxx@ip:portxxxxxxxxxxxxxxxxxxxxxx
    _, enodes := GetGroup(groupid)
    nodes := strings.Split(enodes, common.Sep2)
    if nodecnt != len(sigs) {
	return "",fmt.Errorf("group sigs error")
    }

    sstmp := strconv.Itoa(nodecnt)
    for j := 0; j < nodecnt; j++ {
	en := strings.Split(sigs[j], "@")
	for _, node := range nodes {
	    node2 := ParseNode(node)
	    enId := strings.Split(en[0],"//")
	    if len(enId) < 2 {
		return "",fmt.Errorf("group sigs error")
	    }

	    if strings.EqualFold(node2, enId[1]) {
		enodesigs := []rune(sigs[j])
		if len(enodesigs) <= len(node) {
		    return "",fmt.Errorf("group sigs error")
		}

		sig := enodesigs[len(node):]
		//sigbit, _ := hex.DecodeString(string(sig[:]))
		sigbit := common.FromHex(string(sig[:]))
		if sigbit == nil {
		    return "",fmt.Errorf("group sigs error")
		}

		pub,err := secp256k1.RecoverPubkey(crypto.Keccak256([]byte(node2)),sigbit)
		if err != nil {
		    return "",err
		}
		
		h := coins.NewCryptocoinHandler("FSN")
		if h != nil {
		    pubkey := hex.EncodeToString(pub)
		    from, err := h.PublicKeyToAddress(pubkey)
		    if err != nil {
			return "",err
		    }
		    
		    //5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
		    sstmp += common.Sep
		    sstmp += node2
		    sstmp += common.Sep
		    sstmp += from
		}
	    }
	}
    }

    tmps := strings.Split(sstmp,common.Sep)
    if len(tmps) == (2*nodecnt + 1) {
	return sstmp,nil
    }

    return "",fmt.Errorf("group sigs error")
}

func CheckGroupEnode(gid string) bool {
    if gid == "" {
	return false
    }

    groupenode := make(map[string]bool)
    _, enodes := GetGroup(gid)
    nodes := strings.Split(enodes, common.Sep2)
    for _, node := range nodes {
	node2 := ParseNode(node)
	_, ok := groupenode[strings.ToLower(node2)]
	if ok {
	    return false
	}

	groupenode[strings.ToLower(node2)] = true
    }

    return true
}

func HandleNoReciv(key string,reqer string,ower string,datatype string,wid int) {
    w := workers[wid]
    if w == nil {
	return
    }

    var l *list.List
    switch datatype {
	case "AcceptReqAddrRes":
	    l = w.msg_acceptreqaddrres
	case "AcceptLockOutRes":
	    l = w.msg_acceptlockoutres
	case "SendLockOutRes":
	    l = w.msg_sendlockoutres
	case "AcceptSignRes":
	    l = w.msg_acceptsignres 
	case "AcceptReShareRes":
	    l = w.msg_acceptreshareres 
	case "SendSignRes":
	    l = w.msg_sendsignres 
	case "SendReShareRes":
	    l = w.msg_sendreshareres 
	case "C1":
	    l = w.msg_c1
	case "D1":
	    l = w.msg_d1_1
	case "SHARE1":
	    l = w.msg_share1
	case "NTILDEH1H2":
	    l = w.msg_zkfact
	case "ZKUPROOF":
	    l = w.msg_zku
	case "MTAZK1PROOF":
	    l = w.msg_mtazk1proof 
	case "C11":
	    l = w.msg_c11
	case "KC":
	    l = w.msg_kc
	case "MKG":
	    l = w.msg_mkg
	case "MKW":
	    l = w.msg_mkw
	case "DELTA1":
	    l = w.msg_delta1
	case "D11":
	    l = w.msg_d11_1
	case "CommitBigVAB":
	    l = w.msg_commitbigvab
	case "ZKABPROOF":
	    l = w.msg_zkabproof
	case "CommitBigUT":
	    l = w.msg_commitbigut
	case "CommitBigUTD11":
	    l = w.msg_commitbigutd11
	case "S1":
	    l = w.msg_s1
	case "SS1":
	    l = w.msg_ss1
	case "PaillierKey":
	    l = w.msg_paillierkey
	case "EDC11":
	    l = w.msg_edc11
	case "EDZK":
	    l = w.msg_edzk
	case "EDD11":
	    l = w.msg_edd11
	case "EDSHARE1":
	    l = w.msg_edshare1
	case "EDCFSB":
	    l = w.msg_edcfsb
	case "EDC21":
	    l = w.msg_edc21
	case "EDZKR":
	    l = w.msg_edzkr
	case "EDD21":
	    l = w.msg_edd21 
	case "EDC31":
	    l = w.msg_edc31
	case "EDD31":
	    l = w.msg_edd31
	case "EDS":
	    l = w.msg_eds 
    }
    
    if l == nil {
	return
    }

    mm := make([]string,0)
    mm = append(mm,key + "-" + ower)
    mm = append(mm,datatype)
    //mm[0] = key + "-" + ower
    //mm[1] = datatype
    var next *list.Element
    for e := l.Front(); e != nil; e = next {
	    next = e.Next()

	    if e.Value == nil {
		    continue
	    }

	    s := e.Value.(string)

	    if s == "" {
		    continue
	    }

	    tmp := strings.Split(s, common.Sep)
	    tmp2 := tmp[0:2]
	    if testEq(mm, tmp2) {
		_, enodes := GetGroup(w.groupid)
		nodes := strings.Split(enodes, common.Sep2)
		for _, node := range nodes {
		    node2 := ParseNode(node)
		    if strings.EqualFold(node2,reqer) {
			SendMsgToPeer(node,s)
			break
		    }
		}

		break
	    }
    }
}

//msg: key-enode:C1:X1:X2...:Xn
//msg: key-enode1:NoReciv:enode2:C1
func DisMsg(msg string) {
	defer func() {
	    if r := recover(); r != nil {
		fmt.Errorf("DisMsg Runtime error: %v\n%v", r, string(debug.Stack()))
		return
	    }
	}()

	if msg == "" {
	    return
	}

	//orderbook matchres
	mm := strings.Split(msg, common.Sep)
	if len(mm) < 3 {
		return
	}

	mms := mm[0]
	prexs := strings.Split(mms, "-")
	if len(prexs) < 2 {
		return
	}

	//msg:  hash-enode:C1:X1:X2
	w, err := FindWorker(prexs[0])
	if err != nil || w == nil {
	    mmtmp := mm[0:2]
	    ss := strings.Join(mmtmp, common.Sep)
	    C1Data.WriteMap(strings.ToLower(ss),msg)

	    return
	}

	msgCode := mm[1]
	switch msgCode {
	case "SendLockOutRes":
		///bug
		if w.msg_sendlockoutres.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_sendlockoutres, msg) {
			return
		}

		w.msg_sendlockoutres.PushBack(msg)
		if w.msg_sendlockoutres.Len() == w.ThresHold {
			w.bsendlockoutres <- true
		}
	case "SendSignRes":
		///bug
		if w.msg_sendsignres.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_sendsignres, msg) {
			return
		}

		w.msg_sendsignres.PushBack(msg)
		if w.msg_sendsignres.Len() == w.ThresHold {
			w.bsendsignres <- true
		}
	case "SendReShareRes":
		///bug
		if w.msg_sendreshareres.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_sendreshareres, msg) {
			return
		}

		w.msg_sendreshareres.PushBack(msg)
		if w.msg_sendreshareres.Len() == w.NodeCnt {
			w.bsendreshareres <- true
		}
	case "NoReciv":
		key := prexs[0]
		enode1 := prexs[1]
		enode2 := mm[2]
		datatype := mm[3]
		HandleNoReciv(key,enode1,enode2,datatype,w.id)
	case "C1":
		///bug
		if w.msg_c1.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_c1, msg) {
			return
		}

		w.msg_c1.PushBack(msg)
		if w.msg_c1.Len() == w.NodeCnt {
			w.bc1 <- true
		}
	case "D1":
		///bug
		if w.msg_d1_1.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_d1_1, msg) {
			return
		}

		w.msg_d1_1.PushBack(msg)
		if w.msg_d1_1.Len() == w.NodeCnt {
			w.bd1_1 <- true
		}
	case "SHARE1":
		///bug
		if w.msg_share1.Len() >= (w.NodeCnt-1) {
			return
		}
		///
		if Find(w.msg_share1, msg) {
			return
		}

		w.msg_share1.PushBack(msg)
		if w.msg_share1.Len() == (w.NodeCnt-1) {
			w.bshare1 <- true
		}
	//case "ZKFACTPROOF":
	case "NTILDEH1H2":
		///bug
		if w.msg_zkfact.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_zkfact, msg) {
			return
		}

		w.msg_zkfact.PushBack(msg)
		if w.msg_zkfact.Len() == w.NodeCnt {
			w.bzkfact <- true
		}
	case "ZKUPROOF":
		///bug
		if w.msg_zku.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_zku, msg) {
			return
		}

		w.msg_zku.PushBack(msg)
		if w.msg_zku.Len() == w.NodeCnt {
			w.bzku <- true
		}
	case "MTAZK1PROOF":
		///bug
		if w.msg_mtazk1proof.Len() >= (w.ThresHold-1) {
			return
		}
		///
		if Find(w.msg_mtazk1proof, msg) {
			return
		}

		w.msg_mtazk1proof.PushBack(msg)
		if w.msg_mtazk1proof.Len() == (w.ThresHold-1) {
			w.bmtazk1proof <- true
		}
		//sign
	case "C11":
		///bug
		if w.msg_c11.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_c11, msg) {
			return
		}

		w.msg_c11.PushBack(msg)
		if w.msg_c11.Len() == w.ThresHold {
			w.bc11 <- true
		}
	case "KC":
		///bug
		if w.msg_kc.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_kc, msg) {
			return
		}

		w.msg_kc.PushBack(msg)
		if w.msg_kc.Len() == w.ThresHold {
			w.bkc <- true
		}
	case "MKG":
		///bug
		if w.msg_mkg.Len() >= (w.ThresHold-1) {
			return
		}
		///
		if Find(w.msg_mkg, msg) {
			return
		}

		w.msg_mkg.PushBack(msg)
		if w.msg_mkg.Len() == (w.ThresHold-1) {
			w.bmkg <- true
		}
	case "MKW":
		///bug
		if w.msg_mkw.Len() >= (w.ThresHold-1) {
			return
		}
		///
		if Find(w.msg_mkw, msg) {
			return
		}

		w.msg_mkw.PushBack(msg)
		if w.msg_mkw.Len() == (w.ThresHold-1) {
			w.bmkw <- true
		}
	case "DELTA1":
		///bug
		if w.msg_delta1.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_delta1, msg) {
			return
		}

		w.msg_delta1.PushBack(msg)
		if w.msg_delta1.Len() == w.ThresHold {
			w.bdelta1 <- true
		}
	case "D11":
		///bug
		if w.msg_d11_1.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_d11_1, msg) {
			return
		}

		w.msg_d11_1.PushBack(msg)
		if w.msg_d11_1.Len() == w.ThresHold {
			w.bd11_1 <- true
		}
	case "CommitBigVAB":
		///bug
		if w.msg_commitbigvab.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_commitbigvab, msg) {
			return
		}

		w.msg_commitbigvab.PushBack(msg)
		if w.msg_commitbigvab.Len() == w.ThresHold {
			w.bcommitbigvab <- true
		}
	case "ZKABPROOF":
		///bug
		if w.msg_zkabproof.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_zkabproof, msg) {
			return
		}

		w.msg_zkabproof.PushBack(msg)
		if w.msg_zkabproof.Len() == w.ThresHold {
			w.bzkabproof <- true
		}
	case "CommitBigUT":
		///bug
		if w.msg_commitbigut.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_commitbigut, msg) {
			return
		}

		w.msg_commitbigut.PushBack(msg)
		if w.msg_commitbigut.Len() == w.ThresHold {
			w.bcommitbigut <- true
		}
	case "CommitBigUTD11":
		///bug
		if w.msg_commitbigutd11.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_commitbigutd11, msg) {
			return
		}

		w.msg_commitbigutd11.PushBack(msg)
		if w.msg_commitbigutd11.Len() == w.ThresHold {
			w.bcommitbigutd11 <- true
		}
	case "S1":
		///bug
		if w.msg_s1.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_s1, msg) {
			return
		}

		w.msg_s1.PushBack(msg)
		if w.msg_s1.Len() == w.ThresHold {
			w.bs1 <- true
		}
	case "SS1":
		///bug
		if w.msg_ss1.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_ss1, msg) {
			return
		}

		w.msg_ss1.PushBack(msg)
		if w.msg_ss1.Len() == w.ThresHold {
			w.bss1 <- true
		}
	case "PaillierKey":
		///bug
		if w.msg_paillierkey.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_paillierkey, msg) {
			return
		}

		w.msg_paillierkey.PushBack(msg)
		if w.msg_paillierkey.Len() == w.NodeCnt {
			w.bpaillierkey <- true
		}


	//////////////////ed
	case "EDC11":
		///bug
		if w.msg_edc11.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_edc11, msg) {
			return
		}

		w.msg_edc11.PushBack(msg)
		if w.msg_edc11.Len() == w.NodeCnt {
			w.bedc11 <- true
		}
	case "EDZK":
		///bug
		if w.msg_edzk.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_edzk, msg) {
			return
		}

		w.msg_edzk.PushBack(msg)
		if w.msg_edzk.Len() == w.NodeCnt {
			w.bedzk <- true
		}
	case "EDD11":
		///bug
		if w.msg_edd11.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_edd11, msg) {
			return
		}

		w.msg_edd11.PushBack(msg)
		if w.msg_edd11.Len() == w.NodeCnt {
			w.bedd11 <- true
		}
	case "EDSHARE1":
		///bug
		if w.msg_edshare1.Len() >= (w.NodeCnt-1) {
			return
		}
		///
		if Find(w.msg_edshare1, msg) {
			return
		}

		w.msg_edshare1.PushBack(msg)
		if w.msg_edshare1.Len() == (w.NodeCnt-1) {
			w.bedshare1 <- true
		}
	case "EDCFSB":
		///bug
		if w.msg_edcfsb.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_edcfsb, msg) {
			return
		}

		w.msg_edcfsb.PushBack(msg)
		if w.msg_edcfsb.Len() == w.NodeCnt {
			w.bedcfsb <- true
		}
	case "EDC21":
		///bug
		if w.msg_edc21.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_edc21, msg) {
			return
		}

		w.msg_edc21.PushBack(msg)
		if w.msg_edc21.Len() == w.NodeCnt {
			w.bedc21 <- true
		}
	case "EDZKR":
		///bug
		if w.msg_edzkr.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_edzkr, msg) {
			return
		}

		w.msg_edzkr.PushBack(msg)
		if w.msg_edzkr.Len() == w.NodeCnt {
			w.bedzkr <- true
		}
	case "EDD21":
		///bug
		if w.msg_edd21.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_edd21, msg) {
			return
		}

		w.msg_edd21.PushBack(msg)
		if w.msg_edd21.Len() == w.NodeCnt {
			w.bedd21 <- true
		}
	case "EDC31":
		///bug
		if w.msg_edc31.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_edc31, msg) {
			return
		}

		w.msg_edc31.PushBack(msg)
		if w.msg_edc31.Len() == w.NodeCnt {
			w.bedc31 <- true
		}
	case "EDD31":
		///bug
		if w.msg_edd31.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_edd31, msg) {
			return
		}

		w.msg_edd31.PushBack(msg)
		if w.msg_edd31.Len() == w.NodeCnt {
			w.bedd31 <- true
		}
	case "EDS":
		///bug
		if w.msg_eds.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_eds, msg) {
			return
		}

		w.msg_eds.PushBack(msg)
		if w.msg_eds.Len() == w.NodeCnt {
			w.beds <- true
		}
		///////////////////
	default:
		fmt.Println("unkown msg code")
	}
}

//==========================================================================

func Find(l *list.List, msg string) bool {
	if l == nil || msg == "" {
		return false
	}

	var next *list.Element
	for e := l.Front(); e != nil; e = next {
		next = e.Next()

		if e.Value == nil {
			continue
		}

		s := e.Value.(string)

		if s == "" {
			continue
		}

		if strings.EqualFold(s, msg) {
			return true
		}
	}

	return false
}

func testEq(a, b []string) bool {
    // If one is nil, the other must also be nil.
    if (a == nil) != (b == nil) {
        return false;
    }

    if len(a) != len(b) {
        return false
    }

    for i := range a {
	if !strings.EqualFold(a[i],b[i]) {
            return false
        }
    }

    return true
}

