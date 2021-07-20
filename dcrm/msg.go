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
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	"github.com/fsn-dev/dcrm-walletService/crypto/secp256k1"
	"strings"
	"math/big"
	"encoding/hex"
	"fmt"
	"time"
	"container/list"
	"github.com/fsn-dev/cryptoCoins/coins"
	"crypto/ecdsa"
	"github.com/fsn-dev/dcrm-walletService/crypto"
	"github.com/fsn-dev/dcrm-walletService/crypto/ecies"
	"strconv"
	"github.com/fsn-dev/dcrm-walletService/p2p/discover"
	crand "crypto/rand"
	"github.com/fsn-dev/cryptoCoins/coins/types"
	"github.com/fsn-dev/cryptoCoins/tools/rlp"
	"encoding/json"
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
	common.Debug("=========SendMsgToDcrmGroup=============","msg",msg,"groupid",groupid)
	_,err := BroadcastInGroupOthers(groupid, msg)
	if err != nil {
	    common.Debug("=========SendMsgToDcrmGroup,send msg to dcrm group=============","msg",msg,"groupid",groupid,"err",err)
	}
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
//	common.Debug("=========SendMsgToPeer===========","msg",msg,"send to peer",enodes)
	en := strings.Split(string(enodes[8:]), "@")
	cm, err := EncryptMsg(msg, en[0])
	if err != nil {
		//fmt.Printf("%v =========SendMsgToPeer,encrypt msg fail,err = %v =================\n", common.CurrentTime(), err)
		return
	}

	err = SendToPeer(enodes, cm)
	if err != nil {
//	    common.Debug("=========SendMsgToPeer,send to peer fail===========","msg",msg,"send to peer",enodes,"err",err)
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
	keytmp,from,_,txdata,err := CheckRaw(raw)
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
	    common.Debug("=================GetRawReply,the list item is TxDataSign=================","key",keytmp,"from",from,"sig",sig)
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
	    common.Info("=================GetRawReply,the list item is TxDataAcceptSign================","key",keytmp,"from",from,"accept",acceptsig.Accept,"raw",raw)
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
	    common.Debug("===================== CheckReply,reqaddr================","ac.Sigs",ac.Sigs,"count",count,"k",k,"key",key,"ret",ret)
	    return false
	}

	for j:=0;j<count;j++ {
	    found := false
	    for _,v := range ret {
		    common.Debug("===================== CheckReply,reqaddr================","ac.Sigs",ac.Sigs,"count",count,"k",k,"key",key,"ret.v",v,"v.From",v.From,"mms[2j+2]",mms[2*j+2])
		if strings.EqualFold(v.From,mms[2*j+2]) { //allow user login diffrent node
		    found = true
		    break
		}
	    }

	    if !found {
		common.Debug("===================== CheckReply,reqaddr, return false.====================","ac.Sigs",ac.Sigs,"count",count,"k",k,"key",key)
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
			    common.Debug("===================== CheckReply,lockout===============","ac.Sigs",ac.Sigs,"kk",kk,"key",key,"vv.From",vv.From,"mms[kk+1]",mms[kk+1])
			if strings.EqualFold(vv.From,mms[kk+1]) { //allow user login diffrent node
			    found = true
			    break
			}
		    }

		    if !found {
			common.Debug("===================== CheckReply,lockout,return false==================","ac.Sigs",ac.Sigs,"kk",kk,"key",key)
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
    common.Debug("===================== CheckReply,get raw reply finish================","key",key)
	exsit,data := GetValueFromPubKeyData(key)
	if !exsit {
    common.Debug("===================== CheckReply,get raw reply finish and get value by key fail================","key",key)
	    return false
	}

	sig,ok := data.(*AcceptSignData)
	if !ok || sig == nil {
    common.Debug("===================== CheckReply,get raw reply finish and get accept sign data by key fail================","key",key)
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
			    common.Debug("===================== CheckReply, mms[kk+1] must in ret map===============","key",key,"ret[...]",vv.From,"mms[kk+1]",mms[kk+1],"ac.Sigs",ac.Sigs)
			if strings.EqualFold(vv.From,mms[kk+1]) { //allow user login diffrent node
			    found = true
			    break
			}
		    }

		    if !found {
			common.Debug("===================== CheckReply,mms[kk+1] no find in ret map and return fail==================","key",key,"mms[kk+1]",mms[kk+1])
			return false
		    }

		    break
		}
	    }

	    if !foundeid {
	    common.Debug("===================== CheckReply,get raw reply finish and find eid fail================","key",key)
		return false
	    }
	}

	return true
    }

    return false 
}

//=========================================

func Call(msg interface{}, enode string) {
	common.Debug("====================Call===================","get msg",msg,"sender node",enode)
	s := msg.(string)
	if s == "" {
	    return
	}

	////////
	raw,err := UnCompress(s)
	if err == nil {
		s = raw
	}
	////////
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

//==================================================================

type WorkReq interface {
    Run(workid int, ch chan interface{}) bool
}

//RecvMsg
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
	if workid < 0 || workid >= RPCMaxWorker { //TODO
		res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get worker id fail", Err: fmt.Errorf("no find worker.")}
		ch <- res2
		return false
	}

	res := self.msg
	if res == "" { //TODO
		res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get data fail in RecvMsg.Run", Err: fmt.Errorf("no find worker.")}
		ch <- res2
		return false
	}

	msgdata, errdec := DecryptMsg(res) //for SendMsgToPeer
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

	    //presign
	    if msgmap["Type"] == "PreSign" {
		ps := &PreSign{}
		if err = ps.UnmarshalJSON([]byte(msgmap["PreSign"]));err == nil {
		    w := workers[workid]
		    w.sid = ps.Nonce 
		    w.groupid = ps.Gid
		    w.DcrmFrom = ps.Pub
		    gcnt, _ := GetGroup(w.groupid)
		    w.NodeCnt = gcnt //TODO
		    w.ThresHold = gcnt

		    dcrmpks, _ := hex.DecodeString(ps.Pub)
		    exsit,da := GetPubKeyDataFromLocalDb(string(dcrmpks[:]))
		    if !exsit {
			time.Sleep(time.Duration(5000000000))
			exsit,da = GetPubKeyDataFromLocalDb(string(dcrmpks[:]))
		    }
		    ///////
		    if !exsit {
			common.Debug("============================PreSign at RecvMsg.Run,not exist presign data===========================","pubkey",ps.Pub)
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get presign data from db fail", Err: fmt.Errorf("get presign data from db fail")}
			ch <- res
			return false
		    }

		    pd,ok := da.(*PubKeyData)
		    if !ok {
			common.Debug("============================PreSign at RecvMsg.Run,presign data error==========================","pubkey",ps.Pub)
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get presign data from db fail", Err: fmt.Errorf("get presign data from db fail")}
			ch <- res
			return false
		    }

		    save := (da.(*PubKeyData)).Save
		    ///sku1
		    da2 := GetSkU1FromLocalDb(string(dcrmpks[:]))
		    if da2 == nil {
			    res := RpcDcrmRes{Ret: "", Tip: "presign get sku1 fail", Err: fmt.Errorf("presign get sku1 fail")}
			    ch <- res
			    return false
		    }
		    sku1 := new(big.Int).SetBytes(da2)
		    if sku1 == nil {
			    res := RpcDcrmRes{Ret: "", Tip: "presign get sku1 fail", Err: fmt.Errorf("presign get sku1 fail")}
			    ch <- res
			    return false
		    }
		    //

			///////
		    exsit,da3 := GetValueFromPubKeyData(pd.Key)
		    ac,ok := da3.(*AcceptReqAddrData)
		    if ok {
			HandleC1Data(ac,w.sid,workid)
		    }
			///////

		    var ch1 = make(chan interface{}, 1)
		    pre := PreSign_ec3(w.sid,save,sku1,"ECDSA",ch1,workid)
		    if pre == nil {
			    res := RpcDcrmRes{Ret: "", Tip: "presign fail", Err: fmt.Errorf("presign fail")}
			    ch <- res
			    return false
		    }

		    //if NeedPreSign(ps.Pub) {
			    pre.Key = w.sid
			    pre.Gid = w.groupid
			    pre.Used = false
			    pre.Index = ps.Index

			    err = PutPreSignData(ps.Pub,ps.Gid,ps.Index,pre)
			    if err != nil {
				res := RpcDcrmRes{Ret: "", Tip: "presign fail", Err: fmt.Errorf("presign fail")}
				ch <- res
				return false
			    }
		    //}

		    res := RpcDcrmRes{Ret: "success", Tip: "", Err: nil}
		    ch <- res
		    return true
		}
	    }

	    //signdata
	    if msgmap["Type"] == "SignData" {
		sd := &SignData{}
		if err = sd.UnmarshalJSON([]byte(msgmap["SignData"]));err == nil {

		    common.Debug("===============RecvMsg.Run,it is signdata===================","msgprex",sd.MsgPrex,"key",sd.Key)

		    ys := secp256k1.S256().Marshal(sd.Pkx, sd.Pky)
		    pubkeyhex := hex.EncodeToString(ys)

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
		    for i:=0;i < recalc_times;i++ {
			common.Debug("===============RecvMsg.Run,sign recalc===================","i",i,"msgprex",sd.MsgPrex,"key",sd.Key)
			if len(ch1) != 0 {
			    <-ch1
			}

			//w.Clear2()
			//Sign_ec2(sd.Key, sd.Save, sd.Sku1, sd.Txhash, sd.Keytype, sd.Pkx, sd.Pky, ch1, workid)
			Sign_ec3(sd.Key,sd.Txhash,sd.Keytype,sd.Pkx,sd.Pky,ch1,workid,sd.Pre)
			common.Info("===============RecvMsg.Run, ec3 sign finish ===================","WaitMsgTimeGG20",WaitMsgTimeGG20)
			ret, _, cherr := GetChannelValue(WaitMsgTimeGG20 + 10, ch1)
			if ret != "" && cherr == nil {

			    ww, err2 := FindWorker(sd.MsgPrex)
			    if err2 != nil || ww == nil {
				res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker", Err: fmt.Errorf("no find worker")}
				ch <- res2
				return false
			    }

			    common.Info("===============RecvMsg.Run, ec3 sign success ===================","i",i,"get ret",ret,"cherr",cherr,"msgprex",sd.MsgPrex,"key",sd.Key)

			    ww.rsv.PushBack(ret)
			    res2 := RpcDcrmRes{Ret: ret, Tip: "", Err: nil}
			    ch <- res2
			    return true 
			}
			
			common.Info("===============RecvMsg.Run,ec3 sign fail===================","ret",ret,"cherr",cherr,"msgprex",sd.MsgPrex,"key",sd.Key)
			//time.Sleep(time.Duration(3) * time.Second) //1000 == 1s
		    }	
		    
		    res2 := RpcDcrmRes{Ret: "", Tip: "sign fail", Err: fmt.Errorf("sign fail")}
		    ch <- res2
		    return false
		}/////
	    }
	}

	if msgmap["Type"] == "ComSignBrocastData" {
	    signbrocast,err := UnCompressSignBrocastData(msgmap["ComSignBrocastData"])
	    if err == nil {
		_,_,_,txdata,err := CheckRaw(signbrocast.Raw)
		if err == nil {
		    sig,ok := txdata.(*TxDataSign)
		    if ok {
			pickdata := make([]*PickHashData,0)
			for _,vv := range signbrocast.PickHash {
			    pre := GetPreSignData(sig.PubKey,sig.GroupId,vv.PickKey)
			    if pre == nil {
				res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get pre-sign data fail", Err: fmt.Errorf("get pre-sign data fail.")}
				ch <- res
				return false
			    }

			    pd := &PickHashData{Hash:vv.Hash,Pre:pre}
			    pickdata = append(pickdata,pd)
			    DeletePreSignData(sig.PubKey,sig.GroupId,vv.PickKey)
			}

			signpick := &SignPickData{Raw:signbrocast.Raw,PickData:pickdata}
			errtmp := InitAcceptData2(signpick,workid,self.sender,ch)
			if errtmp == nil {
			    return true
			}

			return false
		    }
		}
	    }
	}

	if msgmap["Type"] == "ComSignData" {
	    signpick,err := UnCompressSignData(msgmap["ComSignData"])
	    if err == nil {
		errtmp := InitAcceptData2(signpick,workid,self.sender,ch)
		if errtmp == nil {
		    return true
		}

		return false
	    }
	}

	////////////////////////////

	errtmp := InitAcceptData(res,workid,self.sender,ch)
	if errtmp == nil {
	    return true
	}
	common.Debug("================RecvMsg.Run, init accept data fail=================","res",res,"err",errtmp)

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
   
    /////////bug
	_, enodes := GetGroup(ac.GroupId)
	nodes := strings.Split(enodes, common.Sep2)
	for _, node := range nodes {
	    node2 := ParseNode(node)
		c1data := key + "-" + node2 + common.Sep + "SS1"
		//common.Debug("===============HandleC1Data====================","c1data",c1data)
		c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
		if exist {
		common.Info("===============HandleC1Data,exsit c1data in C1Data map for ss1====================","c1data",c1data)
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
    ////////////
    
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

func DisAcceptMsg(raw string,workid int) {
    if raw == "" || workid < 0 || workid >= len(workers) {
	return
    }

    w := workers[workid]
    if w == nil {
	return
    }

    common.Debug("=====================DisAcceptMsg call CheckRaw================","raw ",raw)
    key,from,_,txdata,err := CheckRaw(raw)
    common.Debug("=====================DisAcceptMsg=================","key",key,"err",err)
    if err != nil {
	return
    }
    
    _,ok := txdata.(*TxDataReqAddr)
    if ok {
	if Find(w.msg_acceptreqaddrres,raw) {
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
    
    sig2,ok := txdata.(*TxDataSign)
    if ok {
	    common.Debug("======================DisAcceptMsg, get the msg and it is sign tx===========================","key",key,"from",from,"raw",raw)
	if Find(w.msg_acceptsignres, raw) {
	    common.Info("======================DisAcceptMsg,the msg is sign tx,and already in list.===========================","key",key,"from",from)
	    return
	}

	    common.Debug("======================DisAcceptMsg,the msg is sign tx,and put it into list.===========================","key",key,"from",from,"sig",sig2)
	w.msg_acceptsignres.PushBack(raw)
	if w.msg_acceptsignres.Len() >= w.ThresHold {
	    if !CheckReply(w.msg_acceptsignres,Rpc_SIGN,key) {
		//common.Info("=====================DisAcceptMsg,check reply fail===================","key",key,"from",from)
		return
	    }

	    //common.Info("=====================DisAcceptMsg,check reply success and will set timeout channel===================","key",key,"from",from)
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
	    common.Debug("======================DisAcceptMsg, get the msg and it is accept sign tx===========================","key",acceptsig.Key,"from",from,"raw",raw)
	if Find(w.msg_acceptsignres, raw) {
	    common.Info("======================DisAcceptMsg,the msg is accept sign tx,and already in list.===========================","sig key",acceptsig.Key,"from",from)
	    return
	}

	    common.Debug("======================DisAcceptMsg,the msg is accept sign tx,and put it into list.===========================","sig key",acceptsig.Key,"from",from,"accept sig",acceptsig)
	w.msg_acceptsignres.PushBack(raw)
	if w.msg_acceptsignres.Len() >= w.ThresHold {
	    if !CheckReply(w.msg_acceptsignres,Rpc_SIGN,acceptsig.Key) {
		    //common.Info("======================DisAcceptMsg,the msg is accept sign tx,and check reply fail.===========================","sig key",acceptsig.Key,"from",from)
		return
	    }

	    common.Info("======================DisAcceptMsg,the msg is accept sign tx,and check reply success and will set timeout channel.===========================","sig key",acceptsig.Key,"from",from)
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
	res := RpcDcrmRes{Ret: "", Tip: "init accept data fail.", Err: fmt.Errorf("init accept data fail")}
	ch <- res
	return fmt.Errorf("init accept data fail")
    }

    key,from,nonce,txdata,err := CheckRaw(raw)
    common.Info("=====================InitAcceptData,get result from call CheckRaw ================","key",key,"from",from,"err",err,"raw",raw)
    if err != nil {
	common.Info("===============InitAcceptData,check raw error===================","err ",err)
	res := RpcDcrmRes{Ret: "", Tip: err.Error(), Err: err}
	ch <- res
	return err
    }
    
    req,ok := txdata.(*TxDataReqAddr)
    if ok {
	common.Info("===============InitAcceptData, check reqaddr raw success==================","raw ",raw,"key ",key,"from ",from,"nonce ",nonce,"txdata ",req)
	exsit,_ := GetValueFromPubKeyData(key)
	if !exsit {
	    cur_nonce, _, _ := GetReqAddrNonce(from)
	    cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
	    new_nonce_num, _ := new(big.Int).SetString(nonce, 10)
	    common.Debug("===============InitAcceptData============","reqaddr cur_nonce_num ",cur_nonce_num,"reqaddr new_nonce_num ",new_nonce_num,"key ",key)
	    if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
		_, err := SetReqAddrNonce(from,nonce)
		if err == nil {
		    ars := GetAllReplyFromGroup(workid,req.GroupId,Rpc_REQADDR,sender)
		    sigs,err := GetGroupSigsDataByRaw(raw) 
		    common.Info("=================InitAcceptData================","get group sigs ",sigs,"err ",err,"key ",key)
		    if err != nil {
			res := RpcDcrmRes{Ret: "", Tip: err.Error(), Err: err}
			ch <- res
			return err
		    }

		    ac := &AcceptReqAddrData{Initiator:sender,Account: from, Cointype: "ALL", GroupId: req.GroupId, Nonce: nonce, LimitNum: req.ThresHold, Mode: req.Mode, TimeStamp: req.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", PubKey: "", Tip: "", Error: "", AllReply: ars, WorkId: workid,Sigs:sigs}
		    err = SaveAcceptReqAddrData(ac)
		    common.Info("===================call SaveAcceptReqAddrData finish====================","account ",from,"err ",err,"key ",key)
		   if err == nil {
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

			/////////////
			if req.Mode == "0" { // self-group
				////
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
							common.Debug("(self *RecvMsg) Run(),", "account= ", account, "key = ", key)
							ars := GetAllReplyFromGroup(w.id,req.GroupId,Rpc_REQADDR,sender)
							common.Info("================== InitAcceptData,get all AcceptReqAddrRes====================","raw ",raw,"result ",ars,"key ",key)
							
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

							///////
							timeout <- true
							return
						case <-agreeWaitTimeOut.C:
							common.Info("================== InitAcceptData, agree wait timeout==================","raw ",raw,"key ",key)
							ars := GetAllReplyFromGroup(w.id,req.GroupId,Rpc_REQADDR,sender)
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

				common.Debug("================== InitAcceptData======================","raw ",raw,"the terminal accept req addr result ",reply,"key ",key)

				ars := GetAllReplyFromGroup(w.id,req.GroupId,Rpc_REQADDR,sender)
				if !reply {
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

			common.Info("================== InitAcceptData, start call dcrm_genPubKey====================","w.id ",w.id,"w.groupid ",w.groupid,"key ",key)
			dcrm_genPubKey(w.sid, from, "ALL", rch, req.Mode, nonce)
			chret, tip, cherr := GetChannelValue(waitall, rch)
			common.Info("================== InitAcceptData , finish dcrm_genPubKey ===================","get return value ",chret,"err ",cherr,"key ",key)
			if cherr != nil {
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

			////////ec3////
		       /*if strings.EqualFold(sender,cur_enode) {
				go func() {
					PutPreSigal(chret,true)

					for {
						if NeedPreSign(chret) && GetPreSigal(chret) {
							//one,_ := new(big.Int).SetString("1",0)
							//PreSignNonce = new(big.Int).Add(PreSignNonce,one)
							tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
							nonce := Keccak256Hash([]byte(strings.ToLower(chret + req.GroupId + tt))).Hex()
							index := 0
							ids := GetIds2("ECDSA", req.GroupId)
							for kk, id := range ids {
								enodes := GetEnodesByUid(id, "ECDSA", req.GroupId)
								if IsCurNode(enodes, cur_enode) {
									if kk >= 2 {
										index = kk - 2
									} else {
										index = kk
									}
									break
								}

							}
							tmp := ids[index:index+3]
							ps := &PreSign{Pub:chret,Gid:req.GroupId,Nonce:nonce,Index:index}

							val,err := Encode2(ps)
							if err != nil {
								common.Debug("=====================PreSign========================","err",err)
								time.Sleep(time.Duration(10000000))
							    continue 
							}
							
							for _, id := range tmp {
								enodes := GetEnodesByUid(id, "ECDSA", req.GroupId)
								common.Info("===============PreSign in genkey,get enodes===============","enodes",enodes,"index",index)
								if IsCurNode(enodes, cur_enode) {
									common.Debug("===============PreSign in genkey,get cur enodes===============","enodes",enodes)
									continue
								}
								SendMsgToPeer(enodes, val)
							}

							rch := make(chan interface{}, 1)
							SetUpMsgList3(val,cur_enode,rch)
							_, _,cherr := GetChannelValue(waitall+10,rch)
							if cherr != nil {
								common.Debug("=====================PreSign in genkey fail========================","cherr",cherr)
							}

							common.Info("===================generate pre-sign data===============","current total number of the data ",GetTotalCount(chret),"the number of remaining pre-sign data",(PrePubDataCount-GetTotalCount(chret)),"pubkey",chret)
						} 

						time.Sleep(time.Duration(1000000))
					}
				}()
		       }*/
			////////////

			res := RpcDcrmRes{Ret: strconv.Itoa(workid) + common.Sep + "rpc_req_dcrmaddr" + common.Sep + chret, Tip: "", Err: nil}
			ch <- res
			return nil
			/////////////
		   }
		}
	    }
	}
    }

    lo,ok := txdata.(*TxDataLockOut)
    if ok {
	common.Debug("===============InitAcceptData, check lockout raw success=================","raw ",raw,"key ",key,"from ",from,"nonce ",nonce,"txdata ",lo)
	exsit,_ := GetValueFromPubKeyData(key)
	if !exsit {
	    cur_nonce, _, _ := GetLockOutNonce(from)
	    cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
	    new_nonce_num, _ := new(big.Int).SetString(nonce, 10)
	    common.Debug("===============InitAcceptData================","lockout cur_nonce_num ",cur_nonce_num,"lockout new_nonce_num ",new_nonce_num,"key ",key)
	    if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
		_, err := SetLockOutNonce(from,nonce)
		if err == nil {
		    
		    pubkey := ""
		    lokey := Keccak256Hash([]byte(strings.ToLower(lo.DcrmAddr))).Hex()
		    exsit,loda := GetValueFromPubKeyData(lokey)
		    if exsit {
			_,ok := loda.(*PubKeyData)
			if ok {
			    dcrmpub := (loda.(*PubKeyData)).Pub
			    pubkey = hex.EncodeToString([]byte(dcrmpub))
			}
		    }
		    if pubkey == "" {
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get pubkey fail", Err: fmt.Errorf("get pubkey fail")}
			ch <- res
			return fmt.Errorf("get pubkey fail") 
		    }
		    
		    ars := GetAllReplyFromGroup(workid,lo.GroupId,Rpc_LOCKOUT,sender)
		    ac := &AcceptLockOutData{Initiator:sender,Account:from, GroupId:lo.GroupId, Nonce: nonce, PubKey: pubkey, DcrmTo: lo.DcrmTo, Value: lo.Value, Cointype: lo.Cointype, LimitNum: lo.ThresHold, Mode: lo.Mode, TimeStamp: lo.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", OutTxHash: "", Tip: "", Error: "", AllReply: ars, WorkId: workid}
		    err := SaveAcceptLockOutData(ac)
		    if err == nil {
			w := workers[workid]
			w.sid = key
			w.groupid = lo.GroupId 
			w.limitnum = lo.ThresHold
			gcnt, _ := GetGroup(w.groupid)
			w.NodeCnt = gcnt
			common.Debug("===================InitAcceptData====================","w.NodeCnt ",w.NodeCnt,"w.groupid ",w.groupid,"wid ",workid,"key ",key)
			w.ThresHold = w.NodeCnt

			nums := strings.Split(w.limitnum, "/")
			if len(nums) == 2 {
			    nodecnt, err := strconv.Atoi(nums[1])
			    if err == nil {
				w.NodeCnt = nodecnt
			    }

			    w.ThresHold = gcnt
			}

			w.DcrmFrom = lo.DcrmAddr

			////////////////////
			if lo.Mode == "0" {
				////
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
						case account := <-wtmp2.acceptLockOutChan:
							common.Debug("InitAcceptData", "account= ", account, "key = ", key)
							ars := GetAllReplyFromGroup(w.id,lo.GroupId,Rpc_LOCKOUT,sender)
							common.Debug("================== InitAcceptData, get all AcceptLockOutRes=================","raw ",raw,"result ",ars,"key ",key)
							
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
								tip = "don't accept lockout"
								_,err = AcceptLockOut(sender,from, lo.GroupId, nonce, lo.DcrmAddr, lo.ThresHold, "false", "false", "Failure", "", "don't accept lockout", "don't accept lockout", ars, wid)
							} else {
								tip = ""
								_,err = AcceptLockOut(sender,from, lo.GroupId,nonce, lo.DcrmAddr, lo.ThresHold, "false", "true", "Pending", "", "", "", ars, wid)
							}

							if err != nil {
							    tip = "accept lock data error"
							}

							///////
							timeout <- true
							return
						case <-agreeWaitTimeOut.C:
							common.Debug("================== InitAcceptData , agree wait timeout==============","raw ",raw,"key ",key)
							ars := GetAllReplyFromGroup(w.id,lo.GroupId,Rpc_LOCKOUT,sender)
							_,err = AcceptLockOut(sender,from, lo.GroupId,nonce, lo.DcrmAddr, lo.ThresHold, "false", "false", "Timeout", "", "get other node accept lockout result timeout", "get other node accept lockout result timeout", ars, wid)
							reply = false
							tip = "get other node accept lockout result timeout"
							if err != nil {
							    tip = "get other node accept lockout result timeout and accept lockout data fail"
							}
							//

							timeout <- true
							return
						}
					}
				}(workid)

				if len(workers[workid].acceptWaitLockOutChan) == 0 {
					workers[workid].acceptWaitLockOutChan <- "go on"
				}

				DisAcceptMsg(raw,workid)
				reqaddrkey := GetReqAddrKeyByOtherKey(key,Rpc_LOCKOUT)
				exsit,da := GetValueFromPubKeyData(reqaddrkey)
				if !exsit {
				    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
				    ch <- res
				    return fmt.Errorf("get reqaddr sigs data fail") 
				}
				acceptreqdata,ok := da.(*AcceptReqAddrData)
				if !ok || acceptreqdata == nil {
				    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
				    ch <- res
				    return fmt.Errorf("get reqaddr sigs data fail") 
				}

				HandleC1Data(acceptreqdata,key,workid)

				<-timeout

				common.Debug("================== InitAcceptData==================","raw ",raw,"the terminal accept lockout result ",reply,"key ",key)

				if !reply {
					if tip == "get other node accept lockout result timeout" {
						ars := GetAllReplyFromGroup(w.id,lo.GroupId,Rpc_LOCKOUT,sender)
						_,err = AcceptLockOut(sender,from, lo.GroupId, nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Timeout", "", "get other node accept lockout result timeout", "get other node accept lockout result timeout", ars, workid)
					} else {
						/////////////TODO
						//sid-enode:SendLockOutRes:Success:lockout_tx_hash
						//sid-enode:SendLockOutRes:Fail:err
						mp := []string{w.sid, cur_enode}
						enode := strings.Join(mp, "-")
						s0 := "SendLockOutRes"
						s1 := "Fail"
						s2 := "don't accept lockout."
						ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
						SendMsgToDcrmGroup(ss, w.groupid)
						DisMsg(ss)
						_, _, err := GetChannelValue(ch_t, w.bsendlockoutres)
						ars := GetAllReplyFromGroup(w.id,lo.GroupId,Rpc_LOCKOUT,sender)
						if err != nil {
							tip = "get other node terminal accept lockout result timeout" ////bug
							_,err = AcceptLockOut(sender,from, lo.GroupId,nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Timeout", "", tip, tip, ars, workid)
							if err != nil {
							    tip = tip + "accept lockout data fail"
							}

						} else if w.msg_sendlockoutres.Len() != w.ThresHold {
							_,err = AcceptLockOut(sender,from, lo.GroupId, nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Failure", "", "get other node lockout result fail", "get other node lockout result fail", ars, workid)
							if err != nil {
							    tip = tip + "accept lockout data fail"
							}

						} else {
							reply2 := "false"
							lohash := ""
							iter := w.msg_sendlockoutres.Front()
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
								_,err = AcceptLockOut(sender,from, lo.GroupId, nonce, lo.DcrmAddr, lo.ThresHold, "true", "true", "Success", lohash, " ", " ", ars, workid)
								if err != nil {
								    tip = tip + "accept lockout data fail"
								}

							} else {
								_,err = AcceptLockOut(sender,from, lo.GroupId,nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Failure", "", lohash, lohash, ars, workid)
								if err != nil {
								    tip = tip + "accept lockout data fail"
								}

							}
						}
					}

					res := RpcDcrmRes{Ret: strconv.Itoa(workid) + common.Sep + "rpc_lockout", Tip: tip, Err: fmt.Errorf("don't accept lockout.")}
					ch <- res
					return fmt.Errorf("don't accept lockout.") 
				}
			} else {
				if len(workers[workid].acceptWaitLockOutChan) == 0 {
					workers[workid].acceptWaitLockOutChan <- "go on"
				}

				ars := GetAllReplyFromGroup(w.id,lo.GroupId,Rpc_LOCKOUT,sender)
				_,err = AcceptLockOut(sender,from, lo.GroupId, nonce, lo.DcrmAddr, lo.ThresHold, "false", "true", "Pending", "", "", "", ars, workid)
				if err != nil {
				    res := RpcDcrmRes{Ret:"", Tip:err.Error(), Err: err}
				    ch <- res
				    return err
				}
			}

			rch := make(chan interface{}, 1)
			common.Debug("================== InitAcceptData , start call validate_lockout================","key ",key)
			validate_lockout(w.sid,from,lo.DcrmAddr,lo.Cointype, lo.Value, lo.DcrmTo,nonce, lo.Memo,rch)
			chret, tip, cherr := GetChannelValue(waitall, rch)
			common.Debug("================== InitAcceptData, finish and get validate_lockout=================","return value ",chret,"err ",cherr,"key ",key)
			if chret != "" {
				res := RpcDcrmRes{Ret: strconv.Itoa(workid) + common.Sep + "rpc_lockout" + common.Sep + chret, Tip: "", Err: nil}
				ch <- res
				return nil
			}

			ars := GetAllReplyFromGroup(w.id,lo.GroupId,Rpc_LOCKOUT,sender)
			if tip == "get other node accept lockout result timeout" {
				_,err = AcceptLockOut(sender,from, lo.GroupId,nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Timeout", "", tip, cherr.Error(), ars, workid)
			} else {
				/////////////TODO
				//sid-enode:SendLockOutRes:Success:lockout_tx_hash
				//sid-enode:SendLockOutRes:Fail:err
				mp := []string{w.sid, cur_enode}
				enode := strings.Join(mp, "-")
				s0 := "SendLockOutRes"
				s1 := "Fail"
				s2 := cherr.Error()
				ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
				SendMsgToDcrmGroup(ss, w.groupid)
				DisMsg(ss)
				_, _, err := GetChannelValue(ch_t, w.bsendlockoutres)
				if err != nil {
					tip = "get other node terminal accept lockout result timeout" ////bug
					_,err = AcceptLockOut(sender,from, lo.GroupId, nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Timeout", "", tip, tip, ars, workid)
					if err != nil {
					    tip = tip + " and accept lockout data fail"
					}
			
				} else if w.msg_sendlockoutres.Len() != w.ThresHold {
					_,err = AcceptLockOut(sender,from, lo.GroupId,nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Failure", "", "get other node lockout result fail", "get other node lockout result fail", ars,workid)
					if err != nil {
					    tip = tip + " and accept lockout data fail"
					}
			
				} else {
					reply2 := "false"
					lohash := ""
					iter := w.msg_sendlockoutres.Front()
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
						_,err = AcceptLockOut(sender,from, lo.GroupId,nonce, lo.DcrmAddr, lo.ThresHold, "true", "true", "Success", lohash, " ", " ", ars, workid)
						if err != nil {
						    tip = tip + " and accept lockout data fail"
						}
			
					} else {
						_,err = AcceptLockOut(sender,from, lo.GroupId,nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Failure", "", lohash, lohash, ars, workid)
						if err != nil {
						    tip = tip + " and accept lockout data fail"
						}
			
					}
				}
			}

			if cherr != nil {
				res := RpcDcrmRes{Ret: strconv.Itoa(workid) + common.Sep + "rpc_lockout", Tip: tip, Err: cherr}
				ch <- res
				return cherr
			}

			res := RpcDcrmRes{Ret: strconv.Itoa(workid) + common.Sep + "rpc_lockout", Tip: tip, Err: fmt.Errorf("send tx to net fail.")}
			ch <- res
			return fmt.Errorf("send tx to net fail.")
			////////////////////
		    }
		}
	    }
	}
    }

    /*sig,ok := txdata.(*TxDataSign)
    if ok {
	common.Debug("===============InitAcceptData, it is sign txdata and check sign raw success==================","key ",key,"from ",from,"nonce ",nonce)
	exsit,_ := GetValueFromPubKeyData(key)
	if !exsit {
	    cur_nonce, _, _ := GetSignNonce(from)
	    cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
	    new_nonce_num, _ := new(big.Int).SetString(nonce, 10)
	    common.Debug("===============InitAcceptData===============","sign cur_nonce_num ",cur_nonce_num,"sign new_nonce_num ",new_nonce_num,"key ",key)
	    //if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
		//_, err := SetSignNonce(from,nonce)
		_, err := SetSignNonce(from,cur_nonce) //bug
		if err == nil {
		    ars := GetAllReplyFromGroup(workid,sig.GroupId,Rpc_SIGN,sender)
		    ac := &AcceptSignData{Initiator:sender,Account: from, GroupId: sig.GroupId, Nonce: nonce, PubKey: sig.PubKey, MsgHash: sig.MsgHash, MsgContext: sig.MsgContext, Keytype: sig.Keytype, LimitNum: sig.ThresHold, Mode: sig.Mode, TimeStamp: sig.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", Rsv: "", Tip: "", Error: "", AllReply: ars, WorkId:workid}
		    err = SaveAcceptSignData(ac)
		    if err == nil {
			common.Debug("===============InitAcceptData,save sign accept data finish===================","ars ",ars,"key ",key)
			w := workers[workid]
			w.sid = key 
			w.groupid = sig.GroupId 
			w.limitnum = sig.ThresHold
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

			w.DcrmFrom = sig.PubKey  // pubkey replace dcrmfrom in sign
			
			if sig.Mode == "0" { // self-group
				////
				var reply bool
				var tip string
				timeout := make(chan bool, 1)
				go func(wid int) {
					cur_enode = discover.GetLocalID().String() //GetSelfEnode()
					agreeWaitTime := 2 * time.Minute
					agreeWaitTimeOut := time.NewTicker(agreeWaitTime)

					wtmp2 := workers[wid]

					for {
						select {
						case account := <-wtmp2.acceptSignChan:
							common.Debug("InitAcceptData,", "account= ", account, "key = ", key)
							ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
							common.Debug("================== InitAcceptData , get all AcceptSignRes===============","result ",ars,"key ",key)
							
							//TODO//
							reply = true
							recount := 0
							for _,nr := range ars {
							    if strings.EqualFold(nr.Status,"Agree") {
								    recount++
							    }
							}
							if recount < w.ThresHold {
								reply = false
							}
							////////
							//

							if !reply {
								tip = "don't accept sign"
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "false", "Failure", "", "don't accept sign", "don't accept sign", ars,wid)
							} else {
							    	common.Debug("=======================InitAcceptData,11111111111111,set sign pending=============================","key",key)
								tip = ""
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"false", "true", "Pending", "", "", "", ars,wid)
							}

							if err != nil {
							    tip = tip + " and accept sign data fail"
							}

							///////
							timeout <- true
							return
						case <-agreeWaitTimeOut.C:
							common.Debug("================== InitAcceptData , agree wait timeout=============","key ",key)
							ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
							_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "false", "Timeout", "", "get other node accept sign result timeout", "get other node accept sign result timeout", ars,wid)
							reply = false
							tip = "get other node accept sign result timeout"
							if err != nil {
							    tip = tip + " and accept sign data fail"
							}
							//

							timeout <- true
							return
						}
					}
				}(workid)

				if len(workers[workid].acceptWaitSignChan) == 0 {
					workers[workid].acceptWaitSignChan <- "go on"
				}

				DisAcceptMsg(raw,workid)
				common.Debug("===============InitAcceptData, call DisAcceptMsg finish===================","key ",key)
				reqaddrkey := GetReqAddrKeyByOtherKey(key,Rpc_SIGN)
				if reqaddrkey == "" {
				    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get req addr key fail", Err: fmt.Errorf("get reqaddr key fail")}
				    ch <- res
				    return fmt.Errorf("get reqaddr key fail") 
				}

				exsit,da := GetValueFromPubKeyData(reqaddrkey)
				if !exsit {
					common.Debug("===============InitAcceptData, get req addr key by other key fail ===================","key ",key)
				    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
				    ch <- res
				    return fmt.Errorf("get reqaddr sigs data fail") 
				}

				acceptreqdata,ok := da.(*AcceptReqAddrData)
				if !ok || acceptreqdata == nil {
					common.Debug("===============InitAcceptData, get req addr key by other key error ===================","key ",key)
				    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
				    ch <- res
				    return fmt.Errorf("get reqaddr sigs data fail") 
				}

				common.Debug("===============InitAcceptData, start call HandleC1Data===================","reqaddrkey ",reqaddrkey,"key ",key)

				HandleC1Data(acceptreqdata,key,workid)

				<-timeout

				if !reply {
					if tip == "get other node accept sign result timeout" {
						ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
						_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", "get other node accept sign result timeout", "get other node accept sign result timeout", ars,workid)
					} else {
						//sid-enode:SendSignRes:Success:rsv
						//sid-enode:SendSignRes:Fail:err
						mp := []string{w.sid, cur_enode}
						enode := strings.Join(mp, "-")
						s0 := "SendSignRes"
						s1 := "Fail"
						s2 := "don't accept sign."
						ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
						SendMsgToDcrmGroup(ss, w.groupid)
						DisMsg(ss)
						_, _, err := GetChannelValue(waitall, w.bsendsignres)
						ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
						if err != nil {
							tip = "get other node terminal accept sign result timeout" ////bug
							_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", tip, tip, ars,workid)
							if err != nil {
							    tip = tip + " and accept sign data fail"
							}

						} else if w.msg_sendsignres.Len() != w.ThresHold {
							_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", "get other node sign result fail", "get other node sign result fail", ars,workid)
							if err != nil {
							    tip = tip + " and accept sign data fail"
							}

						} else {
							reply2 := "false"
							lohash := ""
							iter := w.msg_sendsignres.Front()
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
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "true", "Success", lohash, " ", " ", ars,workid)
								if err != nil {
								    tip = tip + " and accept sign data fail"
								}

							} else {
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", lohash,lohash, ars,workid)
								if err != nil {
								    tip = tip + " and accept sign data fail"
								}

							}
						}
					}

					res := RpcDcrmRes{Ret:"", Tip: tip, Err: fmt.Errorf("don't accept sign.")}
					ch <- res
					return fmt.Errorf("don't accept sign.")
				}
			} else {
				if len(workers[workid].acceptWaitSignChan) == 0 {
					workers[workid].acceptWaitSignChan <- "go on"
				}

				ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
				common.Debug("=======================InitAcceptData,2222222222222222222,set sign pending=============================","key",key)
				_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"false", "true", "Pending", "", "","", ars,workid)
				if err != nil {
				    res := RpcDcrmRes{Ret:"", Tip: err.Error(), Err:err}
				    ch <- res
				    return err
				}
			}

			common.Debug("===============InitAcceptData,begin to sign=================","sig.MsgHash ",sig.MsgHash,"sig.Mode ",sig.Mode,"key ",key)
			rch := make(chan interface{}, 1)
			sign(w.sid, from,sig.PubKey,sig.MsgHash,sig.Keytype,nonce,sig.Mode,rch)
			chret, tip, cherr := GetChannelValue(waitall, rch)
			common.Debug("================== InitAcceptData,finish sig.================","return sign result ",chret,"err ",cherr,"key ",key)
			if chret != "" {
				res := RpcDcrmRes{Ret: chret, Tip: "", Err: nil}
				ch <- res
				return nil
			}

			ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
			if tip == "get other node accept sign result timeout" {
				_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", tip,cherr.Error(),ars,workid)
			} else {
				//sid-enode:SendSignRes:Success:rsv
				//sid-enode:SendSignRes:Fail:err
				mp := []string{w.sid, cur_enode}
				enode := strings.Join(mp, "-")
				s0 := "SendSignRes"
				s1 := "Fail"
				s2 := cherr.Error()
				ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
				SendMsgToDcrmGroup(ss, w.groupid)
				DisMsg(ss)
				_, _, err := GetChannelValue(waitall, w.bsendsignres)
				if err != nil {
					tip = "get other node terminal accept sign result timeout" ////bug
					_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", tip, tip, ars, workid)
					if err != nil {
					    tip = tip + " and accept sign data fail"
					}

				} else if w.msg_sendsignres.Len() != w.ThresHold {
					_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", "get other node sign result fail", "get other node sign result fail", ars, workid)
					if err != nil {
					    tip = tip + " and accept sign data fail"
					}

				} else {
					reply2 := "false"
					lohash := ""
					iter := w.msg_sendsignres.Front()
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
						_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "true", "Success", lohash, " ", " ", ars, workid)
						if err != nil {
						    tip = tip + " and accept sign data fail"
						}

					} else {
						_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", lohash, lohash, ars, workid)
						if err != nil {
						    tip = tip + " and accept sign data fail"
						}
					}
				}
			}

			if cherr != nil {
				res := RpcDcrmRes{Ret: "", Tip: tip, Err: cherr}
				ch <- res
				return cherr
			}

			res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("sign fail.")}
			ch <- res
			return fmt.Errorf("sign fail.")
		    } else {
			common.Debug("===============InitAcceptData, it is sign txdata,but save accept data fail==================","key ",key,"from ",from)
		    }
		} else {
			common.Debug("===============InitAcceptData, it is sign txdata,but set nonce fail==================","key ",key,"from ",from)
		}
	    //}
	} else {
		common.Debug("===============InitAcceptData, it is sign txdata,but has handled before==================","key ",key,"from ",from)
	}
    }*/

    rh,ok := txdata.(*TxDataReShare)
    if ok {
	ars := GetAllReplyFromGroup(workid,rh.GroupId,Rpc_RESHARE,sender)
	sigs,err := GetGroupSigsDataByRaw(raw) 
	common.Debug("=================InitAcceptData,reshare=================","get group sigs ",sigs,"err ",err,"key ",key)
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: err.Error(), Err: err}
	    ch <- res
	    return err
	}

	ac := &AcceptReShareData{Initiator:sender,Account: from, GroupId: rh.GroupId, TSGroupId:rh.TSGroupId, PubKey: rh.PubKey, LimitNum: rh.ThresHold, PubAccount:rh.Account, Mode:rh.Mode, Sigs:sigs, TimeStamp: rh.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", NewSk: "", Tip: "", Error: "", AllReply: ars, WorkId:workid}
	err = SaveAcceptReShareData(ac)
	common.Info("===================finish call SaveAcceptReShareData======================","err ",err,"workid ",workid,"account ",from,"group id ",rh.GroupId,"pubkey ",rh.PubKey,"threshold ",rh.ThresHold,"key ",key)
	if err == nil {
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
				    common.Debug("(self *RecvMsg) Run(),", "account= ", account, "key = ", key)
				    ars := GetAllReplyFromGroup(w.id,rh.GroupId,Rpc_RESHARE,sender)
				    common.Info("================== InitAcceptData, get all AcceptReShareRes================","raw ",raw,"result ",ars,"key ",key)
				    
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
				    common.Info("================== InitAcceptData, agree wait timeout===================","raw ",raw,"key ",key)
				    ars := GetAllReplyFromGroup(w.id,rh.GroupId,Rpc_RESHARE,sender)
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
	//common.Info("===============InitAcceptData, check accept reqaddr raw success======================","raw ",raw,"key ",acceptreq.Key,"from ",from,"txdata ",acceptreq)
	w, err := FindWorker(acceptreq.Key)
	if err != nil || w == nil {
	    c1data := acceptreq.Key + "-" + from
	    C1Data.WriteMap(strings.ToLower(c1data),raw)
	    res := RpcDcrmRes{Ret:"Failure", Tip: "get reqaddr accept data fail from db.", Err: fmt.Errorf("get reqaddr accept data fail from db when no find worker")}
	    ch <- res
	    return fmt.Errorf("get reqaddr accept data fail from db when no find worker.")
	}

	exsit,da := GetValueFromPubKeyData(acceptreq.Key)
	if !exsit {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "dcrm back-end internal error:get reqaddr accept data fail from db", Err: fmt.Errorf("get reqaddr accept data fail from db in init accept data")}
	    ch <- res
	    return fmt.Errorf("get reqaddr accept data fail from db in init accept data.")
	}

	ac,ok := da.(*AcceptReqAddrData)
	if !ok || ac == nil {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "dcrm back-end internal error:decode accept data fail", Err: fmt.Errorf("decode accept data fail")}
	    ch <- res
	    return fmt.Errorf("decode accept data fail")
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

    acceptlo,ok := txdata.(*TxDataAcceptLockOut)
    if ok {
	common.Debug("===============InitAcceptData, check accept lockout raw success=================","raw ",raw,"key ",acceptlo.Key,"from ",from,"txdata ",acceptlo)
	w, err := FindWorker(acceptlo.Key)
	if err != nil || w == nil {
	    c1data := acceptlo.Key + "-" + from
	    C1Data.WriteMap(strings.ToLower(c1data),raw)
	    res := RpcDcrmRes{Ret:"Failure", Tip: "get lockout accept data fail from db when no find worker.", Err: fmt.Errorf("get lockout accept data fail from db when no find worker")}
	    ch <- res
	    return fmt.Errorf("get lockout accept data fail from db when no find worker.")
	}

	exsit,da := GetValueFromPubKeyData(acceptlo.Key)
	if !exsit {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "dcrm back-end internal error:get lockout accept data fail from db in init accept data", Err: fmt.Errorf("get lockout accept data fail from db in init accept data")}
	    ch <- res
	    return fmt.Errorf("get lockout accept data fail from db in init accept data.")
	}

	ac,ok := da.(*AcceptLockOutData)
	if !ok || ac == nil {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "dcrm back-end internal error:decode accept data fail", Err: fmt.Errorf("decode accept data fail")}
	    ch <- res
	    return fmt.Errorf("decode accept data fail")
	}

	dcrmaddr,_,err := GetAddr(ac.PubKey,ac.Cointype)
	if err != nil {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "dcrm back-end internal error:get dcrm addr fail", Err: fmt.Errorf("get dcrm addr fail")}
	    ch <- res
	    return fmt.Errorf("get dcrm addr fail")
	}

	status := "Pending"
	accept := "false"
	if acceptlo.Accept == "AGREE" {
		accept = "true"
	} else {
		status = "Failure"
	}

	id,_ := GetWorkerId(w)
	DisAcceptMsg(raw,id)
	reqaddrkey := GetReqAddrKeyByOtherKey(acceptlo.Key,Rpc_LOCKOUT)
	exsit,da = GetValueFromPubKeyData(reqaddrkey)
	if !exsit {
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
	    ch <- res
	    return fmt.Errorf("get reqaddr sigs data fail") 
	}
	acceptreqdata,ok := da.(*AcceptReqAddrData)
	if !ok || acceptreqdata == nil {
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
	    ch <- res
	    return fmt.Errorf("get reqaddr sigs data fail") 
	}

	HandleC1Data(acceptreqdata,acceptlo.Key,id)

	ars := GetAllReplyFromGroup(id,ac.GroupId,Rpc_LOCKOUT,ac.Initiator)
	tip, err := AcceptLockOut(ac.Initiator,ac.Account, ac.GroupId, ac.Nonce, dcrmaddr, ac.LimitNum, "false", accept, status, "", "", "", ars, ac.WorkId)
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
	common.Info("===============InitAcceptData, it is acceptsign and check accept sign raw success=====================","key ",acceptsig.Key,"from ",from,"accept",acceptsig.Accept,"raw",raw)
	w, err := FindWorker(acceptsig.Key)
	if err != nil || w == nil {
		common.Info("===============InitAcceptData, it is acceptsign and no find worker=====================","key ",acceptsig.Key,"from ",from)
	    c1data := acceptsig.Key + "-" + from
	    C1Data.WriteMap(strings.ToLower(c1data),raw)
	    res := RpcDcrmRes{Ret:"Failure", Tip: "get sign accept data fail from db when no find worker.", Err: fmt.Errorf("get sign accept data fail from db when no find worker")}
	    ch <- res
	    return fmt.Errorf("get sign accept data fail from db when no find worker.")
	}

	exsit,da := GetValueFromPubKeyData(acceptsig.Key)
	if !exsit {
		common.Info("===============InitAcceptData, it is acceptsign and get sign accept data fail from db=====================","key ",acceptsig.Key,"from ",from)
	    res := RpcDcrmRes{Ret:"Failure", Tip: "dcrm back-end internal error:get sign accept data fail from db in init accept data", Err: fmt.Errorf("get sign accept data fail from db in init accept data")}
	    ch <- res
	    return fmt.Errorf("get sign accept data fail from db in init accept data.")
	}

	ac,ok := da.(*AcceptSignData)
	if !ok || ac == nil {
		common.Info("===============InitAcceptData, it is acceptsign and decode accept data fail=====================","key ",acceptsig.Key,"from ",from)
	    res := RpcDcrmRes{Ret:"Failure", Tip: "dcrm back-end internal error:decode accept data fail", Err: fmt.Errorf("decode accept data fail")}
	    ch <- res
	    return fmt.Errorf("decode accept data fail")
	}

	if ac.Deal == "true" || ac.Status == "Success" || ac.Status == "Failure" || ac.Status == "Timeout" {
		common.Info("===============InitAcceptData, it is acceptsign and sign has handled before=====================","key ",acceptsig.Key,"from ",from)
	    res := RpcDcrmRes{Ret:"", Tip: "sign has handled before", Err: fmt.Errorf("sign has handled before")}
	    ch <- res
	    return fmt.Errorf("sign has handled before")
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
		common.Debug("===============InitAcceptData, it is acceptsign and get reqaddr sigs data fail=====================","key ",acceptsig.Key,"from ",from)
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
	    ch <- res
	    return fmt.Errorf("get reqaddr sigs data fail") 
	}
	acceptreqdata,ok := da.(*AcceptReqAddrData)
	if !ok || acceptreqdata == nil {
		common.Debug("===============InitAcceptData, it is acceptsign and get reqaddr sigs data fail 2222222222 =====================","key ",acceptsig.Key,"from ",from)
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
	    ch <- res
	    return fmt.Errorf("get reqaddr sigs data fail") 
	}

	HandleC1Data(acceptreqdata,acceptsig.Key,id)

	ars := GetAllReplyFromGroup(id,ac.GroupId,Rpc_SIGN,ac.Initiator)
	if ac.Deal == "true" || ac.Status == "Success" || ac.Status == "Failure" || ac.Status == "Timeout" {
		common.Info("===============InitAcceptData, it is acceptsign and sign has handled before 222222222=====================","key ",acceptsig.Key,"from ",from)
	    res := RpcDcrmRes{Ret:"", Tip: "sign has handled before", Err: fmt.Errorf("sign has handled before")}
	    ch <- res
	    return fmt.Errorf("sign has handled before")
	}

	common.Debug("=======================InitAcceptData,333333333333333333333333,set sign status =============================","status",status,"key",acceptsig.Key)
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
	common.Debug("===============InitAcceptData, check accept reshare raw success=====================","raw ",raw,"key ",acceptrh.Key,"from ",from,"txdata ",acceptrh)
	w, err := FindWorker(acceptrh.Key)
	if err != nil || w == nil {
	    c1data := acceptrh.Key + "-" + from
	    C1Data.WriteMap(strings.ToLower(c1data),raw)
	    res := RpcDcrmRes{Ret:"Failure", Tip: "get reshare accept data fail from db when no find worker.", Err: fmt.Errorf("get reshare accept data fail from db when no find worker")}
	    ch <- res
	    return fmt.Errorf("get reshare accept data fail from db whern no find worker.")
	}

	exsit,da := GetValueFromPubKeyData(acceptrh.Key)
	if !exsit {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "dcrm back-end internal error:get reshare accept data fail from db in init accept data", Err: fmt.Errorf("get reshare accept data fail from db in init accept data")}
	    ch <- res
	    return fmt.Errorf("get reshare accept data fail from db in init accept data.")
	}

	ac,ok := da.(*AcceptReShareData)
	if !ok || ac == nil {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "dcrm back-end internal error:decode accept data fail", Err: fmt.Errorf("decode accept data fail")}
	    ch <- res
	    return fmt.Errorf("decode accept data fail")
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
	
    common.Debug("===============InitAcceptData, it is not sign txdata and return fail ==================","key ",key,"from ",from,"nonce ",nonce)
    res := RpcDcrmRes{Ret: "", Tip: "init accept data fail.", Err: fmt.Errorf("init accept data fail")}
    ch <- res
    return fmt.Errorf("init accept data fail")
}

//==========================================================================

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
	    common.Debug("===============DisMsg,no find worker,so save the msg (c1 or accept res) to C1Data map=============","ss",strings.ToLower(ss),"msg",msg,"key",prexs[0])
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

		//test
		tail := w.msg_sendsignres.Back()
		head := w.msg_sendsignres.Front()
		fmt.Printf("=================DisMsg,tail = %v,head = %v, len = %v, key = %v ====================\n",tail,head,w.msg_sendsignres.Len(),prexs[0])
		if tail != nil && tail.Next() == nil {
			fmt.Printf("=================DisMsg, tail.next is nil, key = %v ====================\n",prexs[0])
		}
		if head != nil && head.Next() == nil {
			fmt.Printf("=================DisMsg, head.next is nil, key = %v ====================\n",prexs[0])
		}
		//
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
		common.Debug("======================DisMsg, after pushback================","w.msg_c1 len",w.msg_c1.Len(),"w.NodeCnt",w.NodeCnt,"key",prexs[0])
		if w.msg_c1.Len() == w.NodeCnt {
			common.Debug("======================DisMsg, Get All C1==================","w.msg_c1 len",w.msg_c1.Len(),"w.NodeCnt",w.NodeCnt,"key",prexs[0])
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
			common.Debug("=====================Get All MTAZK1PROOF====================","key",prexs[0])
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

		common.Debug("=====================Get C11====================","msg",msg,"key",prexs[0])
		w.msg_c11.PushBack(msg)
		if w.msg_c11.Len() == w.ThresHold {
			common.Debug("=====================Get All C11====================","key",prexs[0])
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
			common.Debug("=====================Get All KC====================","key",prexs[0])
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
			common.Debug("=====================Get All MKG====================","key",prexs[0])
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
			common.Debug("=====================Get All MKW====================","key",prexs[0])
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
			common.Debug("=====================Get All DELTA1====================","key",prexs[0])
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
			common.Debug("=====================Get All D11====================","key",prexs[0])
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
			common.Debug("=====================Get All CommitBigVAB====================","key",prexs[0])
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
			common.Debug("=====================Get All ZKABPROOF====================","key",prexs[0])
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
			common.Debug("=====================Get All CommitBigUT====================","key",prexs[0])
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
			common.Debug("=====================Get All CommitBigUTD11====================","key",prexs[0])
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
			common.Debug("=====================Get All S1====================","key",prexs[0])
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
			common.Info("=====================Get All SS1====================","key",prexs[0])
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
		//if w.msg_paillierkey.Len() == w.ThresHold {
		if w.msg_paillierkey.Len() == w.NodeCnt {
			common.Debug("=====================Get All PaillierKey====================","key",prexs[0])
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

