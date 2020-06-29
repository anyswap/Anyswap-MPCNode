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
	"strings"
	"math/big"
	"fmt"
	"time"
	"container/list"
	"github.com/fsn-dev/cryptoCoins/coins"
)

var (
	C1Data  = common.NewSafeMap(10)
	DecdsaMap  = common.NewSafeMap(10)
	GAccs  = common.NewSafeMap(10)
	
	//callback
	GetGroup               func(string) (int, string)
	SendToGroupAllNodes    func(string, string) (string, error)
	GetSelfEnode           func() string
	BroadcastInGroupOthers func(string, string) (string, error)
	SendToPeer             func(string, string) error
	ParseNode              func(string) string
	GetEosAccount          func() (string, string, string)

	DcrmCalls   = common.NewSafeMap(10)

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
	fmt.Printf("%v =================GetRawReply call CheckRaw =====================\n",common.CurrentTime())
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

	    if found == false {
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
    if exsit == false {
	return false
    }

    ac,ok := da.(*AcceptReqAddrData)
    if ok == false {
	return false
    }

    if ac == nil {
	return false
    }

    ret := GetRawReply(l)
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

	if found == false {
	    return false
	}
    }

    return true
}

//=========================================

func Call(msg interface{}, enode string) {
	fmt.Printf("%v =========Call,get msg = %v,sender node = %v =================\n", common.CurrentTime(), msg, enode)
	s := msg.(string)
	if s == "" {
	    return
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

	/////////
	res := self.msg
	if res == "" { //TODO
		res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get data fail in RecvMsg.Run", Err: fmt.Errorf("no find worker.")}
		ch <- res2
		return false
	}

	////
	msgdata, errdec := DecryptMsg(res) //for SendMsgToPeer
	if errdec == nil {
		res = msgdata
	}
	////
	mm := strings.Split(res, common.Sep)
	if len(mm) >= 2 {
		//msg:  key-enode:C1:X1:X2....:Xn
		//msg:  key-enode1:NoReciv:enode2:C1
		DisMsg(res)
		return true
	}

	////////////////////
	m, err2 := Decode2(res, "SignData")
	if err2 == nil {
	    sd,ok := m.(*SignData)
	    if ok {
		fmt.Printf("%v===============RecvMsg.Run, sign data = %v, msgprex = %v, key = %v ================\n",common.CurrentTime(),sd,sd.MsgPrex,sd.Key)

		w := workers[workid]
		w.sid = sd.Key
		w.groupid = sd.GroupId
		w.NodeCnt = sd.NodeCnt
		w.ThresHold = sd.ThresHold
		w.DcrmFrom = sd.DcrmFrom

		var ch1 = make(chan interface{}, 1)
		for i:=0;i < recalc_times;i++ {
		    fmt.Printf("%v===============RecvMsg.Run, sign recalc i = %v, msgprex = %v, key = %v ================\n",common.CurrentTime(),i,sd.MsgPrex,sd.Key)
		    if len(ch1) != 0 {
			<-ch1
		    }

		    w.Clear2()
		    Sign_ec2(sd.Key, sd.Save, sd.Sku1, sd.Txhash, sd.Keytype, sd.Pkx, sd.Pky, ch1, workid)
		    ret, _, cherr := GetChannelValue(ch_t, ch1)
		    if ret != "" && cherr == nil {

			ww, err2 := FindWorker(sd.MsgPrex)
			if err2 != nil || ww == nil {
			    res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker", Err: fmt.Errorf("no find worker")}
			    ch <- res2
			    return false
			}

			fmt.Printf("%v ======================RecvMsg.Run, finish sign, get ret = %v, cherr = %v, msgprex = %v, key = %v ==================\n",common.CurrentTime(),ret,cherr,sd.MsgPrex,sd.Key)

			ww.rsv.PushBack(ret)
			res2 := RpcDcrmRes{Ret: ret, Tip: "", Err: nil}
			ch <- res2
			return true 
		    }
		    
		    fmt.Printf("%v ======================RecvMsg.Run, ret = %v, cherr = %v, msgprex = %v, key = %v ==================\n",common.CurrentTime(),ret,cherr,sd.MsgPrex,sd.Key)
		    time.Sleep(time.Duration(3) * time.Second) //1000 == 1s
		}	
		
		res2 := RpcDcrmRes{Ret: "", Tip: "sign fail", Err: fmt.Errorf("sign fail")}
		ch <- res2
		return false 
	    }
	}
	////////////////////////////

	errtmp := InitAcceptData(res,workid,self.sender,ch)
	if errtmp == nil {
	    return true
	}
	fmt.Printf("%v================RecvMsg.Run, init accept data, err = %v ================\n",common.CurrentTime(),errtmp)

	return false 
}

//==========================================================================

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
	    fmt.Printf("%v ===============DisMsg,no find worker,so save the msg (c1 or accept res) to C1Data map. ss = %v, msg = %v,key = %v=================\n", common.CurrentTime(), strings.ToLower(ss),msg,prexs[0])
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
			fmt.Printf("%v=================Get C1 fail,w.msg_c1 was full, msg =%v, key =%v ================\n", common.CurrentTime(),msg, prexs[0])
			return
		}
		///
		if Find(w.msg_c1, msg) {
			fmt.Printf("%v=================C1 has exsit, msg=%v, key =%v ================\n", common.CurrentTime(),msg,prexs[0])
			return
		}

		//fmt.Printf("%v=================DisMsg, before pushback, w.msg_c1 len = %v, w.NodeCnt = %v, key = %v===================",common.CurrentTime(),w.msg_c1.Len(),w.NodeCnt,prexs[0])
		w.msg_c1.PushBack(msg)
		fmt.Printf("%v======================DisMsg, after pushback, w.msg_c1 len = %v, w.NodeCnt = %v, key = %v =======================\n",common.CurrentTime(),w.msg_c1.Len(),w.NodeCnt,prexs[0])
		if w.msg_c1.Len() == w.NodeCnt {
			fmt.Printf("%v======================DisMsg, Get All C1,w.msg_c1 len = %v, w.NodeCnt = %v, key = %v =======================\n",common.CurrentTime(),w.msg_c1.Len(),w.NodeCnt,prexs[0])
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

		//fmt.Printf("%v=================DisMsg, before pushback, w.msg_d1_1 len = %v, w.NodeCnt = %v, key = %v===================",common.CurrentTime(),w.msg_d1_1.Len(),w.NodeCnt,prexs[0])
		w.msg_d1_1.PushBack(msg)
		fmt.Printf("%v======================DisMsg, after pushback, w.msg_d1_1 len = %v, w.NodeCnt = %v, key = %v =======================\n",common.CurrentTime(),w.msg_d1_1.Len(),w.NodeCnt,prexs[0])
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
			fmt.Printf("%v===================Get All MTAZK1PROOF, key = %v====================\n",common.CurrentTime(),prexs[0])
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

		fmt.Printf("%v=================Get C11, msg =%v, key =%s===================\n",common.CurrentTime(),msg,prexs[0])
		w.msg_c11.PushBack(msg)
		if w.msg_c11.Len() == w.ThresHold {
			fmt.Printf("%v===================Get All C11, key = %v====================\n",common.CurrentTime(),prexs[0])
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
			fmt.Printf("%v===================Get All KC, key = %v====================\n",common.CurrentTime(),prexs[0])
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
			fmt.Printf("%v===================Get All MKG, key = %v====================\n",common.CurrentTime(),prexs[0])
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
			fmt.Printf("%v===================Get All MKW, key = %v====================\n",common.CurrentTime(),prexs[0])
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
			fmt.Printf("%v===================Get All DELTA1, key = %v====================\n",common.CurrentTime(),prexs[0])
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

		fmt.Printf("%v=================Get D11, msg =%v, key =%v===================\n",common.CurrentTime(),msg,prexs[0])
		w.msg_d11_1.PushBack(msg)
		if w.msg_d11_1.Len() == w.ThresHold {
		    fmt.Printf("%v=================Get All D11, key =%v===================\n",common.CurrentTime(),prexs[0])
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
			fmt.Printf("%v===================Get All CommitBigVAB, key = %v====================\n",common.CurrentTime(),prexs[0])
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
			fmt.Printf("%v===================Get All ZKABPROOF, key = %v====================\n",common.CurrentTime(),prexs[0])
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
			fmt.Printf("%v===================Get All CommitBigUT, key = %v====================\n",common.CurrentTime(),prexs[0])
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
			fmt.Printf("%v===================Get All CommitBigUTD11, key = %v====================\n",common.CurrentTime(),prexs[0])
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
			fmt.Printf("%v===================Get All S1, key = %v====================\n",common.CurrentTime(),prexs[0])
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

		fmt.Printf("%v=================Get SS1, msg =%v, key =%v===================\n",common.CurrentTime(),msg,prexs[0])
		w.msg_ss1.PushBack(msg)
		if w.msg_ss1.Len() == w.ThresHold {
		    fmt.Printf("%v=================Get All SS1, msg =%v, key =%v===================\n",common.CurrentTime(),msg,prexs[0])
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
			fmt.Printf("%v===================Get All PaillierKey, key = %v====================\n",common.CurrentTime(),prexs[0])
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

type RecivAcceptResTime struct {
    RecivTime string
    Reply string
}

type SendAcceptResTime struct {
    SendTime string
    Reply string
}

type RecivDcrmTime struct {
    Round string
    RecivTime string
    Msg string
}

type SendDcrmTime struct {
    Round string
    SendTime string
    Msg string
}

type NoRecivData struct {
    Node string
    Msg string
}

type DecdsaLog struct {
    CurEnode string  //enodeid:ip:port
    GroupEnodes []string
    DcrmCallTime string
    RecivAcceptRes []RecivAcceptResTime
    SendAcceptRes []SendAcceptResTime
    RecivDcrm []RecivDcrmTime
    SendDcrm []SendDcrmTime
    FailTime string
    FailInfo string
    No_Reciv []NoRecivData
}

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

