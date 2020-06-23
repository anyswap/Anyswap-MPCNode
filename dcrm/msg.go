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
	"encoding/json"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	"strings"
	"strconv"
	"math/big"
	"github.com/fsn-dev/dcrm-walletService/p2p/discover"
	"fmt"
	"time"
	"container/list"
	"encoding/hex"
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

//
func DcrmCall(msg interface{}, enode string) <-chan string {
	s := msg.(string)
	ch := make(chan string, 1)

	///check
	_, exsit := DcrmCalls.ReadMap(s)
	if !exsit {
		DcrmCalls.WriteMap(s, "true")
	} else {
		common.Info("=============DcrmCall,already exsit in DcrmCalls and return ", "get msg len =", len(s), "sender node =", enode, "", "================")
		ret := ("fail" + common.Sep + "already exsit in DcrmCalls" + common.Sep + "dcrm back-end internal error:already exsit in DcrmCalls" + common.Sep + "already exsit in DcrmCalls") //TODO "no-data"
		ch <- ret
		return ch
	}
	///

	////////
	if s == "" {
		//fail:chret:tip:error
		ret := ("fail" + common.Sep + "no-data" + common.Sep + "dcrm back-end internal error:get msg fail" + common.Sep + "get msg fail") //TODO "no-data"
		ch <- ret
		return ch
	}

	res, err := UnCompress(s)
	if err != nil {
		//fail:chret:tip:error
		ret := ("fail" + common.Sep + "no-data" + common.Sep + "dcrm back-end internal error:uncompress data fail in RecvMsg.Run" + common.Sep + "uncompress data fail in recvmsg.run") //TODO "no-data"
		ch <- ret
		return ch
	}

	r, err := Decode2(res, "SendMsg")
	if err != nil {
		//fail:chret:tip:error
		ret := ("fail" + common.Sep + "no-data" + common.Sep + "dcrm back-end internal error:decode data to SendMsg fail in RecvMsg.Run" + common.Sep + "decode data to SendMsg fail in recvmsg.run") //TODO "no-data"
		ch <- ret
		return ch
	}

	rr := r.(*SendMsg)

	test := Keccak256Hash([]byte(strings.ToLower(s))).Hex()
	fmt.Printf("%v =============DcrmCall, get msg len = %v,msg hash = %v,sender node = %v,key = %v =======================\n", common.CurrentTime(), len(s), test, enode, rr.Nonce)
	////////

	v := RecvMsg{msg: s, sender: enode}
	rch := make(chan interface{}, 1)
	req := RPCReq{rpcdata: &v, ch: rch}
	RPCReqQueue <- req
	//fmt.Printf("%v =============DcrmCall, finish send req to Queue,msg hash = %v,key = %v =======================\n", common.CurrentTime(), test, rr.Nonce)
	chret, tip, cherr := GetChannelValue(sendtogroup_timeout, rch)
	//fmt.Printf("%v =============DcrmCall, ret = %v,err = %v,msg hash = %v,key = %v =======================\n", common.CurrentTime(), chret, cherr, test, rr.Nonce)
	if cherr != nil {
		//fail:chret:tip:error
		ret := ("fail" + common.Sep + chret + common.Sep + tip + common.Sep + cherr.Error())
		ch <- ret
		return ch
	}

	//success:chret
	ret := ("success" + common.Sep + chret)
	ch <- ret
	return ch
}

func DcrmCallRet(msg interface{}, enode string) {

	//msg = success:workid:msgtype:ret  or fail:workid:msgtype:tip:error
	res := msg.(string)
	fmt.Printf("%v============================!!!!!! DcrmCallRet, get return value = %v, !!!!!!=========================\n",common.CurrentTime(),res)
	if res == "" {
		return
	}

	ss := strings.Split(res, common.Sep)
	if len(ss) < 4 {
		return
	}

	status := ss[0]
	if strings.EqualFold(status, "fail") {
		//check
		if ss[1] == "already exsit in DcrmCalls" {
			return
		}
		//

		if len(ss) < 5 {
			return
		}
	}

	//msgtype := ss[2]
	//fmt.Printf("%v==============DcrmCallRet,ret = %v ===============\n",common.CurrentTime(),ss[3])
	workid, err := strconv.Atoi(ss[1])
	if err != nil || workid < 0 || workid >= RPCMaxWorker {
		return
	}

	//success:workid:msgtype:ret
	if status == "success" {
		w := workers[workid]
		res2 := RpcDcrmRes{Ret: ss[3], Tip: "", Err: nil}
		w.retres.PushBack(&res2)

		if ss[2] == "rpc_lockout" {
			if w.retres.Len() == w.NodeCnt {
				ret := GetGroupRes(workid)
				w.ch <- ret
			}
		}

		if ss[2] == "rpc_sign" {
			if w.retres.Len() == w.NodeCnt {
				ret := GetGroupRes(workid)
				w.ch <- ret
			}
		}

		if ss[2] == "rpc_reshare" {
			if w.retres.Len() == w.NodeCnt {
				ret := GetGroupRes(workid)
				w.ch <- ret
			}
		}

		if ss[2] == "rpc_req_dcrmaddr" {
			if w.retres.Len() == w.NodeCnt {
				ret := GetGroupRes(workid)
				w.ch <- ret
			}
		}

		return
	}

	//fail:workid:msgtype:tip:error
	if status == "fail" {
		w := workers[workid]
		var ret2 Err
		ret2.Info = ss[4]
		res2 := RpcDcrmRes{Ret: "", Tip: ss[3], Err: ret2}
		w.retres.PushBack(&res2)

		if ss[2] == "rpc_lockout" {
			if w.retres.Len() == w.NodeCnt {
				ret := GetGroupRes(workid)
				w.ch <- ret
			}
		}

		if ss[2] == "rpc_sign" {
			if w.retres.Len() == w.NodeCnt {
				ret := GetGroupRes(workid)
				w.ch <- ret
			}
		}

		if ss[2] == "rpc_reshare" {
			if w.retres.Len() == w.NodeCnt {
				ret := GetGroupRes(workid)
				w.ch <- ret
			}
		}

		if ss[2] == "rpc_req_dcrmaddr" {
			if w.retres.Len() == w.NodeCnt {
				ret := GetGroupRes(workid)
				w.ch <- ret
			}
		}

		return
	}
}

func GetGroupRes(wid int) RpcDcrmRes {
	if wid < 0 || wid >= RPCMaxWorker {
		res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get work id fail", Err: GetRetErr(ErrGetWorkerIdError)}
		return res2
	}

	var l *list.List
	w := workers[wid]
	l = w.retres

	if l == nil {
		res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get result from group fail", Err: GetRetErr(ErrGetNoResFromGroupMem)}
		return res2
	}

	var err error
	iter := l.Front()
	for iter != nil {
		ll := iter.Value.(*RpcDcrmRes)
		err = ll.Err
		if err != nil {
			return (*ll)
		}
		iter = iter.Next()
	}

	iter = l.Front()
	for iter != nil {
		ll := iter.Value.(*RpcDcrmRes)
		return (*ll)
	}

	res2 := RpcDcrmRes{Ret: "", Tip: "", Err: nil}
	return res2
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

	test := Keccak256Hash([]byte(strings.ToLower(res))).Hex()

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
	errtmp := InitAcceptData(res,workid,self.sender,ch)
	if errtmp == nil {
	    return true
	}
	fmt.Printf("%v================RecvMsg.Run, init accept data, err = %v ================\n",common.CurrentTime(),errtmp)
	////////////////////

	res, err := UnCompress(res)
	if err != nil {
		fmt.Printf("%v ===================RecvMsg.Run,the msg is not key-enode:C1:X1:X2...Xn, uncompress fail,msg hash = %v,err = %v ==============================\n", common.CurrentTime(), test, err)
		res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:uncompress data fail in RecvMsg.Run", Err: fmt.Errorf("uncompress data fail in recvmsg.run")}
		ch <- res2
		return false
	}

	r, err := Decode2(res, "SendMsg")
	if err != nil {
		fmt.Printf("%v ===================RecvMsg.Run,the msg is not key-enode:C1:X1:X2...:Xn, decode fail,msg hash = %v,err = %v ==============================\n", common.CurrentTime(), test, err)
		res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:decode data to SendMsg fail in RecvMsg.Run", Err: fmt.Errorf("decode data to SendMsg fail in recvmsg.run")}
		ch <- res2
		return false
	}

	switch r.(type) {
	case *SendMsg:
		rr := r.(*SendMsg)

		var wid int
		if strings.EqualFold(cur_enode, self.sender) { //self send
			wid = rr.WorkId
		} else {
			wid = workid
		}

		//fmt.Printf("%v ===================RecvMsg.Run,the msg is not key-enode:C1:X1:X2...Xn, msg hash = %v,wid = %v,key = %v ==============================\n", common.CurrentTime(), test, wid, rr.Nonce)

		//rpc_lockout
		if rr.MsgType == "rpc_lockout" {
			
			if !strings.EqualFold(cur_enode, self.sender) { //self send
			    //nonce check
			    exsit,_ := GetValueFromPubKeyData(rr.Nonce)
			    ///////
			    if !exsit {
				    fmt.Printf("%v ================RecvMsg.Run,lockout nonce error, key = %v ==================\n", common.CurrentTime(), rr.Nonce)
				    //TODO must set acceptlockout(.....)
				    res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:lockout tx nonce error", Err: fmt.Errorf("lockout tx nonce error")}
				    ch <- res2
				    return false
			    }
			}
			
			w := workers[workid]
			w.sid = rr.Nonce
			//msg = fusionaccount:dcrmaddr:dcrmto:value:cointype:groupid:nonce:threshold:mode:key:timestamp
			lomsg := LockOutSendMsgToDcrm{}
			err = json.Unmarshal([]byte(rr.Msg), &lomsg)
			if err != nil {
			    res := RpcDcrmRes{Ret: "", Tip: "recover tx.data json string fail from raw data,maybe raw data error", Err: err}
			    ch <- res
			    return false
			}

			lo := TxDataLockOut{}
			err = json.Unmarshal([]byte(lomsg.TxData), &lo)
			if err != nil {
			    res := RpcDcrmRes{Ret: "", Tip: "recover tx.data json string fail from raw data,maybe raw data error", Err: err}
			    ch <- res
			    return false
			}

			w.groupid = lo.GroupId 
			w.limitnum = lo.ThresHold
			gcnt, _ := GetGroup(w.groupid)
			w.NodeCnt = gcnt
			//fmt.Printf("%v ===================RecvMsg.Run, w.NodeCnt = %v, w.groupid = %v, wid = %v, key = %v ==============================\n", common.CurrentTime(), w.NodeCnt, w.groupid,wid, rr.Nonce)
			w.ThresHold = w.NodeCnt

			nums := strings.Split(w.limitnum, "/")
			if len(nums) == 2 {
			    nodecnt, err := strconv.Atoi(nums[1])
			    if err == nil {
				w.NodeCnt = nodecnt
			    }

			    //th, err := strconv.Atoi(nums[0])
			    //if err == nil {
				w.ThresHold = gcnt
			    //}
			}

			w.DcrmFrom = lo.DcrmAddr

			/////
			pubkey := ""
			lokey := Keccak256Hash([]byte(strings.ToLower(lo.DcrmAddr))).Hex()
			exsit,loda := GetValueFromPubKeyData(lokey)
			if exsit {
			    _,ok := loda.(*PubKeyData)
			    if ok == true {
				dcrmpub := (loda.(*PubKeyData)).Pub
				pubkey = hex.EncodeToString([]byte(dcrmpub))
			    }
			}
			if pubkey == "" {
			    res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get pubkey fail", Err: fmt.Errorf("get pubkey fail")}
			    ch <- res2
			    return false
			}
			/////

			//fmt.Printf("%v====================RecvMsg.Run,w.NodeCnt = %v, w.ThresHold = %v, w.limitnum = %v, key = %v ================\n",common.CurrentTime(),w.NodeCnt,w.ThresHold,w.limitnum,rr.Nonce)

			if strings.EqualFold(cur_enode, self.sender) { //self send
				AcceptLockOut(self.sender,lomsg.Account, lo.GroupId, lomsg.Nonce, lo.DcrmAddr, lo.ThresHold, "false", "false", "Pending", "", "", "", nil, wid)
			} else {
				cur_nonce, _, _ := GetLockOutNonce(lomsg.Account)
				cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
				new_nonce_num, _ := new(big.Int).SetString(lomsg.Nonce, 10)
				if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
					_, err = SetLockOutNonce(lomsg.Account, lomsg.Nonce)
					if err != nil {
						fmt.Printf("%v ================RecvMsg.Run,set lockout nonce fail, key = %v ==================\n", common.CurrentTime(), rr.Nonce)
						//TODO must set acceptlockout(.....)
						res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:set lockout nonce fail in RecvMsg.Run", Err: fmt.Errorf("set lockout nonce fail in recvmsg.run")}
						ch <- res2
						return false
					}
				}

				ars := GetAllReplyFromGroup(w.id,lo.GroupId,Rpc_LOCKOUT,self.sender)
				ac := &AcceptLockOutData{Initiator:self.sender,Account: lomsg.Account, GroupId: lo.GroupId, Nonce: lomsg.Nonce, PubKey: pubkey, DcrmTo: lo.DcrmTo, Value: lo.Value, Cointype: lo.Cointype, LimitNum: lo.ThresHold, Mode: lo.Mode, TimeStamp: lo.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", OutTxHash: "", Tip: "", Error: "", AllReply: ars, WorkId: wid}
				err := SaveAcceptLockOutData(ac)
				fmt.Printf("%v ===================finish call SaveAcceptLockOutData, err = %v,wid = %v,account = %v,group id = %v,nonce = %v,dcrm from = %v,dcrm to = %v,value = %v,cointype = %v,threshold = %v,mode = %v,key = %v =========================\n", common.CurrentTime(), err, wid, lomsg.Account, lo.GroupId, lomsg.Nonce, lo.DcrmAddr, lo.DcrmTo, lo.Value, lo.Cointype, lo.ThresHold, lo.Mode, rr.Nonce)
				if err != nil {
					res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:set AcceptLockOutData fail in RecvMsg.Run", Err: fmt.Errorf("set AcceptLockOutData fail in recvmsg.run")}
					ch <- res2
					return false
				}
				////
				dcrmkey := Keccak256Hash([]byte(strings.ToLower(lo.DcrmAddr))).Hex()
				exsit,da := GetValueFromPubKeyData(dcrmkey)
				if exsit {
				    _,ok := da.(*PubKeyData)
				    if ok == true {
					dcrmpub := (da.(*PubKeyData)).Pub
					exsit,da2 := GetValueFromPubKeyData(dcrmpub)
					if exsit {
					    _,ok = da2.(*PubKeyData)
					    if ok == true {
						keys := (da2.(*PubKeyData)).RefLockOutKeys
						if keys == "" {
						    keys = rr.Nonce
						} else {
						    keys = keys + ":" + rr.Nonce
						}

						pubs3 := &PubKeyData{Key:(da2.(*PubKeyData)).Key,Account: (da2.(*PubKeyData)).Account, Pub: (da2.(*PubKeyData)).Pub, Save: (da2.(*PubKeyData)).Save, Nonce: (da2.(*PubKeyData)).Nonce, GroupId: (da2.(*PubKeyData)).GroupId, LimitNum: (da2.(*PubKeyData)).LimitNum, Mode: (da2.(*PubKeyData)).Mode,KeyGenTime:(da2.(*PubKeyData)).KeyGenTime,RefLockOutKeys:keys,RefSignKeys:(da2.(*PubKeyData)).RefSignKeys}
						epubs, err := Encode2(pubs3)
						if err == nil {
						    ss3, err := Compress([]byte(epubs))
						    if err == nil {
							kd := KeyData{Key: []byte(dcrmpub), Data: ss3}
							PubKeyDataChan <- kd
							LdbPubKeyData.WriteMap(dcrmpub, pubs3)
							//fmt.Printf("%v ==============================RecvMsg.Run,reset PubKeyData success, key = %v ============================================\n", common.CurrentTime(),rr.Nonce)
						    }
						}
					    }
					}
				    }
				}
			}

			////bug
			if lo.Mode == "0" { // self-group
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
							common.Debug("(self *RecvMsg) Run(),", "account= ", account, "key = ", rr.Nonce)
							ars := GetAllReplyFromGroup(w.id,lo.GroupId,Rpc_LOCKOUT,self.sender)
							fmt.Printf("%v ================== (self *RecvMsg) Run() , get all AcceptLockOutRes ,result = %v,key = %v ============================\n", common.CurrentTime(), ars, rr.Nonce)
							
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
								AcceptLockOut(self.sender,lomsg.Account, lo.GroupId, lomsg.Nonce, lo.DcrmAddr, lo.ThresHold, "false", "false", "Failure", "", "don't accept lockout", "don't accept lockout", ars, wid)
							} else {
								tip = ""
								AcceptLockOut(self.sender,lomsg.Account, lo.GroupId, lomsg.Nonce, lo.DcrmAddr, lo.ThresHold, "false", "true", "Pending", "", "", "", ars, wid)
							}

							///////
							timeout <- true
							return
						case <-agreeWaitTimeOut.C:
							fmt.Printf("%v ================== (self *RecvMsg) Run() , agree wait timeout. key = %v,=====================\n", common.CurrentTime(), rr.Nonce)
							ars := GetAllReplyFromGroup(w.id,lo.GroupId,Rpc_LOCKOUT,self.sender)
							//bug: if self not accept and timeout
							AcceptLockOut(self.sender,lomsg.Account, lo.GroupId, lomsg.Nonce, lo.DcrmAddr, lo.ThresHold, "false", "false", "Timeout", "", "get other node accept lockout result timeout", "get other node accept lockout result timeout", ars, wid)
							reply = false
							tip = "get other node accept lockout result timeout"
							//

							timeout <- true
							return
						}
					}
				}(wid)

				if len(workers[wid].acceptWaitLockOutChan) == 0 {
					workers[wid].acceptWaitLockOutChan <- "go on"
				}

				<-timeout

				//fmt.Printf("%v ================== (self *RecvMsg) Run() , the terminal accept lockout result = %v,key = %v,============================\n", common.CurrentTime(), reply, rr.Nonce)

				if !reply {
					//////////////////////lockout result start/////////////////////////
					if tip == "get other node accept lockout result timeout" {
						ars := GetAllReplyFromGroup(w.id,lo.GroupId,Rpc_LOCKOUT,self.sender)
						AcceptLockOut(self.sender,lomsg.Account, lo.GroupId, lomsg.Nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Timeout", "", "get other node accept lockout result timeout", "get other node accept lockout result timeout", ars, wid)
					} else {
						/////////////TODO tmp
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
						//fmt.Printf("%v ================RecvMsg.Run,send SendLockOutRes msg to other nodes finish,key = %v =============\n", common.CurrentTime(), rr.Nonce)
						_, _, err := GetChannelValue(ch_t, w.bsendlockoutres)
						//fmt.Printf("%v ================RecvMsg.Run,the SendLockOutRes result from other nodes, err = %v,key = %v =============\n", common.CurrentTime(), err, rr.Nonce)
						ars := GetAllReplyFromGroup(w.id,lo.GroupId,Rpc_LOCKOUT,self.sender)
						if err != nil {
							tip = "get other node terminal accept lockout result timeout" ////bug
							AcceptLockOut(self.sender,lomsg.Account, lo.GroupId, lomsg.Nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Timeout", "", tip, tip, ars, wid)
						} else if w.msg_sendlockoutres.Len() != w.ThresHold {
							//fmt.Printf("%v ================RecvMsg,the result SendLockOutRes msg from other nodes fail,key = %v =======================\n", common.CurrentTime(), rr.Nonce)
							AcceptLockOut(self.sender,lomsg.Account, lo.GroupId, lomsg.Nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Failure", "", "get other node lockout result fail", "get other node lockout result fail", ars, wid)
						} else {
							reply2 := "false"
							lohash := ""
							iter := w.msg_sendlockoutres.Front()
							for iter != nil {
								mdss := iter.Value.(string)
								ms := strings.Split(mdss, common.Sep)
								//prexs := strings.Split(ms[0],"-")
								//node := prexs[1]
								if strings.EqualFold(ms[2], "Success") {
									reply2 = "true"
									lohash = ms[3]
									break
								}

								lohash = ms[3]
								iter = iter.Next()
							}

							if reply2 == "true" {
								//fmt.Printf("%v ================RecvMsg,the terminal lockout res is success. key = %v ==================\n", common.CurrentTime(), rr.Nonce)
								AcceptLockOut(self.sender,lomsg.Account, lo.GroupId, lomsg.Nonce, lo.DcrmAddr, lo.ThresHold, "true", "true", "Success", lohash, " ", " ", ars, wid)
							} else {
								//fmt.Printf("%v ================RecvMsg,the terminal lockout res is fail. key = %v ==================\n", common.CurrentTime(), rr.Nonce)
								AcceptLockOut(self.sender,lomsg.Account, lo.GroupId, lomsg.Nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Failure", "", lohash, lohash, ars, wid)
							}
						}
						/////////////////////
					}
					///////////////////////lockout result end////////////////////////

					res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + common.Sep + rr.MsgType, Tip: tip, Err: fmt.Errorf("don't accept lockout.")}
					ch <- res2
					return false
				}
			} else {
				if len(workers[wid].acceptWaitLockOutChan) == 0 {
					workers[wid].acceptWaitLockOutChan <- "go on"
				}

				if !strings.EqualFold(cur_enode, self.sender) { //no self send
					ars := GetAllReplyFromGroup(w.id,lo.GroupId,Rpc_LOCKOUT,self.sender)
					AcceptLockOut(self.sender,lomsg.Account, lo.GroupId, lomsg.Nonce, lo.DcrmAddr, lo.ThresHold, "false", "true", "Pending", "", "", "", ars, wid)
				}
			}

			rch := make(chan interface{}, 1)
			//msg = fusionaccount:dcrmaddr:dcrmto:value:cointype:groupid:nonce:threshold:mode:key:timestamp
			//fmt.Printf("%v ================== (self *RecvMsg) Run() , start call validate_lockout,key = %v,=====================\n", common.CurrentTime(), rr.Nonce)
			validate_lockout(w.sid, lomsg.Account, lo.DcrmAddr, lo.Cointype, lo.Value, lo.DcrmTo, lomsg.Nonce, lo.Memo,rch)
			//fmt.Printf("%v ================== (self *RecvMsg) Run() , finish call validate_lockout,key = %v ============================\n", common.CurrentTime(), rr.Nonce)
			chret, tip, cherr := GetChannelValue(ch_t, rch)
			//fmt.Printf("%v ================== (self *RecvMsg) Run() , finish and get validate_lockout return value = %v,err = %v,key = %v ============================\n", common.CurrentTime(), chret, cherr, rr.Nonce)
			if chret != "" {
				res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + common.Sep + rr.MsgType + common.Sep + chret, Tip: "", Err: nil}
				ch <- res2
				return true
			}

			//////////////////////lockout result start/////////////////////////
			ars := GetAllReplyFromGroup(w.id,lo.GroupId,Rpc_LOCKOUT,self.sender)
			if tip == "get other node accept lockout result timeout" {
				AcceptLockOut(self.sender,lomsg.Account, lo.GroupId, lomsg.Nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Timeout", "", tip, cherr.Error(), ars, wid)
			} else {
				/////////////TODO tmp
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
				//fmt.Printf("%v ================RecvMsg.Run,send SendLockOutRes msg to other nodes finish,key = %v =============\n", common.CurrentTime(), rr.Nonce)
				_, _, err := GetChannelValue(ch_t, w.bsendlockoutres)
				//fmt.Printf("%v ================RecvMsg.Run,the SendLockOutRes result from other nodes finish,key = %v =============\n", common.CurrentTime(), rr.Nonce)
				if err != nil {
					tip = "get other node terminal accept lockout result timeout" ////bug
					AcceptLockOut(self.sender,lomsg.Account, lo.GroupId, lomsg.Nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Timeout", "", tip, tip, ars, wid)
				} else if w.msg_sendlockoutres.Len() != w.ThresHold {
					//fmt.Printf("%v ================RecvMsg.Run,the SendLockOutRes result from other nodes fail,key = %v =============\n", common.CurrentTime(), rr.Nonce)
					AcceptLockOut(self.sender,lomsg.Account, lo.GroupId, lomsg.Nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Failure", "", "get other node lockout result fail", "get other node lockout result fail", ars, wid)
				} else {
					reply2 := "false"
					lohash := ""
					iter := w.msg_sendlockoutres.Front()
					for iter != nil {
						mdss := iter.Value.(string)
						ms := strings.Split(mdss, common.Sep)
						//prexs := strings.Split(ms[0],"-")
						//node := prexs[1]
						if strings.EqualFold(ms[2], "Success") {
							reply2 = "true"
							lohash = ms[3]
							break
						}

						lohash = ms[3]
						iter = iter.Next()
					}

					if reply2 == "true" {
						//fmt.Printf("%v ================RecvMsg,the terminal lockout res is success. key = %v ==================\n", common.CurrentTime(), rr.Nonce)
						AcceptLockOut(self.sender,lomsg.Account, lo.GroupId, lomsg.Nonce, lo.DcrmAddr, lo.ThresHold, "true", "true", "Success", lohash, " ", " ", ars, wid)
					} else {
						//fmt.Printf("%v ================RecvMsg,the terminal lockout res is fail. key = %v ==================\n", common.CurrentTime(), rr.Nonce)
						AcceptLockOut(self.sender,lomsg.Account, lo.GroupId, lomsg.Nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Failure", "", lohash, lohash, ars, wid)
					}
				}
				/////////////////////
			}
			///////////////////////lockout result end////////////////////////

			if cherr != nil {
				res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + common.Sep + rr.MsgType, Tip: tip, Err: cherr}
				ch <- res2
				return false
			}

			//fmt.Printf("%v ==============RecvMsg.Run,LockOut send tx to net fail, key = %v =======================\n", common.CurrentTime(), rr.Nonce)
			res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + common.Sep + rr.MsgType, Tip: tip, Err: fmt.Errorf("send tx to net fail.")}
			ch <- res2
			return true
		}

		//rpc_reshare
		if rr.MsgType == "rpc_reshare" {
			
			w := workers[workid]
			w.sid = rr.Nonce
			resharemsg := ReShareSendMsgToDcrm{}
			err = json.Unmarshal([]byte(rr.Msg), &resharemsg)
			if err != nil {
			    res := RpcDcrmRes{Ret: "", Tip: "recover tx.data json string fail from raw data,maybe raw data error", Err: err}
			    ch <- res
			    return false
			}

			rh := TxDataReShare{}
			err = json.Unmarshal([]byte(resharemsg.TxData), &rh)
			if err != nil {
			    res := RpcDcrmRes{Ret: "", Tip: "recover tx.data json string fail from raw data,maybe raw data error", Err: err}
			    ch <- res
			    return false
			}

			w.groupid = rh.TSGroupId 
			w.limitnum = rh.ThresHold
			gcnt, _ := GetGroup(w.groupid)
			w.NodeCnt = gcnt
			//tscount,_ := strconv.Atoi(rh.TSCount)
			//w.NodeCnt = tscount
			//fmt.Printf("%v ===================RecvMsg.Run, w.NodeCnt = %v, w.groupid = %v, wid = %v, key = %v ==============================\n", common.CurrentTime(), w.NodeCnt, w.groupid,wid, rr.Nonce)
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

			//fmt.Printf("%v====================RecvMsg.Run,w.NodeCnt = %v, w.ThresHold = %v, w.limitnum = %v, key = %v ================\n",common.CurrentTime(),w.NodeCnt,w.ThresHold,w.limitnum,rr.Nonce)

			if strings.EqualFold(cur_enode, self.sender) { //self send
				AcceptReShare(self.sender,resharemsg.Account, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "false", "Pending", "", "", "", nil, wid)
			} else {
				sigs := ""
				datmp, exsit := GAccs.ReadMap(strings.ToLower(rr.Nonce))
				if exsit {
				    sigs = string(datmp.([]byte))
				    go GAccs.DeleteMap(strings.ToLower(rr.Nonce))
				}

				ars := GetAllReplyFromGroup(w.id,rh.GroupId,Rpc_RESHARE,self.sender)
				ac := &AcceptReShareData{Initiator:self.sender,Account: resharemsg.Account, GroupId: rh.GroupId, TSGroupId:rh.TSGroupId, PubKey: rh.PubKey, LimitNum: rh.ThresHold, PubAccount:rh.Account, Mode:rh.Mode, Sigs:sigs, TimeStamp: rh.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", NewSk: "", Tip: "", Error: "", AllReply: ars, WorkId:wid}
				err := SaveAcceptReShareData(ac)
				fmt.Printf("%v ===================finish call SaveAcceptReShareData, err = %v,wid = %v,account = %v,group id = %v,pubkey = %v,threshold = %v,key = %v =========================\n", common.CurrentTime(), err, wid, resharemsg.Account, rh.GroupId, rh.PubKey, rh.ThresHold, rr.Nonce)
				if err != nil {
					res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:set AcceptReShareData fail in RecvMsg.Run", Err: fmt.Errorf("set AcceptReShareData fail in recvmsg.run")}
					ch <- res2
					return false
				}
				////
				/*dcrmpks, _ := hex.DecodeString(ac.PubKey)
				exsit,da := GetValueFromPubKeyData(string(dcrmpks[:]))
				if exsit {
				    _,ok := da.(*PubKeyData)
				    if ok == true {
					keys := (da.(*PubKeyData)).RefReShareKeys
					if keys == "" {
					    keys = rr.Nonce
					} else {
					    keys = keys + ":" + rr.Nonce
					}

					pubs3 := &PubKeyData{Key:(da.(*PubKeyData)).Key,Account: (da.(*PubKeyData)).Account, Pub: (da.(*PubKeyData)).Pub, Save: (da.(*PubKeyData)).Save, Nonce: (da.(*PubKeyData)).Nonce, GroupId: (da.(*PubKeyData)).GroupId, LimitNum: (da.(*PubKeyData)).LimitNum, Mode: (da.(*PubKeyData)).Mode,KeyGenTime:(da.(*PubKeyData)).KeyGenTime,RefLockOutKeys:(da.(*PubKeyData)).RefLockOutKeys,RefSignKeys:(da.(*PubKeyData)).RefSignKeys,RefReShareKeys:keys}
					epubs, err := Encode2(pubs3)
					if err == nil {
					    ss3, err := Compress([]byte(epubs))
					    if err == nil {
						kd := KeyData{Key: dcrmpks[:], Data: ss3}
						PubKeyDataChan <- kd
						LdbPubKeyData.WriteMap(string(dcrmpks[:]), pubs3)
						fmt.Printf("%v ==============================RecvMsg.Run,reset PubKeyData success, key = %v ============================================\n", common.CurrentTime(),rr.Nonce)
					    }
					}
				    }
				}*/
			}

			////bug
			//if rh.Mode == "0" { // self-group
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
						case account := <-wtmp2.acceptReShareChan:
							common.Debug("(self *RecvMsg) Run(),", "account= ", account, "key = ", rr.Nonce)
							ars := GetAllReplyFromGroup(w.id,rh.GroupId,Rpc_RESHARE,self.sender)
							fmt.Printf("%v ================== (self *RecvMsg) Run() , get all AcceptReShareRes ,result = %v,key = %v ============================\n", common.CurrentTime(), ars, rr.Nonce)
							
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
								AcceptReShare(self.sender,resharemsg.Account, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "false", "Failure", "", "don't accept reshare", "don't accept reshare", nil, wid)
							} else {
								tip = ""
								AcceptReShare(self.sender,resharemsg.Account, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "false", "pending", "", "", "", ars, wid)
							}

							///////
							timeout <- true
							return
						case <-agreeWaitTimeOut.C:
							fmt.Printf("%v ================== (self *RecvMsg) Run() , agree wait timeout. key = %v,=====================\n", common.CurrentTime(), rr.Nonce)
							ars := GetAllReplyFromGroup(w.id,rh.GroupId,Rpc_RESHARE,self.sender)
							//bug: if self not accept and timeout
							AcceptReShare(self.sender,resharemsg.Account, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "false", "Timeout", "", "get other node accept reshare result timeout", "get other node accept reshare result timeout", ars, wid)
							reply = false
							tip = "get other node accept reshare result timeout"
							//

							timeout <- true
							return
						}
					}
				}(wid)

				if len(workers[wid].acceptWaitReShareChan) == 0 {
					workers[wid].acceptWaitReShareChan <- "go on"
				}

				<-timeout

				//fmt.Printf("%v ================== (self *RecvMsg) Run() , the terminal accept reshare result = %v,key = %v,============================\n", common.CurrentTime(), reply, rr.Nonce)

				if !reply {
					//////////////////////reshare result start/////////////////////////
					if tip == "get other node accept reshare result timeout" {
						ars := GetAllReplyFromGroup(w.id,rh.GroupId,Rpc_RESHARE,self.sender)
						AcceptReShare(self.sender,resharemsg.Account, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold, rh.Mode,"false", "", "Timeout", "", "get other node accept reshare result timeout", "get other node accept reshare result timeout", ars, wid)
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
						//fmt.Printf("%v ================RecvMsg.Run,send SendReShareRes msg to other nodes finish,key = %v =============\n", common.CurrentTime(), rr.Nonce)
						_, _, err := GetChannelValue(ch_t, w.bsendreshareres)
						//fmt.Printf("%v ================RecvMsg.Run,the SendReShareRes result from other nodes, err = %v,key = %v =============\n", common.CurrentTime(), err, rr.Nonce)
						ars := GetAllReplyFromGroup(w.id,rh.GroupId,Rpc_RESHARE,self.sender)
						if err != nil {
							tip = "get other node terminal accept reshare result timeout" ////bug
							AcceptReShare(self.sender,resharemsg.Account, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "", "Timeout", "", tip,tip, ars, wid)
						} else if w.msg_sendreshareres.Len() != w.ThresHold {
							AcceptReShare(self.sender,resharemsg.Account, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold, rh.Mode,"false", "", "Failure", "", "get other node reshare result fail","get other node reshare result fail",ars, wid)
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
								//fmt.Printf("%v ================RecvMsg,the terminal reshare res is success. key = %v ==================\n", common.CurrentTime(), rr.Nonce)
								AcceptReShare(self.sender,resharemsg.Account, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold, rh.Mode,"true", "true", "Success", lohash," "," ",ars, wid)
							} else {
								AcceptReShare(self.sender,resharemsg.Account, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "", "Failure", "",lohash,lohash,ars, wid)
							}
						}
						/////////////////////
					}
					///////////////////////reshare result end////////////////////////

					res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + common.Sep + rr.MsgType, Tip: tip, Err: fmt.Errorf("don't accept reshare.")}
					ch <- res2
					return false
				}
			//} 

			rch := make(chan interface{}, 1)
			//fmt.Printf("%v ================== (self *RecvMsg) Run() , start call reshare,key = %v,=====================\n", common.CurrentTime(), rr.Nonce)
			sigs := ""
			exsit,da := GetValueFromPubKeyData(rr.Nonce)
			if exsit {
			    ac,ok := da.(*AcceptReShareData)
			    if ok == true {
				if ac != nil {
				    sigs = ac.Sigs
				}
			    }
			}
			reshare(w.sid, resharemsg.Account,rh.GroupId,rh.PubKey,rh.Account,rh.Mode,sigs,rch)
			//fmt.Printf("%v ================== (self *RecvMsg) Run() , finish call reshare,key = %v ============================\n", common.CurrentTime(), rr.Nonce)
			chret, tip, cherr := GetChannelValue(ch_t, rch)
			//fmt.Printf("%v ================== (self *RecvMsg) Run() , finish and get reshare return value = %v,err = %v,key = %v ============================\n", common.CurrentTime(), chret, cherr, rr.Nonce)
			if chret != "" {
				res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + common.Sep + rr.MsgType + common.Sep + chret, Tip: "", Err: nil}
				ch <- res2
				return true
			}

			//////////////////////reshare result start/////////////////////////
			if tip == "get other node accept reshare result timeout" {
				ars := GetAllReplyFromGroup(w.id,rh.GroupId,Rpc_RESHARE,self.sender)
				AcceptReShare(self.sender,resharemsg.Account, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "", "Timeout", "", "get other node accept reshare result timeout", "get other node accept reshare result timeout", ars, wid)
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
				//fmt.Printf("%v ================RecvMsg.Run,send SendReShareRes msg to other nodes finish,key = %v =============\n", common.CurrentTime(), rr.Nonce)
				_, _, err := GetChannelValue(ch_t, w.bsendreshareres)
				//fmt.Printf("%v ================RecvMsg.Run,the SendReShareRes result from other nodes, err = %v,key = %v =============\n", common.CurrentTime(), err, rr.Nonce)
				ars := GetAllReplyFromGroup(w.id,rh.GroupId,Rpc_RESHARE,self.sender)
				if err != nil {
					tip = "get other node terminal accept reshare result timeout" ////bug
					AcceptReShare(self.sender,resharemsg.Account, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "", "Timeout", "", tip,tip, ars, wid)
				} else if w.msg_sendsignres.Len() != w.ThresHold {
					AcceptReShare(self.sender,resharemsg.Account, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "", "Failure", "", "get other node reshare result fail","get other node reshare result fail",ars, wid)
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
						//fmt.Printf("%v ================RecvMsg,the terminal reshare res is success. key = %v ==================\n", common.CurrentTime(), rr.Nonce)
						AcceptReShare(self.sender,resharemsg.Account, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"true", "true", "Success", lohash," "," ",ars, wid)
					} else {
						AcceptReShare(self.sender,resharemsg.Account, rh.GroupId,rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "", "Failure", "",lohash,lohash,ars, wid)
					}
				}
				/////////////////////
			}
			///////////////////////reshare result end////////////////////////

			if cherr != nil {
				res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + common.Sep + rr.MsgType, Tip: tip, Err: cherr}
				ch <- res2
				return false
			}

			res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + common.Sep + rr.MsgType, Tip: tip, Err: fmt.Errorf("sign fail.")}
			ch <- res2
			return true
		}

		//rpc_sign
		if rr.MsgType == "rpc_sign" {
			
			if !strings.EqualFold(cur_enode, self.sender) { //self send
			    //nonce check
			    exsit,_ := GetValueFromPubKeyData(rr.Nonce)
			    ///////
			    if exsit {
				    //fmt.Printf("%v ================RecvMsg.Run, sign nonce error, key = %v ==================\n", common.CurrentTime(), rr.Nonce)
				    //TODO must set acceptsign(.....)
				    res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:sign tx nonce error", Err: fmt.Errorf("sign tx nonce error")}
				    ch <- res2
				    return false
			    }
			}
			
			w := workers[workid]
			w.sid = rr.Nonce
			//msg = fusionaccount:pubkey:msghash:keytype:groupid:nonce:threshold:mode:key:timestamp
			sigmsg := SignSendMsgToDcrm{}
			err = json.Unmarshal([]byte(rr.Msg), &sigmsg)
			if err != nil {
			    res := RpcDcrmRes{Ret: "", Tip: "recover tx.data json string fail from raw data,maybe raw data error", Err: err}
			    ch <- res
			    return false
			}

			sig := TxDataSign{}
			err = json.Unmarshal([]byte(sigmsg.TxData), &sig)
			if err != nil {
			    res := RpcDcrmRes{Ret: "", Tip: "recover tx.data json string fail from raw data,maybe raw data error", Err: err}
			    ch <- res
			    return false
			}

			w.groupid = sig.GroupId 
			w.limitnum = sig.ThresHold
			gcnt, _ := GetGroup(w.groupid)
			w.NodeCnt = gcnt
			//fmt.Printf("%v ===================RecvMsg.Run, w.NodeCnt = %v, w.groupid = %v, wid = %v, key = %v ==============================\n", common.CurrentTime(), w.NodeCnt, w.groupid,wid, rr.Nonce)
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

			//fmt.Printf("%v====================RecvMsg.Run,w.NodeCnt = %v, w.ThresHold = %v, w.limitnum = %v, key = %v ================\n",common.CurrentTime(),w.NodeCnt,w.ThresHold,w.limitnum,rr.Nonce)

			if strings.EqualFold(cur_enode, self.sender) { //self send
				AcceptSign(self.sender,sigmsg.Account,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,sigmsg.Nonce,sig.ThresHold,sig.Mode,"false", "false", "Pending", "", "", "", nil,wid)
			} else {
				cur_nonce, _, _ := GetSignNonce(sigmsg.Account)
				cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
				//msg = fusionaccount:pubkey:msghash:keytype:groupid:nonce:threshold:mode:key:timestamp
				new_nonce_num, _ := new(big.Int).SetString(sigmsg.Nonce, 10)
				if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
					_, err = SetSignNonce(sigmsg.Account,sigmsg.Nonce)
					if err != nil {
						fmt.Printf("%v ================RecvMsg.Run,set sign nonce fail, key = %v ==================\n", common.CurrentTime(), rr.Nonce)
						//TODO must set acceptsign(.....)
						res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:set sign nonce fail in RecvMsg.Run", Err: fmt.Errorf("set sign nonce fail in recvmsg.run")}
						ch <- res2
						return false
					}
				}

				ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,self.sender)
				//msg = fusionaccount:pubkey:msghash:keytype:groupid:nonce:threshold:mode:key:timestamp
				ac := &AcceptSignData{Initiator:self.sender,Account: sigmsg.Account, GroupId: sig.GroupId, Nonce: sigmsg.Nonce, PubKey: sig.PubKey, MsgHash: sig.MsgHash, MsgContext: sig.MsgContext, Keytype: sig.Keytype, LimitNum: sig.ThresHold, Mode: sig.Mode, TimeStamp: sig.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", Rsv: "", Tip: "", Error: "", AllReply: ars, WorkId:wid}
				err := SaveAcceptSignData(ac)
				fmt.Printf("%v ===================finish call SaveAcceptSignData, err = %v,wid = %v,account = %v,group id = %v,nonce = %v,pubkey = %v,msghash = %v,keytype = %v,threshold = %v,mode = %v,key = %v =========================\n", common.CurrentTime(), err, wid, sigmsg.Account, sig.GroupId, sigmsg.Nonce, sig.PubKey, sig.MsgHash, sig.Keytype, sig.ThresHold, sig.Mode, rr.Nonce)
				if err != nil {
					res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:set AcceptSignData fail in RecvMsg.Run", Err: fmt.Errorf("set AcceptSignData fail in recvmsg.run")}
					ch <- res2
					return false
				}
				////
				dcrmpks, _ := hex.DecodeString(ac.PubKey)
				exsit,da := GetValueFromPubKeyData(string(dcrmpks[:]))
				if exsit {
				    _,ok := da.(*PubKeyData)
				    if ok == true {
					keys := (da.(*PubKeyData)).RefSignKeys
					if keys == "" {
					    keys = rr.Nonce
					} else {
					    keys = keys + ":" + rr.Nonce
					}

					pubs3 := &PubKeyData{Key:(da.(*PubKeyData)).Key,Account: (da.(*PubKeyData)).Account, Pub: (da.(*PubKeyData)).Pub, Save: (da.(*PubKeyData)).Save, Nonce: (da.(*PubKeyData)).Nonce, GroupId: (da.(*PubKeyData)).GroupId, LimitNum: (da.(*PubKeyData)).LimitNum, Mode: (da.(*PubKeyData)).Mode,KeyGenTime:(da.(*PubKeyData)).KeyGenTime,RefLockOutKeys:(da.(*PubKeyData)).RefLockOutKeys,RefSignKeys:keys}
					epubs, err := Encode2(pubs3)
					if err == nil {
					    ss3, err := Compress([]byte(epubs))
					    if err == nil {
						kd := KeyData{Key: dcrmpks[:], Data: ss3}
						PubKeyDataChan <- kd
						LdbPubKeyData.WriteMap(string(dcrmpks[:]), pubs3)
						//fmt.Printf("%v ==============================RecvMsg.Run,reset PubKeyData success, key = %v ============================================\n", common.CurrentTime(),rr.Nonce)
					    }
					}
				    }
				}
			}

			//msg = fusionaccount:pubkey:msghash:keytype:groupid:nonce:threshold:mode:key:timestamp
			////bug
			if sig.Mode == "0" { // self-group
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
						case account := <-wtmp2.acceptSignChan:
							common.Debug("(self *RecvMsg) Run(),", "account= ", account, "key = ", rr.Nonce)
							ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,self.sender)
							fmt.Printf("%v ================== (self *RecvMsg) Run() , get all AcceptSignRes ,result = %v,key = %v ============================\n", common.CurrentTime(), ars, rr.Nonce)
							
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
								tip = "don't accept sign"
								AcceptSign(self.sender,sigmsg.Account,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,sigmsg.Nonce,sig.ThresHold,sig.Mode,"false", "false", "Failure", "", "don't accept sign", "don't accept sign", ars,wid)
							} else {
								tip = ""
								AcceptSign(self.sender,sigmsg.Account,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,sigmsg.Nonce,sig.ThresHold,sig.Mode,"false", "false", "Pending", "", "", "", ars,wid)
							}

							///////
							timeout <- true
							return
						case <-agreeWaitTimeOut.C:
							fmt.Printf("%v ================== (self *RecvMsg) Run() , agree wait timeout. key = %v,=====================\n", common.CurrentTime(), rr.Nonce)
							ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,self.sender)
							//bug: if self not accept and timeout
							AcceptSign(self.sender,sigmsg.Account,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,sigmsg.Nonce,sig.ThresHold,sig.Mode,"false", "false", "Timeout", "", "get other node accept sign result timeout", "get other node accept sign result timeout", ars,wid)
							reply = false
							tip = "get other node accept sign result timeout"
							//

							timeout <- true
							return
						}
					}
				}(wid)

				if len(workers[wid].acceptWaitSignChan) == 0 {
					workers[wid].acceptWaitSignChan <- "go on"
				}

				<-timeout

				//fmt.Printf("%v ================== (self *RecvMsg) Run() , the terminal accept sign result = %v,key = %v,============================\n", common.CurrentTime(), reply, rr.Nonce)

				if !reply {
					//////////////////////sign result start/////////////////////////
					if tip == "get other node accept sign result timeout" {
						ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,self.sender)
						AcceptSign(self.sender,sigmsg.Account,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,sigmsg.Nonce,sig.ThresHold,sig.Mode,"false", "", "Timeout", "", "get other node accept sign result timeout", "get other node accept sign result timeout", ars,wid)
					} else {
						/////////////TODO tmp
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
						//fmt.Printf("%v ================RecvMsg.Run,send SendSignRes msg to other nodes finish,key = %v =============\n", common.CurrentTime(), rr.Nonce)
						_, _, err := GetChannelValue(ch_t, w.bsendsignres)
						//fmt.Printf("%v ================RecvMsg.Run,the SendSignRes result from other nodes, err = %v,key = %v =============\n", common.CurrentTime(), err, rr.Nonce)
						ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,self.sender)
						if err != nil {
							tip = "get other node terminal accept sign result timeout" ////bug
							AcceptSign(self.sender,sigmsg.Account,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,sigmsg.Nonce,sig.ThresHold,sig.Mode,"false", "", "Timeout", "", tip, tip, ars,wid)
						} else if w.msg_sendsignres.Len() != w.ThresHold {
							//fmt.Printf("%v ================RecvMsg,the result SendSignRes msg from other nodes fail,key = %v =======================\n", common.CurrentTime(), rr.Nonce)
							AcceptSign(self.sender,sigmsg.Account,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,sigmsg.Nonce,sig.ThresHold,sig.Mode,"false", "", "Failure", "", "get other node sign result fail", "get other node sign result fail", ars,wid)
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
								//fmt.Printf("%v ================RecvMsg,the terminal sign res is success. key = %v ==================\n", common.CurrentTime(), rr.Nonce)
								AcceptSign(self.sender,sigmsg.Account,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,sigmsg.Nonce,sig.ThresHold,sig.Mode,"true", "true", "Success", lohash, " ", " ", ars,wid)
							} else {
								//fmt.Printf("%v ================RecvMsg,the terminal sign res is fail. key = %v ==================\n", common.CurrentTime(), rr.Nonce)
								AcceptSign(self.sender,sigmsg.Account,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,sigmsg.Nonce,sig.ThresHold,sig.Mode,"false", "", "Failure", "", lohash,lohash, ars,wid)
							}
						}
						/////////////////////
					}
					///////////////////////sign result end////////////////////////

					res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + common.Sep + rr.MsgType, Tip: tip, Err: fmt.Errorf("don't accept sign.")}
					ch <- res2
					return false
				}
			} else {
				if len(workers[wid].acceptWaitSignChan) == 0 {
					workers[wid].acceptWaitSignChan <- "go on"
				}

				if !strings.EqualFold(cur_enode, self.sender) { //no self send
					ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,self.sender)
					AcceptSign(self.sender,sigmsg.Account,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,sigmsg.Nonce,sig.ThresHold,sig.Mode,"false", "true", "Pending", "", "","", ars,wid)
				}
			}

			rch := make(chan interface{}, 1)
			//msg = fusionaccount:pubkey:msghash:keytype:groupid:nonce:threshold:mode:key:timestamp
			//fmt.Printf("%v ================== (self *RecvMsg) Run() , start call sign,key = %v,=====================\n", common.CurrentTime(), rr.Nonce)
			sign(w.sid, sigmsg.Account,sig.PubKey,sig.MsgHash,sig.Keytype,sigmsg.Nonce,sig.Mode,rch)
			//fmt.Printf("%v ================== (self *RecvMsg) Run() , finish call sign,key = %v ============================\n", common.CurrentTime(), rr.Nonce)
			chret, tip, cherr := GetChannelValue(ch_t, rch)
			//fmt.Printf("%v ================== (self *RecvMsg) Run() , finish and get sign return value = %v,err = %v,key = %v ============================\n", common.CurrentTime(), chret, cherr, rr.Nonce)
			if chret != "" {
				res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + common.Sep + rr.MsgType + common.Sep + chret, Tip: "", Err: nil}
				ch <- res2
				return true
			}

			//////////////////////sign result start/////////////////////////
			ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,self.sender)
			if tip == "get other node accept sign result timeout" {
				AcceptSign(self.sender,sigmsg.Account,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,sigmsg.Nonce,sig.ThresHold,sig.Mode,"false", "", "Timeout", "", tip,cherr.Error(),ars,wid)
			} else {
				/////////////TODO tmp
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
				//fmt.Printf("%v ================RecvMsg.Run,send SendSignRes msg to other nodes finish,key = %v =============\n", common.CurrentTime(), rr.Nonce)
				_, _, err := GetChannelValue(ch_t, w.bsendsignres)
				//fmt.Printf("%v ================RecvMsg.Run,the SendSignRes result from other nodes finish,key = %v =============\n", common.CurrentTime(), rr.Nonce)
				if err != nil {
					tip = "get other node terminal accept sign result timeout" ////bug
					AcceptSign(self.sender,sigmsg.Account,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,sigmsg.Nonce,sig.ThresHold,sig.Mode,"false", "", "Timeout", "", tip, tip, ars, wid)
				} else if w.msg_sendsignres.Len() != w.ThresHold {
					//fmt.Printf("%v ================RecvMsg.Run,the SendSignRes result from other nodes fail,key = %v =============\n", common.CurrentTime(), rr.Nonce)
					AcceptSign(self.sender,sigmsg.Account,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,sigmsg.Nonce,sig.ThresHold,sig.Mode,"false", "", "Failure", "", "get other node sign result fail", "get other node sign result fail", ars, wid)
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
						//fmt.Printf("%v ================RecvMsg,the terminal sign res is success. key = %v ==================\n", common.CurrentTime(), rr.Nonce)
						AcceptSign(self.sender,sigmsg.Account,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,sigmsg.Nonce,sig.ThresHold,sig.Mode,"true", "true", "Success", lohash, " ", " ", ars, wid)
					} else {
						//fmt.Printf("%v ================RecvMsg,the terminal sign res is fail. key = %v ==================\n", common.CurrentTime(), rr.Nonce)
						AcceptSign(self.sender,sigmsg.Account,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,sigmsg.Nonce,sig.ThresHold,sig.Mode,"false", "", "Failure", "", lohash, lohash, ars, wid)
					}
				}
				/////////////////////
			}
			///////////////////////sign result end////////////////////////

			if cherr != nil {
				res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + common.Sep + rr.MsgType, Tip: tip, Err: cherr}
				ch <- res2
				return false
			}

			res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + common.Sep + rr.MsgType, Tip: tip, Err: fmt.Errorf("sign fail.")}
			ch <- res2
			return true
		}

	default:
		return false
	}
	/////////

	return true
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

	test := Keccak256Hash([]byte(strings.ToLower(msg))).Hex()
	//fmt.Printf("%v ===============DisMsg,get msg = %v,msg hash = %v,=================\n", common.CurrentTime(), msg, test)

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

	/////////////////
	if mm[1] == "GroupAccounts" {
		//msg:       key-enode:GroupAccounts:5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
		key := prexs[0]
		//fmt.Printf("%v ===============DisMsg,get group accounts data,msg = %v,msg hash = %v,key = %v=================\n", common.CurrentTime(), msg, test, key)
		nodecnt,_ := strconv.Atoi(mm[2])
		for j:= 1;j <= nodecnt; j++ {
		    acc := mm[2+2*j]
		    exsit,da := GetValueFromPubKeyData(strings.ToLower(acc))
		    if !exsit {
			kdtmp := KeyData{Key: []byte(strings.ToLower(acc)), Data: key}
			PubKeyDataChan <- kdtmp
			LdbPubKeyData.WriteMap(strings.ToLower(acc), []byte(key))
		    } else {
			//
			found := false
			keys := strings.Split(string(da.([]byte)),":")
			for _,v := range keys {
			    if strings.EqualFold(v,key) {
				found = true
				break
			    }
			}
			//
			if !found {
			    da2 := string(da.([]byte)) + ":" + key
			    kdtmp := KeyData{Key: []byte(strings.ToLower(acc)), Data: da2}
			    PubKeyDataChan <- kdtmp
			    LdbPubKeyData.WriteMap(strings.ToLower(acc), []byte(da2))
			}
		    }
		}

		mmtmp := mm[2:]
		ss := strings.Join(mmtmp, common.Sep)
		GAccs.WriteMap(strings.ToLower(key),[]byte(ss))
		exsit,da := GetValueFromPubKeyData(key)
		if exsit {
		    ac,ok := da.(*AcceptReqAddrData)
		    if ok == true {
			if ac != nil {
			    ac.Sigs = ss
			    go GAccs.DeleteMap(strings.ToLower(key))
			}
		    }
		}

		return
	}
	if mm[1] == "GroupAccounts_ReShare" {
		//msg:       key-enode:GroupAccounts:5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
		key := prexs[0]
		//fmt.Printf("%v ===============DisMsg,get group accounts data,msg = %v,msg hash = %v,key = %v=================\n", common.CurrentTime(), msg, test, key)
		/*nodecnt,_ := strconv.Atoi(mm[2])
		for j:= 1;j <= nodecnt; j++ {
		    acc := mm[2+2*j]
		    exsit,da := GetValueFromPubKeyData(strings.ToLower(acc))
		    if exsit == false {
			kdtmp := KeyData{Key: []byte(strings.ToLower(acc)), Data: key}
			PubKeyDataChan <- kdtmp
			LdbPubKeyData.WriteMap(strings.ToLower(acc), []byte(key))
		    } else {
			//
			found := false
			keys := strings.Split(string(da.([]byte)),":")
			for _,v := range keys {
			    if strings.EqualFold(v,key) {
				found = true
				break
			    }
			}
			//
			if !found {
			    da2 := string(da.([]byte)) + ":" + key
			    kdtmp := KeyData{Key: []byte(strings.ToLower(acc)), Data: da2}
			    PubKeyDataChan <- kdtmp
			    LdbPubKeyData.WriteMap(strings.ToLower(acc), []byte(da2))
			}
		    }
		}*/

		mmtmp := mm[2:]
		ss := strings.Join(mmtmp, common.Sep)
		GAccs.WriteMap(strings.ToLower(key),[]byte(ss))
		exsit,da := GetValueFromPubKeyData(key)
		if exsit {
		    ac,ok := da.(*AcceptReShareData)
		    if ok == true {
			if ac != nil {
			    ac.Sigs = ss
			    go GAccs.DeleteMap(strings.ToLower(key))
			}
		    }
		}

		return
	}
	/////////////////

	//msg:  hash-enode:C1:X1:X2
	w, err := FindWorker(prexs[0])
	if err != nil || w == nil {

	    mmtmp := mm[0:2]
	    ss := strings.Join(mmtmp, common.Sep)
	    fmt.Printf("%v ===============DisMsg,no find worker,so save the msg (c1 or accept res) to C1Data map. ss = %v, msg = %v,key = %v=================\n", common.CurrentTime(), strings.ToLower(ss),msg,prexs[0])
	    C1Data.WriteMap(strings.ToLower(ss),msg)

	    return
	}

	//fmt.Printf("%v ===============DisMsg,get worker, worker id = %v,msg = %v,msg hash = %v,key = %v=================\n", common.CurrentTime(), w.id,msg, test, prexs[0])

	msgCode := mm[1]
	switch msgCode {
	case "AcceptReqAddrRes":
		///bug
		if w.msg_acceptreqaddrres.Len() >= w.NodeCnt {
			//fmt.Printf("%v ===============DisMsg, w.msg_acceptreqaddrres.Len() = %v,w.NodeCnt = %v,msg = %v,msg hash = %v,key = %v=================\n", common.CurrentTime(), w.msg_acceptreqaddrres.Len(), w.NodeCnt, msg, test, prexs[0])
			return
		}

		///
		if Find(w.msg_acceptreqaddrres, msg) {
			//fmt.Printf("%v ===============DisMsg, msg has exist in w.msg_acceptreqaddrres, w.msg_acceptreqaddrres.Len() = %v,w.NodeCnt = %v,msg = %v,msg hash = %v,key = %v=================\n", common.CurrentTime(), w.msg_acceptreqaddrres.Len(), w.NodeCnt, msg, test, prexs[0])
			return
		}

		///bug
		mm2 := mm[0:3]
		var next *list.Element
		for e := w.msg_acceptreqaddrres.Front(); e != nil; e = next {
			next = e.Next()

			if e.Value == nil {
				continue
			}

			s := e.Value.(string)

			if s == "" {
				continue
			}

			tmp := strings.Split(s, common.Sep)
			tmp2 := tmp[0:3]
			//fmt.Printf("%v ===============DisMsg, msg = %v,s = %v,key = %v=================\n", common.CurrentTime(), msg, s,prexs[0])
			if testEq(mm2, tmp2) {
				fmt.Printf("%v ===============DisMsg, test eq return true,msg = %v,s = %v,key = %v=================\n", common.CurrentTime(), msg, s,prexs[0])
				return
			}
		}
		//////

		w.msg_acceptreqaddrres.PushBack(msg)
		if w.msg_acceptreqaddrres.Len() == w.NodeCnt {
			//fmt.Printf("%v ===============DisMsg, Get All AcceptReqAddrRes, w.msg_acceptreqaddrres.Len() = %v, w.NodeCnt = %v, msg = %v, msg hash = %v, key = %v=================\n", common.CurrentTime(), w.msg_acceptreqaddrres.Len(), w.NodeCnt, msg, test, prexs[0])
			w.bacceptreqaddrres <- true
			///////
			exsit,da := GetValueFromPubKeyData(prexs[0])
			if !exsit {
				fmt.Printf("%v ==================DisMsg,no exist reqaddr data, worker id = %v,key = %v =======================\n", common.CurrentTime(), w.id, prexs[0])
				return
			}

			ac,ok := da.(*AcceptReqAddrData)
			if ok == false {
			    return
			}

			if ac == nil {
				fmt.Printf("%v ==================DisMsg,ac is nil, worker id = %v,key = %v =======================\n", common.CurrentTime(), w.id, prexs[0])
				return
			}
			///////

			//fmt.Printf("%v ==================DisMsg,get wid = %v,key = %v =======================\n", common.CurrentTime(), ac.WorkId, prexs[0])
			workers[ac.WorkId].acceptReqAddrChan <- "go on"
		}
	case "AcceptLockOutRes":
		///bug
		if w.msg_acceptlockoutres.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_acceptlockoutres, msg) {
			return
		}

		///bug
		mm2 := mm[0:3]
		var next *list.Element
		for e := w.msg_acceptlockoutres.Front(); e != nil; e = next {
			next = e.Next()

			if e.Value == nil {
				continue
			}

			s := e.Value.(string)

			if s == "" {
				continue
			}

			tmp := strings.Split(s, common.Sep)
			tmp2 := tmp[0:3]
			//fmt.Printf("%v ===============DisMsg, msg = %v,s = %v,key = %v=================\n", common.CurrentTime(), msg, s,prexs[0])
			if testEq(mm2, tmp2) {
				fmt.Printf("%v ===============DisMsg, test eq return true,msg = %v,s = %v,key = %v=================\n", common.CurrentTime(), msg, s,prexs[0])
				return
			}
		}
		//////

		w.msg_acceptlockoutres.PushBack(msg)
		if w.msg_acceptlockoutres.Len() == w.ThresHold {
			w.bacceptlockoutres <- true
			/////
			exsit,da := GetValueFromPubKeyData(prexs[0])
			if !exsit {
				return
			}

			ac,ok := da.(*AcceptLockOutData)
			if ok == false {
			    return
			}

			if ac == nil {
				return
			}
			workers[ac.WorkId].acceptLockOutChan <- "go on"
			/////
		}
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
	case "AcceptSignRes":
		///bug
		if w.msg_acceptsignres.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_acceptsignres, msg) {
			return
		}

		///bug
		mm2 := mm[0:3]
		var next *list.Element
		for e := w.msg_acceptsignres.Front(); e != nil; e = next {
			next = e.Next()

			if e.Value == nil {
				continue
			}

			s := e.Value.(string)

			if s == "" {
				continue
			}

			tmp := strings.Split(s, common.Sep)
			tmp2 := tmp[0:3]
			//fmt.Printf("%v ===============DisMsg, msg = %v,s = %v,key = %v=================\n", common.CurrentTime(), msg, s,prexs[0])
			if testEq(mm2, tmp2) {
				fmt.Printf("%v ===============DisMsg, test eq return true,msg = %v,s = %v,key = %v=================\n", common.CurrentTime(), msg, s,prexs[0])
				return
			}
		}
		//////

		w.msg_acceptsignres.PushBack(msg)
		if w.msg_acceptsignres.Len() == w.ThresHold {
			w.bacceptsignres <- true
			/////
			exsit,da := GetValueFromPubKeyData(prexs[0])
			if !exsit {
				return
			}

			ac,ok := da.(*AcceptSignData)
			if ok == false {
			    return
			}

			if ac == nil {
				return
			}
			workers[ac.WorkId].acceptSignChan <- "go on"
			/////
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
	case "AcceptReShareRes":
		///bug
		if w.msg_acceptreshareres.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_acceptreshareres, msg) {
			return
		}

		///bug
		mm2 := mm[0:3]
		var next *list.Element
		for e := w.msg_acceptreshareres.Front(); e != nil; e = next {
			next = e.Next()

			if e.Value == nil {
				continue
			}

			s := e.Value.(string)

			if s == "" {
				continue
			}

			tmp := strings.Split(s, common.Sep)
			tmp2 := tmp[0:3]
			//fmt.Printf("%v ===============DisMsg, msg = %v,s = %v,key = %v=================\n", common.CurrentTime(), msg, s,prexs[0])
			if testEq(mm2, tmp2) {
				fmt.Printf("%v ===============DisMsg, test eq return true,msg = %v,s = %v,key = %v=================\n", common.CurrentTime(), msg, s,prexs[0])
				return
			}
		}
		//////

		w.msg_acceptreshareres.PushBack(msg)
		if w.msg_acceptreshareres.Len() == w.NodeCnt {
			w.bacceptreshareres <- true
			/////
			exsit,da := GetValueFromPubKeyData(prexs[0])
			if !exsit {
				return
			}

			ac,ok := da.(*AcceptReShareData)
			if ok == false {
			    return
			}

			if ac == nil {
				return
			}
			workers[ac.WorkId].acceptReShareChan <- "go on"
			/////
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
			common.Info("===================Get All D1 ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
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
			common.Info("===================Get All SHARE1 ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
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
			common.Info("===================Get All NTILDEH1H2 ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
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
			common.Info("===================Get All ZKUPROOF ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
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
			common.Info("===================Get All MTAZK1PROOF ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
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
			common.Info("===================Get All KC ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
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
			common.Info("===================Get All MKG ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
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
			common.Info("===================Get All MKW ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
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
			common.Info("===================Get All DELTA1 ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
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
			common.Info("===================Get All CommitBigVAB ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
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
			common.Info("===================Get All ZKABPROOF ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
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
			common.Info("===================Get All CommitBigUT ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
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
			common.Info("===================Get All CommitBigUTD11 ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
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
			common.Info("===================Get All S1 ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
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

