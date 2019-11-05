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
    "time"
    "container/list"
    "bytes"
    "compress/zlib"
    "io"
    "os"
    "github.com/fsn-dev/dcrm-sdk/crypto/sha3"
    "github.com/fsn-dev/dcrm-sdk/internal/common/hexutil"
    "runtime"
    "path/filepath"
    "sync"
    "os/user"
    "strings"
    "fmt"
    "strconv"
    "github.com/syndtr/goleveldb/leveldb"
    "encoding/json"
)

var (
    Sep = "dcrmparm"
    SepSave = "dcrmsepsave"
    SepSg = "dcrmmsg"
    SepDel = "dcrmsepdel"

    PaillierKeyLength = 2048
    sendtogroup_lilo_timeout = 80 
    sendtogroup_timeout = 80
    ch_t = 60

    //callback
    GetGroup func(string) (int,string)
    SendToGroupAllNodes func(string,string) string
    GetSelfEnode func() string
    BroadcastInGroupOthers func(string,string)
    SendToPeer func(string,string) error
    ParseNode func(string) string
)

func RegP2pGetGroupCallBack(f func(string)(int,string)) {
    GetGroup = f
}

func RegP2pSendToGroupAllNodesCallBack(f func(string,string)string) {
    SendToGroupAllNodes = f
}

func RegP2pGetSelfEnodeCallBack(f func()string) {
    GetSelfEnode = f
}

func RegP2pBroadcastInGroupOthersCallBack(f func(string,string)) {
    BroadcastInGroupOthers = f
}

func RegP2pSendMsgToPeerCallBack(f func(string,string)error) {
    SendToPeer = f
}

func RegP2pParseNodeCallBack(f func(string)string) {
    ParseNode = f
}

func PutGroup(groupId string) bool {
    if groupId == "" {
	return false
    }

    lock.Lock()
    dir := GetGroupDir()
    db, err := leveldb.OpenFile(dir, nil) 
    if err != nil {
	lock.Unlock()
	return false
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
	if strings.EqualFold(key,"GroupIds") {
	    data = value
	    break
	}
    }
    iter.Release()
    ///////
    if data == "" {
	db.Put([]byte("GroupIds"),[]byte(groupId),nil)
	db.Close()
	lock.Unlock()
	return true 
    }

    m := strings.Split(data,":")
    for _,v := range m {
	if strings.EqualFold(v,groupId) {
	    db.Close()
	    lock.Unlock()
	    return true 
	}
    }

    data += ":" + groupId
    db.Put([]byte("GroupIds"),[]byte(data),nil)
   
    db.Close()
    lock.Unlock()
    return true
}

func InitDev(groupId string) {
    cur_enode = GetSelfEnode()
    if !PutGroup(groupId) {
	return
    }

    fmt.Println("=========InitDev===========","groupId",groupId)
    peerscount, _ := GetGroup(groupId)
   NodeCnt = peerscount
   Enode_cnts = peerscount //bug
    GetEnodesInfo()
}

////////////////////////dcrm///////////////////////////////
var (
    //rpc-req //dcrm node
    RpcMaxWorker = 10000 
    RpcMaxQueue  = 10000
    RpcReqQueue chan RpcReq 
    workers []*RpcReqWorker
    //rpc-req
    cur_enode string
    Enode_cnts int
    NodeCnt = 3
    ThresHold = 3
    lock5 sync.Mutex
    lock sync.Mutex
)

type RpcDcrmRes struct {
    Ret string
    Err error
}

type RpcReq struct {
    rpcdata WorkReq
    ch chan interface{}
}

//rpc-req
type ReqDispatcher struct {
    // A pool of workers channels that are registered with the dispatcher
    WorkerPool chan chan RpcReq
}

type RpcReqWorker struct {
    RpcReqWorkerPool  chan chan RpcReq
    RpcReqChannel  chan RpcReq
    rpcquit        chan bool
    id int
    groupid string
    ch chan interface{}
    retres *list.List
    //
    msg_c1 *list.List
    splitmsg_c1 map[string]*list.List
    
    msg_kc *list.List
    splitmsg_kc map[string]*list.List
    
    msg_mkg *list.List
    splitmsg_mkg map[string]*list.List
    
    msg_mkw *list.List
    splitmsg_mkw map[string]*list.List
    
    msg_delta1 *list.List
    splitmsg_delta1 map[string]*list.List
    
    msg_d1_1 *list.List
    splitmsg_d1_1 map[string]*list.List
    
    msg_share1 *list.List
    splitmsg_share1 map[string]*list.List
    
    msg_zkfact *list.List
    splitmsg_zkfact map[string]*list.List
    
    msg_zku *list.List
    splitmsg_zku map[string]*list.List
    
    msg_mtazk1proof *list.List
    splitmsg_mtazk1proof map[string]*list.List
    
    msg_c11 *list.List
    splitmsg_c11 map[string]*list.List
    
    msg_d11_1 *list.List
    splitmsg_d11_1 map[string]*list.List
    
    msg_s1 *list.List
    splitmsg_s1 map[string]*list.List
    
    msg_ss1 *list.List
    splitmsg_ss1 map[string]*list.List

    pkx *list.List
    pky *list.List
    save *list.List
    
    bc1 chan bool
    bmkg chan bool
    bmkw chan bool
    bdelta1 chan bool
    bd1_1 chan bool
    bshare1 chan bool
    bzkfact chan bool
    bzku chan bool
    bmtazk1proof chan bool
    bkc chan bool
    bs1 chan bool
    bss1 chan bool
    bc11 chan bool
    bd11_1 chan bool

    sid string //save the txhash

    //ed
    bedc11 chan bool
    msg_edc11 *list.List
    bedzk chan bool
    msg_edzk *list.List
    bedd11 chan bool
    msg_edd11 *list.List
    bedshare1 chan bool
    msg_edshare1 *list.List
    bedcfsb chan bool
    msg_edcfsb *list.List
    edsave *list.List
    edpk *list.List
    
    bedc21 chan bool
    msg_edc21 *list.List
    bedzkr chan bool
    msg_edzkr *list.List
    bedd21 chan bool
    msg_edd21 *list.List
    bedc31 chan bool
    msg_edc31 *list.List
    bedd31 chan bool
    msg_edd31 *list.List
    beds chan bool
    msg_eds *list.List

}

//workers,RpcMaxWorker,RpcReqWorker,RpcReqQueue,RpcMaxQueue,ReqDispatcher
func InitChan() {
    workers = make([]*RpcReqWorker,RpcMaxWorker)
    RpcReqQueue = make(chan RpcReq,RpcMaxQueue)
    reqdispatcher := NewReqDispatcher(RpcMaxWorker)
    reqdispatcher.Run()
}

func NewReqDispatcher(maxWorkers int) *ReqDispatcher {
    pool := make(chan chan RpcReq, maxWorkers)
    return &ReqDispatcher{WorkerPool: pool}
}

func (d *ReqDispatcher) Run() {
// starting n number of workers
    for i := 0; i < RpcMaxWorker; i++ {
	worker := NewRpcReqWorker(d.WorkerPool)
	worker.id = i
	workers[i] = worker
	worker.Start()
    }

    go d.dispatch()
}

func (d *ReqDispatcher) dispatch() {
    for {
	select {
	    case req := <-RpcReqQueue:
	    // a job request has been received
	    go func(req RpcReq) {
		// try to obtain a worker job channel that is available.
		// this will block until a worker is idle
		reqChannel := <-d.WorkerPool

		// dispatch the job to the worker job channel
		reqChannel <- req
	    }(req)
	}
    }
}

func FindWorker(sid string) (*RpcReqWorker,error) {
    for i := 0; i < RpcMaxWorker; i++ {
	w := workers[i]

	if strings.EqualFold(w.sid,sid) {
	    return w,nil
	}
    }

    time.Sleep(time.Duration(5)*time.Second) //1000 == 1s //TODO
    
    for i := 0; i < RpcMaxWorker; i++ {
	w := workers[i]
	if strings.EqualFold(w.sid,sid) {
	    return w,nil
	}
    }

    return nil,fmt.Errorf("no find worker.")
}

func NewRpcReqWorker(workerPool chan chan RpcReq) *RpcReqWorker {
    return &RpcReqWorker{
    RpcReqWorkerPool: workerPool,
    RpcReqChannel: make(chan RpcReq),
    rpcquit:       make(chan bool),
    retres:list.New(),
    ch:		   make(chan interface{}),
    msg_share1:list.New(),
    splitmsg_share1:make(map[string]*list.List),
    msg_zkfact:list.New(),
    splitmsg_zkfact:make(map[string]*list.List),
    msg_zku:list.New(),
    splitmsg_zku:make(map[string]*list.List),
    msg_mtazk1proof:list.New(),
    splitmsg_mtazk1proof:make(map[string]*list.List),
    msg_c1:list.New(),
    splitmsg_c1:make(map[string]*list.List),
    msg_d1_1:list.New(),
    splitmsg_d1_1:make(map[string]*list.List),
    msg_c11:list.New(),
    splitmsg_c11:make(map[string]*list.List),
    msg_kc:list.New(),
    splitmsg_kc:make(map[string]*list.List),
    msg_mkg:list.New(),
    splitmsg_mkg:make(map[string]*list.List),
    msg_mkw:list.New(),
    splitmsg_mkw:make(map[string]*list.List),
    msg_delta1:list.New(),
    splitmsg_delta1:make(map[string]*list.List),
    msg_d11_1:list.New(),
    splitmsg_d11_1:make(map[string]*list.List),
    msg_s1:list.New(),
    splitmsg_s1:make(map[string]*list.List),
    msg_ss1:list.New(),
    splitmsg_ss1:make(map[string]*list.List),
    
    pkx:list.New(),
    pky:list.New(),
    save:list.New(),
    
    bc1:make(chan bool,1),
    bd1_1:make(chan bool,1),
    bc11:make(chan bool,1),
    bkc:make(chan bool,1),
    bs1:make(chan bool,1),
    bss1:make(chan bool,1),
    bmkg:make(chan bool,1),
    bmkw:make(chan bool,1),
    bshare1:make(chan bool,1),
    bzkfact:make(chan bool,1),
    bzku:make(chan bool,1),
    bmtazk1proof:make(chan bool,1),
    bdelta1:make(chan bool,1),
    bd11_1:make(chan bool,1),

    //ed
    bedc11:make(chan bool,1),
    msg_edc11:list.New(),
    bedzk:make(chan bool,1),
    msg_edzk:list.New(),
    bedd11:make(chan bool,1),
    msg_edd11:list.New(),
    bedshare1:make(chan bool,1),
    msg_edshare1:list.New(),
    bedcfsb:make(chan bool,1),
    msg_edcfsb:list.New(),
    edsave:list.New(),
    edpk:list.New(),
    bedc21:make(chan bool,1),
    msg_edc21:list.New(),
    bedzkr:make(chan bool,1),
    msg_edzkr:list.New(),
    bedd21:make(chan bool,1),
    msg_edd21:list.New(),
    bedc31:make(chan bool,1),
    msg_edc31:list.New(),
    bedd31:make(chan bool,1),
    msg_edd31:list.New(),
    beds:make(chan bool,1),
    msg_eds:list.New(),

    sid:"",
    }
}

func (w *RpcReqWorker) Clear() {

    w.sid = ""
    w.groupid = ""
    
    var next *list.Element
    
    for e := w.msg_c1.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_c1.Remove(e)
    }
    
    for e := w.msg_kc.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_kc.Remove(e)
    }

    for e := w.msg_mkg.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_mkg.Remove(e)
    }

    for e := w.msg_mkw.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_mkw.Remove(e)
    }

    for e := w.msg_delta1.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_delta1.Remove(e)
    }

    for e := w.msg_d1_1.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_d1_1.Remove(e)
    }

    for e := w.msg_share1.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_share1.Remove(e)
    }

    for e := w.msg_zkfact.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_zkfact.Remove(e)
    }

    for e := w.msg_zku.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_zku.Remove(e)
    }

    for e := w.msg_mtazk1proof.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_mtazk1proof.Remove(e)
    }

    for e := w.msg_c11.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_c11.Remove(e)
    }

    for e := w.msg_d11_1.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_d11_1.Remove(e)
    }

    for e := w.msg_s1.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_s1.Remove(e)
    }

    for e := w.msg_ss1.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_ss1.Remove(e)
    }

    for e := w.pkx.Front(); e != nil; e = next {
        next = e.Next()
        w.pkx.Remove(e)
    }

    for e := w.pky.Front(); e != nil; e = next {
        next = e.Next()
        w.pky.Remove(e)
    }

    for e := w.save.Front(); e != nil; e = next {
        next = e.Next()
        w.save.Remove(e)
    }

    for e := w.retres.Front(); e != nil; e = next {
        next = e.Next()
        w.retres.Remove(e)
    }

    if len(w.ch) == 1 {
	<-w.ch
    }
    if len(w.rpcquit) == 1 {
	<-w.rpcquit
    }
    if len(w.bshare1) == 1 {
	<-w.bshare1
    }
    if len(w.bzkfact) == 1 {
	<-w.bzkfact
    }
    if len(w.bzku) == 1 {
	<-w.bzku
    }
    if len(w.bmtazk1proof) == 1 {
	<-w.bmtazk1proof
    }
    if len(w.bc1) == 1 {
	<-w.bc1
    }
    if len(w.bd1_1) == 1 {
	<-w.bd1_1
    }
    if len(w.bc11) == 1 {
	<-w.bc11
    }
    if len(w.bkc) == 1 {
	<-w.bkc
    }
    if len(w.bs1) == 1 {
	<-w.bs1
    }
    if len(w.bss1) == 1 {
	<-w.bss1
    }
    if len(w.bmkg) == 1 {
	<-w.bmkg
    }
    if len(w.bmkw) == 1 {
	<-w.bmkw
    }
    if len(w.bdelta1) == 1 {
	<-w.bdelta1
    }
    if len(w.bd11_1) == 1 {
	<-w.bd11_1
    }

    //ed
    if len(w.bedc11) == 1 {
	<-w.bedc11
    }
    for e := w.msg_edc11.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edc11.Remove(e)
    }

    if len(w.bedzk) == 1 {
	<-w.bedzk
    }
    for e := w.msg_edzk.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edzk.Remove(e)
    }
    if len(w.bedd11) == 1 {
	<-w.bedd11
    }
    for e := w.msg_edd11.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edd11.Remove(e)
    }
    if len(w.bedshare1) == 1 {
	<-w.bedshare1
    }
    for e := w.msg_edshare1.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edshare1.Remove(e)
    }
    if len(w.bedcfsb) == 1 {
	<-w.bedcfsb
    }
    for e := w.msg_edcfsb.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edcfsb.Remove(e)
    }
    for e := w.edsave.Front(); e != nil; e = next {
        next = e.Next()
        w.edsave.Remove(e)
    }
    for e := w.edpk.Front(); e != nil; e = next {
        next = e.Next()
        w.edpk.Remove(e)
    }
    
    if len(w.bedc21) == 1 {
	<-w.bedc21
    }
    for e := w.msg_edc21.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edc21.Remove(e)
    }
    if len(w.bedzkr) == 1 {
	<-w.bedzkr
    }
    for e := w.msg_edzkr.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edzkr.Remove(e)
    }
    if len(w.bedd21) == 1 {
	<-w.bedd21
    }
    for e := w.msg_edd21.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edd21.Remove(e)
    }
    if len(w.bedc31) == 1 {
	<-w.bedc31
    }
    for e := w.msg_edc31.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edc31.Remove(e)
    }
    if len(w.bedd31) == 1 {
	<-w.bedd31
    }
    for e := w.msg_edd31.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edd31.Remove(e)
    }
    if len(w.beds) == 1 {
	<-w.beds
    }
    for e := w.msg_eds.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_eds.Remove(e)
    }

    //TODO
    w.splitmsg_c1 = make(map[string]*list.List)
    w.splitmsg_kc = make(map[string]*list.List)
    w.splitmsg_mkg = make(map[string]*list.List)
    w.splitmsg_mkw = make(map[string]*list.List)
    w.splitmsg_delta1 = make(map[string]*list.List)
    w.splitmsg_d1_1 = make(map[string]*list.List)
    w.splitmsg_share1 = make(map[string]*list.List)
    w.splitmsg_zkfact = make(map[string]*list.List)
    w.splitmsg_zku = make(map[string]*list.List)
    w.splitmsg_mtazk1proof = make(map[string]*list.List)
    w.splitmsg_c11 = make(map[string]*list.List)
    w.splitmsg_d11_1 = make(map[string]*list.List)
    w.splitmsg_s1 = make(map[string]*list.List)
    w.splitmsg_ss1 = make(map[string]*list.List)
}

func (w *RpcReqWorker) Start() {
    go func() {

	for {
	    // register the current worker into the worker queue.
	    w.RpcReqWorkerPool <- w.RpcReqChannel
	    select {
		    case req := <-w.RpcReqChannel:
			    req.rpcdata.Run(w.id,req.ch)
			    w.Clear()

		    case <-w.rpcquit:
			// we have received a signal to stop
			    return
		}
	}
    }()
}

func (w *RpcReqWorker) Stop() {
    go func() {
	w.rpcquit <- true
    }()
}
//rpc-req

type WorkReq interface {
    Run(workid int,ch chan interface{}) bool
}

//RecvMsg
type RecvMsg struct {
    msg string
    groupid string
}

func Dcrmcall(msg interface{},enode string) <-chan string {
    ch := make(chan string, 1)
    GroupId := GetGroupIdByEnode(enode)
    fmt.Println("=========Dcrmcall===========","GroupId",GroupId,"enode",enode)
    //if !strings.EqualFold(GroupId,enode) {
    if strings.EqualFold(GroupId,"") {
	ret := ("fail"+Sep+"xxx"+Sep+"error group id")
	ch <- ret 
	return ch
    }
    
    s := msg.(string)
    v := RecvMsg{msg:s,groupid:GroupId}
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:&v,ch:rch}
    RpcReqQueue <- req
    chret,cherr := GetChannelValue(sendtogroup_timeout,rch)
    if cherr != nil {
	//fail:chret:error
	ret := ("fail"+Sep+chret+Sep+cherr.Error())
	ch <- ret 
	return ch
    }

    //success:chret
    ret := ("success"+Sep+chret)
    ch <- ret 
    return ch
}

func Dcrmcallret(msg interface{},enode string) {
    res := msg.(string)
    if res == "" {
	return
    }
   
    fmt.Println("=========Dcrmcallret,node count=%v==============",NodeCnt)

    ss := strings.Split(res,Sep)
    if len(ss) != 4 {
	return
    }

    status := ss[0]
    //msgtype := ss[2]
    ret := ss[3]
    workid,err := strconv.Atoi(ss[1])
    if err != nil || workid < 0 {
	return
    }

    //success:workid:msgtype:ret
    if status == "success" {
	w := workers[workid]
	res2 := RpcDcrmRes{Ret:ss[3],Err:nil}
	w.retres.PushBack(&res2)

	if ss[2] == "rpc_sign" {
	    if w.retres.Len() == NodeCnt {
		ret := GetGroupRes(workid)
		w.ch <- ret
	    }
	}
	    
	if ss[2] == "rpc_req_dcrmaddr" {
	    if w.retres.Len() == NodeCnt {
		ret := GetGroupRes(workid)
		w.ch <- ret
	    }
	}

	return
    }
    
    //fail:workid:msgtype:error
    if status == "fail" {
	w := workers[workid]
	var ret2 Err
	ret2.Info = ret
	res2 := RpcDcrmRes{Ret:"",Err:ret2}
	w.retres.PushBack(&res2)

	if ss[2] == "rpc_sign" {
	    if w.retres.Len() == NodeCnt {
		ret := GetGroupRes(workid)
		w.ch <- ret
	    }
	}

	if ss[2] == "rpc_req_dcrmaddr" {
	    if w.retres.Len() == NodeCnt {
		ret := GetGroupRes(workid)
		w.ch <- ret
	    }
	}
	
	return
    }
}

func GetGroupRes(wid int) RpcDcrmRes {
    if wid < 0 {
	res2 := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetWorkerIdError)}
	return res2
    }

    var l *list.List
    w := workers[wid]
    l = w.retres

    if l == nil {
	res2 := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetNoResFromGroupMem)}
	return res2
    }

    var err error
    iter := l.Front()
    for iter != nil {
	ll := iter.Value.(*RpcDcrmRes)
	err = ll.Err
	if err == nil {
	    return (*ll)
	}
	iter = iter.Next()
    }

    iter = l.Front()
    for iter != nil {
	ll := iter.Value.(*RpcDcrmRes)
	err = ll.Err
	res2 := RpcDcrmRes{Ret:"",Err:err}
	return res2
	
	iter = iter.Next()
    }
    
    res2 := RpcDcrmRes{Ret:"",Err:nil}
    return res2
}

//=========================================

func Call(msg interface{},enode string) {
    s := msg.(string)
    SetUpMsgList(s)
}

func SetUpMsgList(msg string) {

    v := RecvMsg{msg:msg}
    //rpc-req
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:&v,ch:rch}
    RpcReqQueue <- req
}

func (self *RecvMsg) Run(workid int,ch chan interface{}) bool {
    if workid < 0 { //TODO
	res2 := RpcDcrmRes{Ret:"",Err:fmt.Errorf("no find worker.")}
	ch <- res2
	return false
    }

    /////////
    res := self.msg
    if res == "" { //TODO
	return false 
    }

    mm := strings.Split(res,Sep)
    if len(mm) >= 2 {
	//msg:  hash-enode:C1:X1:X2
	DisMsg(res)
	return true 
    }
    
    res,err := UnCompress(res)
    if err != nil {
	return false
    }
    r,err := Decode2(res)
    if err != nil {
	return false
    }

    switch r.(type) {
    case *SendMsg:
	rr := r.(*SendMsg)

	if rr.MsgType == "ec2_data" {
	    mm := strings.Split(rr.Msg,Sep)
	    if len(mm) >= 2 {
		//msg:  hash-enode:C1:X1:X2
		DisMsg(rr.Msg)
		return true 
	    }
	    return true
	}

	//rpc_sign
	if rr.MsgType == "rpc_sign" {
	    w := workers[workid]
	    w.sid = rr.Nonce
	    w.groupid = self.groupid
	    //msg = pubkey:keytype:message 
	    msg := rr.Msg
	    msgs := strings.Split(msg,":")

	    rch := make(chan interface{},1)
	    validate_lockout(w.sid,msgs[0],msgs[1],msgs[2],rch)
	    chret,cherr := GetChannelValue(ch_t,rch)
	    if chret != "" {
		res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType+Sep+chret,Err:nil}
		ch <- res2
		return true
	    }

	    if cherr != nil {
		var ret2 Err
		ret2.Info = cherr.Error() 
		res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType,Err:ret2}
		ch <- res2
		return false
	    }
	    
	    res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType,Err:fmt.Errorf("send tx to net fail.")}
	    ch <- res2
	    return true
	}
	//rpc_req_dcrmaddr
	if rr.MsgType == "rpc_req_dcrmaddr" {
	    //msg = keytype 
	    rch := make(chan interface{},1)
	    w := workers[workid]
	    w.sid = rr.Nonce
	    w.groupid = self.groupid

	    dcrm_liloreqAddress(w.sid,rr.Msg,rch)
	    chret,cherr := GetChannelValue(ch_t,rch)
	    if cherr != nil {
		var ret2 Err
		ret2.Info = cherr.Error()
		res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType,Err:ret2}
		ch <- res2
		return false
	    }
	    
	    res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType+Sep+chret,Err:nil}
	    ch <- res2
	    return true
	}

    default:
	return false
    }
    /////////

    return true 
}
type SendMsg struct {
    MsgType string
    Nonce string 
    WorkId int
    Msg string
}
func Encode2(obj interface{}) (string,error) {
    switch obj.(type) {
    case *SendMsg:
	ch := obj.(*SendMsg)
	ret,err := json.Marshal(ch)
	if err != nil {
	    return "",err
	}
	return string(ret),nil
    default:
	return "",fmt.Errorf("encode obj fail.")
    }
}

func Decode2(s string) (interface{},error) {
    var m SendMsg
    err := json.Unmarshal([]byte(s), &m)
    if err != nil {
	return nil,err
    }

    return &m,nil
} 
///////

////compress
func Compress(c []byte) (string,error) {
    if c == nil {
	return "",fmt.Errorf("compress fail.")
    }

    var in bytes.Buffer
    w,err := zlib.NewWriterLevel(&in,zlib.BestCompression-1)
    if err != nil {
	return "",err
    }

    w.Write(c)
    w.Close()

    s := in.String()
    return s,nil
}

////uncompress
func UnCompress(s string) (string,error) {

    if s == "" {
	return "",fmt.Errorf("param error.")
    }

    var data bytes.Buffer
    data.Write([]byte(s))

    r,err := zlib.NewReader(&data)
    if err != nil {
	return "",err
    }

    var out bytes.Buffer
    io.Copy(&out, r)
    return out.String(),nil
}
////

type DcrmHash [32]byte
func (h DcrmHash) Hex() string { return hexutil.Encode(h[:]) }

// Keccak256Hash calculates and returns the Keccak256 hash of the input data,
// converting it to an internal Hash data structure.
func Keccak256Hash(data ...[]byte) (h DcrmHash) {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	d.Sum(h[:0])
	return h
}

type ReqAddrSendMsgToDcrm struct {
    KeyType string
}

func (self *ReqAddrSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetWorkerIdError)}
	ch <- res
	return false
    }

    GetEnodesInfo()
    timestamp := time.Now().Unix()
    tt := strconv.Itoa(int(timestamp))
    nonce := Keccak256Hash([]byte(self.KeyType + ":" + tt + ":" + strconv.Itoa(workid))).Hex()
    
    sm := &SendMsg{MsgType:"rpc_req_dcrmaddr",Nonce:nonce,WorkId:workid,Msg:self.KeyType}
    res,err := Encode2(sm)
    if err != nil {
	res := RpcDcrmRes{Ret:"",Err:err}
	ch <- res
	return false
    }

    res,err = Compress([]byte(res))
    if err != nil {
	res := RpcDcrmRes{Ret:"",Err:err}
	ch <- res
	return false
    }

    GroupId := GetGroupIdByEnode(cur_enode)
    fmt.Println("=========ReqAddrSendMsgToMsg.Run===========","GroupId",GroupId,"cur_enode",cur_enode)
    //if !strings.EqualFold(GroupId,cur_enode) {
    if strings.EqualFold(GroupId,"") {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get group id fail.")}
	ch <- res
	return false
    }

    s := SendToGroupAllNodes(GroupId,res)
    
    if strings.EqualFold(s,"send fail.") {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrSendDataToGroupFail)}
	ch <- res
	return false
    }

    fmt.Println("=========ReqAddrSendMsgToMsg.Run,waiting for result===========","GroupId",GroupId,"cur_enode",cur_enode)
    w := workers[workid]
    chret,cherr := GetChannelValue(sendtogroup_timeout,w.ch)
    if cherr != nil {
	res2 := RpcDcrmRes{Ret:chret,Err:cherr}
	ch <- res2
	return false
    }
    res2 := RpcDcrmRes{Ret:chret,Err:cherr}
    ch <- res2

    return true
}

type SignSendMsgToDcrm struct {
    PubKey string
    KeyType string
    Message string
}

func (self *SignSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetWorkerIdError)}
	ch <- res
	return false
    }

    /////check message
    message := self.Message
    txhashs := []rune(message)
    if string(txhashs[0:2]) != "0x" {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("message must be 16-in-32-byte character sprang at the beginning of 0x,for example: 0x19b6236d2e7eb3e925d0c6e8850502c1f04822eb9aa67cb92e5004f7017e5e41")}
	ch <- res
	return false
    }
    message = string(txhashs[2:])
    if len(message) != 64 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("message must be 16-in-32-byte character sprang at the beginning of 0x,for example: 0x19b6236d2e7eb3e925d0c6e8850502c1f04822eb9aa67cb92e5004f7017e5e41")}
	ch <- res
	return false
    }
    //////

    GetEnodesInfo()
    msg := self.PubKey + ":" + self.KeyType + ":" + self.Message
    timestamp := time.Now().Unix()
    tt := strconv.Itoa(int(timestamp))
    nonce := Keccak256Hash([]byte(msg + ":" + tt + ":" + strconv.Itoa(workid))).Hex()
    
    sm := &SendMsg{MsgType:"rpc_sign",Nonce:nonce,WorkId:workid,Msg:msg}
    res,err := Encode2(sm)
    if err != nil {
	res := RpcDcrmRes{Ret:"",Err:err}
	ch <- res
	return false
    }

    res,err = Compress([]byte(res))
    if err != nil {
	res := RpcDcrmRes{Ret:"",Err:err}
	ch <- res
	return false
    }

    GroupId := GetGroupIdByEnode(cur_enode)
    fmt.Println("=========SignSendMsgToDcrm.Run===========","GroupId",GroupId,"cur_enode",cur_enode)
    if strings.EqualFold(GroupId,"") {
    //if !strings.EqualFold(GroupId,cur_enode) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get group id fail.")}
	ch <- res
	return false
    }
    s := SendToGroupAllNodes(GroupId,res)
    if strings.EqualFold(s,"send fail.") {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrSendDataToGroupFail)}
	ch <- res
	return false
    }

    fmt.Println("=========SignSendMsgToDcrm.Run,waiting for result.===========","GroupId",GroupId,"cur_enode",cur_enode)
    w := workers[workid]
    chret,cherr := GetChannelValue(sendtogroup_lilo_timeout,w.ch)
    if cherr != nil {
	res2 := RpcDcrmRes{Ret:chret,Err:cherr}
	ch <- res2
	return false
    }
    res2 := RpcDcrmRes{Ret:chret,Err:cherr}
    ch <- res2

    return true
}

func IsInGroup(enode string,groupId string) bool {
    if groupId == "" || enode == "" {
	return false
    }

    cnt,enodes := GetGroup(groupId)
    if cnt <= 0 || enodes == "" {
	return false
    }

    nodes := strings.Split(enodes,SepSg)
    for _,node := range nodes {
	node2 := ParseNode(node)
	if strings.EqualFold(node2,enode) {
	    return true
	}
    }

    return false
}

func GetGroupIdByEnode(enode string) string {
    if enode == "" {
	return ""
    }

    lock.Lock()
    dir := GetGroupDir()
    db, err := leveldb.OpenFile(dir, nil) 
    if err != nil { 
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
	if strings.EqualFold(key,"GroupIds") {
	    data = value
	    break
	}
    }
    iter.Release()
    ///////
    if data == "" {
	db.Close()
	lock.Unlock()
	return "" 
    }

    m := strings.Split(data,":")
    for _,v := range m {
	if IsInGroup(enode,v) {
	    db.Close()
	    lock.Unlock()
	    return v 
	}
    }

    db.Close()
    lock.Unlock()
    return ""
}

func GetEnodesInfo() {
    GroupId := GetGroupIdByEnode(cur_enode)
    if GroupId == "" {
	return
    }
    Enode_cnts,_ = GetGroup(GroupId)
    NodeCnt = Enode_cnts
    cur_enode = GetSelfEnode()
}

func SendReqToGroup(msg string,rpctype string) (string,error) {
    var req RpcReq
    switch rpctype {
	case "rpc_req_dcrmaddr":
	    v := ReqAddrSendMsgToDcrm{KeyType:msg}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	case "rpc_sign":
	    m := strings.Split(msg,":")
	    v := SignSendMsgToDcrm{PubKey:m[0],KeyType:m[1],Message:m[2]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	default:
	    return "",nil
    }

    var t int
    if rpctype == "rpc_sign" {
	t = sendtogroup_lilo_timeout 
    } else {
	t = sendtogroup_timeout
    }

    RpcReqQueue <- req
    chret,cherr := GetChannelValue(t,req.ch)
    if cherr != nil {
	return chret,cherr
    }

    return chret,nil
}

func GetChannelValue(t int,obj interface{}) (string,error) {
    timeout := make(chan bool, 1)
    go func(timeout chan bool) {
	 time.Sleep(time.Duration(t)*time.Second) //1000 == 1s
	 timeout <- true
     }(timeout)

     switch obj.(type) {
	 case chan interface{} :
	     ch := obj.(chan interface{})
	     select {
		 case v := <- ch :
		     ret,ok := v.(RpcDcrmRes)
		     if ok == true {
			 return ret.Ret,ret.Err
		     }
		 case <- timeout :
		     return "",fmt.Errorf("get data from node fail.")
	     }
	 case chan string:
	     ch := obj.(chan string)
	     select {
		 case v := <- ch :
			    return v,nil 
		 case <- timeout :
		     return "",fmt.Errorf("get data from node fail.")
	     }
	 case chan int64:
	     ch := obj.(chan int64)
	     select {
		 case v := <- ch :
		    return strconv.Itoa(int(v)),nil 
		 case <- timeout :
		     return "",fmt.Errorf("get data from node fail.")
	     }
	 case chan int:
	     ch := obj.(chan int)
	     select {
		 case v := <- ch :
		    return strconv.Itoa(v),nil 
		 case <- timeout :
		     return "",fmt.Errorf("get data from node fail.")
	     }
	 case chan bool:
	     ch := obj.(chan bool)
	     select {
		 case v := <- ch :
		    if !v {
			return "false",nil
		    } else {
			return "true",nil
		    }
		 case <- timeout :
		     return "",fmt.Errorf("get data from node fail.")
	     }
	 default:
	    return "",fmt.Errorf("unknown ch type.") 
     }

     return "",fmt.Errorf("get value fail.")
 }

//error type 1
type Err struct {
	Info  string
}

func (e Err) Error() string {
	return e.Info
}

//msg:  hash-enode:C1:X1:X2
func DisMsg(msg string) {

    if msg == "" {
	return
    }

    //orderbook matchres
    mm := strings.Split(msg, Sep)
    if len(mm) < 3 {
	return
    }
    
    mms := mm[0]
    prexs := strings.Split(mms,"-")
    if len(prexs) < 2 {
	return
    }

	//msg:  hash-enode:C1:X1:X2
	w,err := FindWorker(prexs[0])
	if err != nil || w == nil {
	    return
	}

	msgCode := mm[1]
	switch msgCode {
	case "C1":
	    ///bug
	    if w.msg_c1.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_c1.PushBack(msg)
	    if w.msg_c1.Len() == (NodeCnt-1) {
		fmt.Println("=========Get All C1===========","GroupId",w.groupid)
		w.bc1 <- true
	    }
	case "D1":
	    ///bug
	    if w.msg_d1_1.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_d1_1.PushBack(msg)
	    if w.msg_d1_1.Len() == (NodeCnt-1) {
		fmt.Println("=========Get All D1===========","GroupId",w.groupid)
		w.bd1_1 <- true
	    }
	case "SHARE1":
	    ///bug
	    if w.msg_share1.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_share1.PushBack(msg)
	    if w.msg_share1.Len() == (NodeCnt-1) {
		fmt.Println("=========Get All SHARE1===========","GroupId",w.groupid)
		w.bshare1 <- true
	    }
	case "ZKFACTPROOF":
	    ///bug
	    if w.msg_zkfact.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_zkfact.PushBack(msg)
	    if w.msg_zkfact.Len() == (NodeCnt-1) {
		fmt.Println("=========Get All ZKFACTPROOF===========","GroupId",w.groupid)
		w.bzkfact <- true
	    }
	case "ZKUPROOF":
	    ///bug
	    if w.msg_zku.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_zku.PushBack(msg)
	    if w.msg_zku.Len() == (NodeCnt-1) {
		fmt.Println("=========Get All ZKUPROOF===========","GroupId",w.groupid)
		w.bzku <- true
	    }
	case "MTAZK1PROOF":
	    ///bug
	    if w.msg_mtazk1proof.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    w.msg_mtazk1proof.PushBack(msg)
	    if w.msg_mtazk1proof.Len() == (ThresHold-1) {
		fmt.Println("=========Get All MTAZK1PROOF===========","GroupId",w.groupid)
		w.bmtazk1proof <- true
	    }
	    //sign
       case "C11":
	    ///bug
	    if w.msg_c11.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    w.msg_c11.PushBack(msg)
	    if w.msg_c11.Len() == (ThresHold-1) {
		fmt.Println("=========Get All C11===========","GroupId",w.groupid)
		w.bc11 <- true
	    }
       case "KC":
	    ///bug
	    if w.msg_kc.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    w.msg_kc.PushBack(msg)
	    if w.msg_kc.Len() == (ThresHold-1) {
		fmt.Println("=========Get All KC===========","GroupId",w.groupid)
		w.bkc <- true
	    }
       case "MKG":
	    ///bug
	    if w.msg_mkg.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    w.msg_mkg.PushBack(msg)
	    if w.msg_mkg.Len() == (ThresHold-1) {
		fmt.Println("=========Get All MKG===========","GroupId",w.groupid)
		w.bmkg <- true
	    }
       case "MKW":
	    ///bug
	    if w.msg_mkw.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    w.msg_mkw.PushBack(msg)
	    if w.msg_mkw.Len() == (ThresHold-1) {
		fmt.Println("=========Get All MKW===========","GroupId",w.groupid)
		w.bmkw <- true
	    }
       case "DELTA1":
	    ///bug
	    if w.msg_delta1.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    w.msg_delta1.PushBack(msg)
	    if w.msg_delta1.Len() == (ThresHold-1) {
		fmt.Println("=========Get All DELTA1===========","GroupId",w.groupid)
		w.bdelta1 <- true
	    }
	case "D11":
	    ///bug
	    if w.msg_d11_1.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    w.msg_d11_1.PushBack(msg)
	    if w.msg_d11_1.Len() == (ThresHold-1) {
		fmt.Println("=========Get All D11===========","GroupId",w.groupid)
		w.bd11_1 <- true
	    }
	case "S1":
	    ///bug
	    if w.msg_s1.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    w.msg_s1.PushBack(msg)
	    if w.msg_s1.Len() == (ThresHold-1) {
		fmt.Println("=========Get All S1===========","GroupId",w.groupid)
		w.bs1 <- true
	    }
	case "SS1":
	    ///bug
	    if w.msg_ss1.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    w.msg_ss1.PushBack(msg)
	    if w.msg_ss1.Len() == (ThresHold-1) {
		fmt.Println("=========Get All SS1===========","GroupId",w.groupid)
		w.bss1 <- true
	    }

	default:
	    fmt.Println("unkown msg code")
	}

	return
}

func GetGroupDir() string { //TODO
    dir := DefaultDataDir()
    dir += "/dcrmdata/dcrmdb" + cur_enode + "group"
    return dir
}

func GetDbDir() string {
    dir := DefaultDataDir()
    dir += "/dcrmdata/dcrmdb" + cur_enode
    return dir
}
func homeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	if usr, err := user.Current(); err == nil {
		return usr.HomeDir
	}
	return ""
}
func DefaultDataDir() string {
	home := homeDir()
	if home != "" {
		if runtime.GOOS == "darwin" {
			return filepath.Join(home, "Library", "Fusion")
		} else if runtime.GOOS == "windows" {
			return filepath.Join(home, "AppData", "Roaming", "Fusion")
		} else {
			return filepath.Join(home, ".fusion")
		}
	}
	// As we cannot guess a stable location, return empty and handle later
	return ""
}

