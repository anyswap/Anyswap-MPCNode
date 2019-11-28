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
    "github.com/fsn-dev/dcrm5-libcoins/crypto/sha3"
    "github.com/fsn-dev/dcrm5-libcoins/internal/common/hexutil"
    "runtime"
    "path/filepath"
    "sync"
    "os/user"
    "strings"
    "fmt"
    "strconv"
    "github.com/syndtr/goleveldb/leveldb"
    "encoding/json"
    "github.com/astaxie/beego/logs"
    "encoding/gob"
)

var (
    Sep = "dcrmparm"
    SepSave = "dcrmsepsave"
    SepSg = "dcrmmsg"
    SepDel = "dcrmsepdel"

    PaillierKeyLength = 2048
    sendtogroup_lilo_timeout = 100 
    sendtogroup_timeout = 100
    ch_t = 10
    lock5 sync.Mutex
    lock sync.Mutex

    //callback
    GetGroup func(string) (int,string)
    SendToGroupAllNodes func(string,string) string
    GetSelfEnode func() string
    BroadcastInGroupOthers func(string,string)
    SendToPeer func(string,string) error
    ParseNode func(string) string
    GetEosAccount func() (string,string,string)

    acceptLockOutChan chan string = make(chan string, 10)
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

func RegDcrmGetEosAccountCallBack(f func() (string,string,string)) {
    GetEosAccount = f
}

func InitDev(groupId string) {
    cur_enode = GetSelfEnode()
    fmt.Println("=========InitDev===========","groupId",groupId)
    peerscount, _ := GetGroup(groupId)
   NodeCnt = peerscount
   Enode_cnts = peerscount //bug
    GetEnodesInfo(groupId)
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
)

type RpcDcrmRes struct {
    Ret string
    Tip string
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
    limitnum string
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
    w.limitnum = ""
    
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

func (w *RpcReqWorker) Clear2() {
    fmt.Println("===========RpcReqWorker.Clear2,w.id = %s ===================",w.id)
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
}

func Dcrmcall(msg interface{},enode string) <-chan string {
    ch := make(chan string, 1)
    s := msg.(string)
    fmt.Println("=============Dcrmcall, receiv = %s,len(receiv) = %v ==============",s,len(s))
    v := RecvMsg{msg:s}
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:&v,ch:rch}
    RpcReqQueue <- req
    chret,tip,cherr := GetChannelValue(sendtogroup_timeout,rch)
    if cherr != nil {
	//fail:chret:tip:error
	ret := ("fail"+Sep+chret+Sep+tip+Sep+cherr.Error())
	ch <- ret 
	return ch
    }

    //success:chret
    ret := ("success"+Sep+chret)
    ch <- ret 
    return ch
}

func Dcrmcallret(msg interface{},enode string) {

    //msg = success:workid:msgtype:ret  or fail:workid:msgtype:tip:error
    res := msg.(string)
    if res == "" {
	return
    }
   
    ss := strings.Split(res,Sep)
    if len(ss) < 4 {
	return
    }

    status := ss[0]
    if strings.EqualFold(status, "fail") {
	if len(ss) < 5 {
	    return
	}
    }

    //msgtype := ss[2]
    fmt.Println("=========Dcrmcallret, ret = %s,len(ret) = %v ==============",ss[3],len(ss[3]))
    workid,err := strconv.Atoi(ss[1])
    if err != nil || workid < 0 || workid >= RpcMaxWorker {
	return
    }

    //success:workid:msgtype:ret
    if status == "success" {
	w := workers[workid]
	res2 := RpcDcrmRes{Ret:ss[3],Tip:"",Err:nil}
	w.retres.PushBack(&res2)

	if ss[2] == "rpc_lockout" {
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

	if ss[2] == "rpc_get_lockout_reply" {
	    
	    if w.retres.Len() == NodeCnt {
	    }
	}
	    
	return
    }
    
    //fail:workid:msgtype:tip:error
    if status == "fail" {
	w := workers[workid]
	var ret2 Err
	ret2.Info = ss[4] 
	res2 := RpcDcrmRes{Ret:"",Tip:ss[3],Err:ret2}
	w.retres.PushBack(&res2)

	if ss[2] == "rpc_lockout" {
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
	
	if ss[2] == "rpc_get_lockout_reply" {
	    if w.retres.Len() == NodeCnt {
	    }
	}

	return
    }
}

func GetGroupRes(wid int) RpcDcrmRes {
    if wid < 0 || wid >= RpcMaxWorker {
	res2 := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get work id fail",Err:GetRetErr(ErrGetWorkerIdError)}
	return res2
    }

    var l *list.List
    w := workers[wid]
    l = w.retres

    if l == nil {
	res2 := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get result from group fail",Err:GetRetErr(ErrGetNoResFromGroupMem)}
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
	res2 := RpcDcrmRes{Ret:"",Tip:ll.Tip,Err:err}
	return res2
	
	iter = iter.Next()
    }
    
    res2 := RpcDcrmRes{Ret:"",Tip:"",Err:nil}
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

func GetLockOutReply() (string,string,error) {
    lock5.Lock()
    dir := GetAcceptLockOutDir()
    db, err := leveldb.OpenFile(dir, nil)
    if err != nil {
        lock5.Unlock()
	return "","dcrm back-end internal error:open level db fail",err 
    }
   
    var ret []string
    var b bytes.Buffer 
    b.WriteString("") 
    b.WriteByte(0) 
    b.WriteString("") 
    iter := db.NewIterator(nil, nil) 
    for iter.Next() { 
	//key := string(iter.Key()) //TODO
	value := string(iter.Value())
	////
	ds,err := UnCompress(value)
	if err != nil {
	    continue
	}

	dss,err := Decode2(ds,"AcceptLockOutData")
	if err != nil {
	    continue
	}

	ac := dss.(*AcceptLockOutData)
	if ac.Deal == true {
	    continue
	}

	tmp := "{"
	tmp += "\"Account\":"
	tmp += "\""
	tmp += ac.Account
	tmp += "\""
	tmp += ","
	tmp += "\"Address\":"
	tmp += "\""
	tmp += ac.Address
	tmp += "\""
	tmp += ","
	tmp += "\"GroupId\":"
	tmp += "\""
	tmp += ac.GroupId
	tmp += "\""
	tmp += ","
	tmp += "\"Nonce\":"
	tmp += "\""
	tmp += ac.Nonce
	tmp += "\""
	tmp += ","
	tmp += "\"DcrmFrom\":"
	tmp += "\""
	tmp += ac.DcrmFrom
	tmp += "\""
	tmp += ","
	tmp += "\"DcrmTo\":"
	tmp += "\""
	tmp += ac.DcrmTo
	tmp += "\""
	tmp += ","
	tmp += "\"Value\":"
	tmp += "\""
	tmp += ac.Value
	tmp += "\""
	tmp += ","
	tmp += "\"Cointype\":"
	tmp += "\""
	tmp += ac.Cointype
	tmp += "\""
	tmp += ","
	tmp += "\"LimitNum\":"
	tmp += "\""
	tmp += ac.LimitNum
	tmp += "\""
	tmp += "}"
	ret = append(ret,tmp)
	////
    }
    iter.Release()
    
    ///////
    ss := strings.Join(ret,"|")
    db.Close()
    lock5.Unlock()

    return ss,"",nil
}

func GetAcceptRes(account string,groupid string,nonce string,dcrmfrom string,threshold string) (string,bool) {
    lock5.Lock()
    dir := GetAcceptLockOutDir()
    db, err := leveldb.OpenFile(dir, nil)
    if err != nil {
        lock5.Unlock()
	return "dcrm back-end internal error:open level db fail",false
    }
    
    key := Keccak256Hash([]byte(strings.ToLower(account + ":" + groupid + ":" + nonce + ":" + dcrmfrom + ":" + threshold))).Hex()
    da,err := db.Get([]byte(key),nil)
    ///////
    if err != nil {
	db.Close()
	lock5.Unlock()
	return "dcrm back-end internal error:get accept result from db fail",false
    }

    ds,err := UnCompress(string(da))
    if err != nil {
	db.Close()
	lock5.Unlock()
	return "dcrm back-end internal error:uncompress accept result fail",false
    }

    dss,err := Decode2(ds,"AcceptLockOutData")
    if err != nil {
	db.Close()
	lock5.Unlock()
	return "dcrm back-end internal error:decode accept result fail",false
    }

    ac := dss.(*AcceptLockOutData)

    db.Close()
    lock5.Unlock()
    return "",ac.Accept 
}

func AcceptLockOut(account string,groupid string,nonce string,dcrmfrom string,threshold string,deal bool,accept bool) (string,error) {
    lock5.Lock()
    dir := GetAcceptLockOutDir()
    db, err := leveldb.OpenFile(dir, nil)
    if err != nil {
        lock5.Unlock()
	return "dcrm back-end internal error:open level db fail",err
    }
    
    key := Keccak256Hash([]byte(strings.ToLower(account + ":" + groupid + ":" + nonce + ":" + dcrmfrom + ":" + threshold))).Hex()
    da,err := db.Get([]byte(key),nil)
    ///////
    if err != nil {
	db.Close()
	lock5.Unlock()
	return "dcrm back-end internal error:get accept data fail from db",err
    }

    ds,err := UnCompress(string(da))
    if err != nil {
	db.Close()
	lock5.Unlock()
	return "dcrm back-end internal error:uncompress accept data fail",err
    }

    dss,err := Decode2(ds,"AcceptLockOutData")
    if err != nil {
	db.Close()
	lock5.Unlock()
	return "dcrm back-end internal error:decode accept data fail",err
    }

    ac := dss.(*AcceptLockOutData)
    ac.Accept = accept
    ac.Deal = deal

    e,err := Encode2(ac)
    if err != nil {
	db.Close()
	lock5.Unlock()
	return "dcrm back-end internal error:encode accept data fail",err
    }

    es,err := Compress([]byte(e))
    if err != nil {
	db.Close()
	lock5.Unlock()
	return "dcrm back-end internal error:compress accept data fail",err
    }

    db.Put([]byte(key),[]byte(es),nil)
    db.Close()
    lock5.Unlock()
    acceptLockOutChan <- account
    return "",nil
}

func (self *RecvMsg) Run(workid int,ch chan interface{}) bool {
    if workid < 0 || workid >= RpcMaxWorker { //TODO
	res2 := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get worker id fail",Err:fmt.Errorf("no find worker.")}
	ch <- res2
	return false
    }

    /////////
    res := self.msg
    if res == "" { //TODO
	res2 := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get data fail in RecvMsg.Run",Err:fmt.Errorf("no find worker.")}
	ch <- res2
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
	res2 := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:uncompress data fail in RecvMsg.Run",Err:fmt.Errorf("uncompress data fail in recvmsg.run")}
	ch <- res2
	return false
    }
    r,err := Decode2(res,"SendMsg")
    if err != nil {
	res2 := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:decode data to SendMsg fail in RecvMsg.Run",Err:fmt.Errorf("decode data to SendMsg fail in recvmsg.run")}
	ch <- res2
	return false
    }

    switch r.(type) {
    case *SendMsg:
	rr := r.(*SendMsg)

	//rpc_lockout
	if rr.MsgType == "rpc_lockout" {
	    w := workers[workid]
	    w.sid = rr.Nonce
	    //msg = fusionaccount:address:dcrmaddr:dcrmto:value:cointype:groupid:nonce:threshold
	    msg := rr.Msg
	    msgs := strings.Split(msg,":")
	     
	    ac := &AcceptLockOutData{Account:msgs[0],Address:msgs[1],GroupId:msgs[6],Nonce:msgs[7],DcrmFrom:msgs[2],DcrmTo:msgs[3],Value:msgs[4],Cointype:msgs[5],LimitNum:msgs[8],Deal:false,Accept:false}
	    SaveAcceptData(ac) 
	    
	    ////
	    var reply bool 
	    var tip string 
	    timeout := make(chan bool, 1)
	    go func(timeout chan bool) {
                agreeWaitTime := 3 * time.Minute
                agreeWaitTimeOut := time.NewTicker(agreeWaitTime)
                for {
                   select {
                   case account := <-acceptLockOutChan:
                       tip,reply = GetAcceptRes(msgs[1],msgs[6],msgs[7],msgs[2],msgs[8])
                        fmt.Printf("==== (self *RecvMsg) Run() ====, address: %v, tip: %v, GetAcce     ptRes = %v\n", account, tip, reply)
                       timeout <- true
                   case <-agreeWaitTimeOut.C:
                        fmt.Printf("==== (self *RecvMsg) Run() ====, timerout %v\n", agreeWaitTime     )
                       break
                   }
               }
	     }(timeout)
	     <-timeout

	     fmt.Println("===============RecvMsg.Run,Get Accept LockOut Result =%v ================",reply)
	     if reply == false {
		 res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType,Tip:tip,Err:fmt.Errorf("don't accept lockout.")}
		ch <- res2
		return false
	     }
	    ////

	    w.groupid = msgs[6] 

	    rch := make(chan interface{},1)
	    validate_lockout(w.sid,msgs[0],msgs[2],msgs[5],msgs[4],msgs[3],msgs[7],rch)
	    chret,tip,cherr := GetChannelValue(ch_t,rch)
	    if chret != "" {
		fmt.Println("==============RecvMsg.Run,Get LockOut Result.TxHash = %s =================",chret)
		res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType+Sep+chret,Tip:"",Err:nil}
		ch <- res2
		return true
	    }

	    if cherr != nil {
		res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType,Tip:tip,Err:cherr}
		ch <- res2
		return false
	    }
	    
	    res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType,Tip:tip,Err:fmt.Errorf("send tx to net fail.")}
	    ch <- res2
	    return true
	}
	
	//rpc_req_dcrmaddr
	if rr.MsgType == "rpc_req_dcrmaddr" {
	    //msg = account:cointype:groupid:threshold
	    rch := make(chan interface{},1)
	    w := workers[workid]
	    w.sid = rr.Nonce

	    msgs := strings.Split(rr.Msg,":")
	    if len(msgs) < 4 {
		res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType,Tip:"dcrm back-end internal error:parameter error in req addr",Err:fmt.Errorf("get msg error.")}
		ch <- res2
		return false
	    }
	    
	    w.groupid = msgs[2]
	    w.limitnum = msgs[3]
	    dcrm_genPubKey(w.sid,msgs[0],msgs[1],rch)
	    chret,tip,cherr := GetChannelValue(ch_t,rch)
	    if cherr != nil {
		res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType,Tip:tip,Err:cherr}
		ch <- res2
		return false
	    }
	    
	    res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType+Sep+chret,Tip:"",Err:nil}
	    ch <- res2
	    return true
	}

	//rpc_get_lockout_reply
	if rr.MsgType == "rpc_get_lockout_reply" {
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

type PubKeyData struct {
    Pub string
    Save string
    Nonce string
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
    case *PubKeyData:
	ch := obj.(*PubKeyData)
	//ret,err := json.Marshal(ch)
	//if err != nil {
	//    return "",err
	//}
	//return string(ret),nil

	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)

	err1 := enc.Encode(ch)
	if err1 != nil {
	    return "",err1
	}
	return buff.String(),nil
    case *AcceptLockOutData:
	ch := obj.(*AcceptLockOutData)
	ret,err := json.Marshal(ch)
	if err != nil {
	    return "",err
	}
	return string(ret),nil
    default:
	return "",fmt.Errorf("encode obj fail.")
    }
}

func Decode2(s string,datatype string) (interface{},error) {
    if datatype == "SendMsg" {
	var m SendMsg
	err := json.Unmarshal([]byte(s), &m)
	if err != nil {
	    return nil,err
	}

	return &m,nil
    }

    if datatype == "PubKeyData" {
	//var m PubKeyData
	//err := json.Unmarshal([]byte(s), &m)
	//if err != nil {
	//    return nil,err
	//}

	//return &m,nil

	var data bytes.Buffer
	data.Write([]byte(s))
	
	dec := gob.NewDecoder(&data)

	var res PubKeyData 
	err := dec.Decode(&res)
	if err != nil {
	    return nil,err
	}

	return &res,nil
    }
    
    if datatype == "AcceptLockOutData" {
	var m AcceptLockOutData
	err := json.Unmarshal([]byte(s), &m)
	if err != nil {
	    return nil,err
	}

	return &m,nil
    }
    
    return nil,fmt.Errorf("decode obj fail.")
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
    Account string
    Cointype string
    GroupId string
    LimitNum string
}

func (self *ReqAddrSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 || workid >= RpcMaxWorker {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:no worker id",Err:GetRetErr(ErrGetWorkerIdError)}
	ch <- res
	return false
    }

    GetEnodesInfo(self.GroupId)
    timestamp := time.Now().Unix()
    tt := strconv.Itoa(int(timestamp))
    nonce := Keccak256Hash([]byte(self.Account + ":" + self.Cointype + ":" + self.GroupId + ":" + self.LimitNum + ":" + tt + ":" + strconv.Itoa(workid))).Hex()
    
    sm := &SendMsg{MsgType:"rpc_req_dcrmaddr",Nonce:nonce,WorkId:workid,Msg:self.Account + ":" + self.Cointype + ":" + self.GroupId + ":" + self.LimitNum}
    res,err := Encode2(sm)
    if err != nil {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:encode SendMsg fail in req addr",Err:err}
	ch <- res
	return false
    }

    res,err = Compress([]byte(res))
    if err != nil {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:compress SendMsg data fail in req addr",Err:err}
	ch <- res
	return false
    }

    s := SendToGroupAllNodes(self.GroupId,res)
    
    if strings.EqualFold(s,"send fail.") {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:send data to group fail in req addr",Err:GetRetErr(ErrSendDataToGroupFail)}
	ch <- res
	return false
    }

    fmt.Println("=============ReqAddrSendMsgToMsg.Run,Waiting For Result===========")
    w := workers[workid]
    chret,tip,cherr := GetChannelValue(sendtogroup_timeout,w.ch)
    if cherr != nil {
	res2 := RpcDcrmRes{Ret:chret,Tip:tip,Err:cherr}
	ch <- res2
	return false
    }

    fmt.Println("=========ReqAddrSendMsgToMsg.Run,Get Result = ===========",chret)
    res2 := RpcDcrmRes{Ret:chret,Tip:tip,Err:cherr}
    ch <- res2

    return true
}

//msg = fusionaccount:dcrmaddr:dcrmto:value:cointype:groupid:nonce:threshold
type LockOutSendMsgToDcrm struct {
    Account string
    Address string
    DcrmFrom string
    DcrmTo string
    Value string
    Cointype string
    GroupId string
    Nonce string
    LimitNum string
}

func (self *LockOutSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 || workid >= RpcMaxWorker {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get worker id error",Err:GetRetErr(ErrGetWorkerIdError)}
	ch <- res
	return false
    }

    GetEnodesInfo(self.GroupId)
    msg := self.Account + ":" self.Address + ":" + self.DcrmFrom + ":" + self.DcrmTo + ":" + self.Value + ":" + self.Cointype + ":" + self.GroupId + ":" + self.Nonce + ":" + self.LimitNum
    timestamp := time.Now().Unix()
    tt := strconv.Itoa(int(timestamp))
    nonce := Keccak256Hash([]byte(msg + ":" + tt + ":" + strconv.Itoa(workid))).Hex()
    
    sm := &SendMsg{MsgType:"rpc_lockout",Nonce:nonce,WorkId:workid,Msg:msg}
    res,err := Encode2(sm)
    if err != nil {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:encode SendMsg fail in lockout",Err:err}
	ch <- res
	return false
    }

    res,err = Compress([]byte(res))
    if err != nil {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:compress SendMsg data error in lockout",Err:err}
	ch <- res
	return false
    }

    s := SendToGroupAllNodes(self.GroupId,res)
    if strings.EqualFold(s,"send fail.") {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:send data to group fail",Err:GetRetErr(ErrSendDataToGroupFail)}
	ch <- res
	return false
    }

    ////
    var reply error
    var tip string
    timeout := make(chan bool, 1)
    go func(timeout chan bool) {
       agreeWaitTime := 3 * time.Minute
       agreeWaitTimeOut := time.NewTicker(agreeWaitTime)
       for {
          select {
          case account := <-acceptLockOutChan:
              tip,reply = AcceptLockOut(self.Account,self.GroupId,self.Nonce,self.DcrmFrom,self.Li     mitNum,false,true)
               fmt.Printf("==== (self *RecvMsg) Run() ====, account: %v, tip: %v, GetAcceptRes = %     v\n", account, tip, reply)
              timeout <- true
          case <-agreeWaitTimeOut.C:
               fmt.Printf("==== (self *RecvMsg) Run() ====, timerout %v\n", agreeWaitTime)
              break
          }
      }
     }(timeout)
     <-timeout

    fmt.Println("============LockOutSendMsgToDcrm.Run,get accept lockout result, err = %v ============",reply)
     if reply != nil {
	 res2 := RpcDcrmRes{Ret:"",Tip:tip,Err:reply}
	ch <- res2
	return false
     }
    ////
    w := workers[workid]
    chret,tip,cherr := GetChannelValue(sendtogroup_lilo_timeout,w.ch)
    fmt.Println("========LockOutSendMsgToDcrm.Run,Get Result = %s, err = %v ============",chret,cherr)
    if cherr != nil {
	res2 := RpcDcrmRes{Ret:"",Tip:tip,Err:cherr}
	ch <- res2
	return false
    }

    res2 := RpcDcrmRes{Ret:chret,Tip:tip,Err:cherr}
    ch <- res2

    return true
}

//msg = fusionaccount:groupid:nonce:dcrmaddr:threshold
type GetLockOutReplySendMsgToDcrm struct {
}

func (self *GetLockOutReplySendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 || workid >= RpcMaxWorker {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get worker id fail",Err:GetRetErr(ErrGetWorkerIdError)}
	ch <- res
	return false
    }

    ret,tip,err := GetLockOutReply()
    if err != nil {
	res2 := RpcDcrmRes{Ret:"",Tip:tip,Err:err}
	ch <- res2
	return false
    }

    res2 := RpcDcrmRes{Ret:ret,Tip:"",Err:nil}
    ch <- res2

    return true
}

type AcceptLockOutData struct {
    Account string
    Address string
    GroupId string
    Nonce string
    DcrmFrom string
    DcrmTo string
    Value string
    Cointype string
    LimitNum string

    Deal bool
    Accept bool
}

func SaveAcceptData(ac *AcceptLockOutData) error {
    if ac == nil {
	return fmt.Errorf("no accept data.")
    }

    lock5.Lock()
    dir := GetAcceptLockOutDir()
    db, err := leveldb.OpenFile(dir, nil)
    if err != nil {
        lock5.Unlock()
        return err
    }
    
    key := Keccak256Hash([]byte(strings.ToLower(ac.Address + ":" + ac.GroupId + ":" + ac.Nonce + ":" + ac.DcrmFrom + ":" + ac.LimitNum))).Hex()
    
    alos,err := Encode2(ac)
    if err != nil {
	db.Close()
	lock5.Unlock()
	return err
    }
    
    ss,err := Compress([]byte(alos))
    if err != nil {
	db.Close()
	lock5.Unlock()
	return err 
    }
   
    db.Put([]byte(key),[]byte(ss),nil)
    db.Close()
    lock5.Unlock()
    return nil
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

/*func GetGroupIdByEnode(enode string) string {
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
}*/

func GetEnodesInfo(GroupId string) {
    if GroupId == "" {
	return
    }
    
    Enode_cnts,_ = GetGroup(GroupId)
    NodeCnt = Enode_cnts
    cur_enode = GetSelfEnode()
}

func SendReqToGroup(msg string,rpctype string) (string,string,error) {
    var req RpcReq
    switch rpctype {
	case "rpc_req_dcrmaddr":
	    //msg = account : cointype : groupid : threshold 
	    msgs := strings.Split(msg,":")
	    v := ReqAddrSendMsgToDcrm{Account:msgs[0],Cointype:msgs[1],GroupId:msgs[2],LimitNum:msgs[3]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	    break
	case "rpc_lockout":
	    //msg = fusionaccount:address:dcrmaddr:dcrmto:value:cointype:groupid:nonce:threshold
	    m := strings.Split(msg,":")
	    v := LockOutSendMsgToDcrm{Account:m[0],Address:m[1],DcrmFrom:m[2],DcrmTo:m[3],Value:m[4],Cointype:m[5],GroupId:m[6],Nonce:m[7],LimitNum:m[8]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	    break
	case "rpc_get_lockout_reply":
	    v := GetLockOutReplySendMsgToDcrm{}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	    break
	default:
	    return "","",nil
    }

    var t int
    if rpctype == "rpc_lockout" {
	t = sendtogroup_lilo_timeout 
    } else {
	t = sendtogroup_timeout
    }

    RpcReqQueue <- req
    chret,tip,cherr := GetChannelValue(t,req.ch)
    if cherr != nil {
	return chret,tip,cherr
    }

    return chret,"",nil
}

func GetChannelValue(t int,obj interface{}) (string,string,error) {
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
			 return ret.Ret,ret.Tip,ret.Err
		     }
		 case <- timeout :
		     return "","dcrm back-end internal error:get result from channel timeout",fmt.Errorf("get data from node fail.")
	     }
	 case chan string:
	     ch := obj.(chan string)
	     select {
		 case v := <- ch :
			    return v,"",nil 
		 case <- timeout :
		     return "","dcrm back-end internal error:get result from channel timeout",fmt.Errorf("get data from node fail.")
	     }
	 case chan int64:
	     ch := obj.(chan int64)
	     select {
		 case v := <- ch :
		    return strconv.Itoa(int(v)),"",nil 
		 case <- timeout :
		     return "","dcrm back-end internal error:get result from channel timeout",fmt.Errorf("get data from node fail.")
	     }
	 case chan int:
	     ch := obj.(chan int)
	     select {
		 case v := <- ch :
		    return strconv.Itoa(v),"",nil 
		 case <- timeout :
		     return "","dcrm back-end internal error:get result from channel timeout",fmt.Errorf("get data from node fail.")
	     }
	 case chan bool:
	     ch := obj.(chan bool)
	     select {
		 case v := <- ch :
		    if !v {
			return "false","",nil
		    } else {
			return "true","",nil
		    }
		 case <- timeout :
		     return "","dcrm back-end internal error:get result from channel timeout",fmt.Errorf("get data from node fail.")
	     }
	 default:
	     return "","dcrm back-end internal error:unknown channel type",fmt.Errorf("unknown ch type.") 
     }

     return "","dcrm back-end internal error:unknown error.",fmt.Errorf("get value fail.")
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

	    //////////////////ed
	    case "EDC11":
	    logs.Debug("=========DisMsg,it is ed and it is EDC11.=============","len msg_edc11",w.msg_edc11.Len(),"len msg",len(msg))
	    ///bug
	    if w.msg_edc11.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_edc11.PushBack(msg)
	    logs.Debug("=========DisMsg,EDC11 msg.=============","len c11",w.msg_edc11.Len(),"nodecnt-1",(NodeCnt-1))
	    if w.msg_edc11.Len() == (NodeCnt-1) {
		logs.Debug("=========DisMsg,get all EDC11 msg.=============")
		w.bedc11 <- true
	    }
	    case "EDZK":
	    logs.Debug("=========DisMsg,it is ed and it is EDZK.=============","len msg_edzk",w.msg_edzk.Len(),"len msg",len(msg))
	    ///bug
	    if w.msg_edzk.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_edzk.PushBack(msg)
	    logs.Debug("=========DisMsg,EDZK msg.=============","len zk",w.msg_edzk.Len(),"nodecnt-1",(NodeCnt-1))
	    if w.msg_edzk.Len() == (NodeCnt-1) {
		logs.Debug("=========DisMsg,get all EDZK msg.=============")
		w.bedzk <- true
	    }
	    case "EDD11":
	    logs.Debug("=========DisMsg,it is ed and it is EDD11.=============","len msg_edd11",w.msg_edd11.Len(),"len msg",len(msg))
	    ///bug
	    if w.msg_edd11.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_edd11.PushBack(msg)
	    logs.Debug("=========DisMsg,EDD11 msg.=============","len d11",w.msg_edd11.Len(),"nodecnt-1",(NodeCnt-1))
	    if w.msg_edd11.Len() == (NodeCnt-1) {
		logs.Debug("=========DisMsg,get all EDD11 msg.=============")
		w.bedd11 <- true
	    }
	    case "EDSHARE1":
	    logs.Debug("=========DisMsg,it is ed and it is EDSHARE1.=============","len msg_edshare1",w.msg_edshare1.Len(),"len msg",len(msg))
	    ///bug
	    if w.msg_edshare1.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_edshare1.PushBack(msg)
	    logs.Debug("=========DisMsg,EDSHARE1 msg.=============","len share1",w.msg_edshare1.Len(),"nodecnt-1",(NodeCnt-1))
	    if w.msg_edshare1.Len() == (NodeCnt-1) {
		logs.Debug("=========DisMsg,get all EDSHARE1 msg.=============")
		w.bedshare1 <- true
	    }
	    case "EDCFSB":
	    logs.Debug("=========DisMsg,it is ed and it is EDCFSB.=============","len msg_edcfsb",w.msg_edcfsb.Len(),"len msg",len(msg))
	    ///bug
	    if w.msg_edcfsb.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_edcfsb.PushBack(msg)
	    logs.Debug("=========DisMsg,EDCFSB msg.=============","len cfsb",w.msg_edcfsb.Len(),"nodecnt-1",(NodeCnt-1))
	    if w.msg_edcfsb.Len() == (NodeCnt-1) {
		logs.Debug("=========DisMsg,get all EDCFSB msg.=============")
		w.bedcfsb <- true
	    }
	    case "EDC21":
	    logs.Debug("=========DisMsg,it is ed and it is EDC21.=============","len msg_edc21",w.msg_edc21.Len(),"len msg",len(msg))
	    ///bug
	    if w.msg_edc21.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_edc21.PushBack(msg)
	    logs.Debug("=========DisMsg,EDC21 msg.=============","len c21",w.msg_edc21.Len(),"nodecnt-1",(NodeCnt-1))
	    if w.msg_edc21.Len() == (NodeCnt-1) {
		logs.Debug("=========DisMsg,get all EDC21 msg.=============")
		w.bedc21 <- true
	    }
	    case "EDZKR":
	    logs.Debug("=========DisMsg,it is ed and it is EDZKR.=============","len msg_edzkr",w.msg_edzkr.Len(),"len msg",len(msg))
	    ///bug
	    if w.msg_edzkr.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_edzkr.PushBack(msg)
	    logs.Debug("=========DisMsg,EDZKR msg.=============","len zkr",w.msg_edzkr.Len(),"nodecnt-1",(NodeCnt-1))
	    if w.msg_edzkr.Len() == (NodeCnt-1) {
		logs.Debug("=========DisMsg,get all EDZKR msg.=============")
		w.bedzkr <- true
	    }
	    case "EDD21":
	    logs.Debug("=========DisMsg,it is ed and it is EDD21.=============","len msg_edd21",w.msg_edd21.Len(),"len msg",len(msg))
	    ///bug
	    if w.msg_edd21.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_edd21.PushBack(msg)
	    logs.Debug("=========DisMsg,EDD21 msg.=============","len d21",w.msg_edd21.Len(),"nodecnt-1",(NodeCnt-1))
	    if w.msg_edd21.Len() == (NodeCnt-1) {
		logs.Debug("=========DisMsg,get all EDD21 msg.=============")
		w.bedd21 <- true
	    }
	    case "EDC31":
	    logs.Debug("=========DisMsg,it is ed and it is EDC31.=============","len msg_edc31",w.msg_edc31.Len(),"len msg",len(msg))
	    ///bug
	    if w.msg_edc31.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_edc31.PushBack(msg)
	    logs.Debug("=========DisMsg,EDC31 msg.=============","len c31",w.msg_edc31.Len(),"nodecnt-1",(NodeCnt-1))
	    if w.msg_edc31.Len() == (NodeCnt-1) {
		logs.Debug("=========DisMsg,get all EDC31 msg.=============")
		w.bedc31 <- true
	    }
	    case "EDD31":
	    logs.Debug("=========DisMsg,it is ed and it is EDD31.=============","len msg_edd31",w.msg_edd31.Len(),"len msg",len(msg))
	    ///bug
	    if w.msg_edd31.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_edd31.PushBack(msg)
	    logs.Debug("=========DisMsg,EDD31 msg.=============","len d31",w.msg_edd31.Len(),"nodecnt-1",(NodeCnt-1))
	    if w.msg_edd31.Len() == (NodeCnt-1) {
		logs.Debug("=========DisMsg,get all EDD31 msg.=============")
		w.bedd31 <- true
	    }
	    case "EDS":
	    logs.Debug("=========DisMsg,it is ed and it is EDS.=============","len msg_eds",w.msg_eds.Len(),"len msg",len(msg))
	    ///bug
	    if w.msg_eds.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_eds.PushBack(msg)
	    logs.Debug("=========DisMsg,EDS msg.=============","len s",w.msg_eds.Len(),"nodecnt-1",(NodeCnt-1))
	    if w.msg_eds.Len() == (NodeCnt-1) {
		logs.Debug("=========DisMsg,get all EDS msg.=============")
		w.beds <- true
	    }
	    ///////////////////
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

func GetAcceptLockOutDir() string {
    dir := DefaultDataDir()
    dir += "/dcrmdata/dcrmdb/accept" + cur_enode
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

//eos_init---> eos account
//key: crypto.Keccak256Hash([]byte("eossettings"))
//value: pubkey+eos account
func GetEosDbDir() string {
    dir := DefaultDataDir()
    dir += "/dcrmdata/eosdb"
    return dir
}

