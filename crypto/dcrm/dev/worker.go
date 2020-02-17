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
    "sort"
    "compress/zlib"
    "io"
    "os"
    "github.com/fsn-dev/dcrm-walletService/crypto/sha3"
    "github.com/fsn-dev/dcrm-walletService/crypto/dcrm/dev/lib/ec2"
    "github.com/fsn-dev/dcrm-walletService/internal/common/hexutil"
    "runtime"
    "path/filepath"
    "sync"
    "os/user"
    "strings"
    "fmt"
    "strconv"
    //"math/big"
    //"github.com/fsn-dev/dcrm-walletService/p2p/rlp"
    "encoding/json"
    "github.com/astaxie/beego/logs"
    "encoding/gob"
    "encoding/hex"
    //"github.com/fsn-dev/dcrm-walletService/coins/types"
    "github.com/fsn-dev/dcrm-walletService/internal/common"
)

var (
    Sep = "dcrmparm"
    SepSave = "dcrmsepsave"
    SepSg = "dcrmmsg"
    SepDel = "dcrmsepdel"

    PaillierKeyLength = 2048
    sendtogroup_lilo_timeout =1200 
    sendtogroup_timeout = 1200
    ch_t = 700 
    lock5 sync.Mutex
    lock sync.Mutex

    //callback
    GetGroup func(string) (int,string)
    SendToGroupAllNodes func(string,string) (string,error)
    GetSelfEnode func() string
    BroadcastInGroupOthers func(string,string) (string,error)
    SendToPeer func(string,string) error
    ParseNode func(string) string
    GetEosAccount func() (string,string,string)

    KeyFile string
    
    AllAccounts = common.NewSafeMap(10)//make([]*PubKeyData,0)
    AllAccountsChan = make(chan KeyData, 1000)
    
    LdbPubKeyData = common.NewSafeMap(10)//make(map[string][]byte)
    PubKeyDataChan = make(chan KeyData, 1000)
    
    LdbReqAddr = common.NewSafeMap(10)//make(map[string][]byte)
    ReqAddrChan = make(chan KeyData, 1000)
    
    LdbLockOut = common.NewSafeMap(10)//make(map[string][]byte)
    LockOutChan = make(chan KeyData, 1000)

    ReSendTimes int //resend p2p msg times
    DcrmCalls = common.NewSafeMap(10)
    
    RpcReqQueueCache = make(chan RpcReq,RpcMaxQueue)
)

func RegP2pGetGroupCallBack(f func(string)(int,string)) {
    GetGroup = f
}

func RegP2pSendToGroupAllNodesCallBack(f func(string,string) (string,error)) {
    SendToGroupAllNodes = f
}

func RegP2pGetSelfEnodeCallBack(f func()string) {
    GetSelfEnode = f
}

func RegP2pBroadcastInGroupOthersCallBack(f func(string,string) (string,error)) {
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

func InitDev(keyfile string,groupId string) {
    cur_enode = GetSelfEnode()
    fmt.Println("=========InitDev===========","groupId=",groupId,"cur_enode=",cur_enode)
    peerscount, _ := GetGroup(groupId)
   NodeCnt = peerscount
   ThresHold = peerscount
   Enode_cnts = peerscount //bug
    GetEnodesInfo(groupId)
    KeyFile = keyfile
    AllAccounts = GetAllPubKeyDataFromDb()
    //LdbReqAddr = GetAllPendingReqAddrFromDb()
    //LdbLockOut = GetAllPendingLockOutFromDb()
    go SavePubKeyDataToDb()
    go SaveAllAccountsToDb()
    go SaveReqAddrToDb()
    go SaveLockOutToDb()

    ReSendTimes = 1
    
    go CommitRpcReq()
    go ec2.GenRandomInt(2048)
    go ec2.GenRandomSafePrime(2048)
}

func GenRandomSafePrime(length int) {
    ec2.GenRandomSafePrime(length)
}

////////////////////////dcrm///////////////////////////////
var (
    //rpc-req //dcrm node
    RpcMaxWorker = 2000 
    RpcMaxQueue  = 2000
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
    msg_acceptreqaddrres *list.List
    splitmsg_acceptreqaddrres map[string]*list.List
    
    msg_acceptlockoutres *list.List
    splitmsg_acceptlockoutres map[string]*list.List
    
    msg_sendlockoutres *list.List
    splitmsg_sendlockoutres map[string]*list.List
    
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
    
    msg_commitbigvab *list.List
    splitmsg_commitbigvab map[string]*list.List
    
    msg_zkabproof *list.List
    splitmsg_zkabproof map[string]*list.List
    
    msg_commitbigut *list.List
    splitmsg_commitbigut map[string]*list.List
    
    msg_commitbigutd11 *list.List
    splitmsg_commitbigutd11 map[string]*list.List
    
    msg_s1 *list.List
    splitmsg_s1 map[string]*list.List
    
    msg_ss1 *list.List
    splitmsg_ss1 map[string]*list.List

    pkx *list.List
    pky *list.List
    save *list.List
    
    bacceptreqaddrres chan bool
    bacceptlockoutres chan bool
    bsendlockoutres chan bool
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
    bcommitbigvab chan bool
    bzkabproof chan bool
    bcommitbigut chan bool
    bcommitbigutd11 chan bool
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

    acceptReqAddrChan chan string
    acceptWaitReqAddrChan chan string
    
    acceptLockOutChan chan string
    acceptWaitLockOutChan chan string
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
    if sid == "" {
	return nil,fmt.Errorf("input worker id error.")
    }

    for i := 0; i < RpcMaxWorker; i++ {
	w := workers[i]

	if w.sid == "" {
	    continue
	}

	if strings.EqualFold(w.sid,sid) {
	    return w,nil
	}
    }

    time.Sleep(time.Duration(5)*time.Second) //1000 == 1s //TODO
    
    for i := 0; i < RpcMaxWorker; i++ {
	w := workers[i]
	if w.sid == "" {
	    continue
	}

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
    msg_commitbigvab:list.New(),
    splitmsg_commitbigvab:make(map[string]*list.List),
    msg_zkabproof:list.New(),
    splitmsg_zkabproof:make(map[string]*list.List),
    msg_commitbigut:list.New(),
    splitmsg_commitbigut:make(map[string]*list.List),
    msg_commitbigutd11:list.New(),
    splitmsg_commitbigutd11:make(map[string]*list.List),
    msg_s1:list.New(),
    splitmsg_s1:make(map[string]*list.List),
    msg_ss1:list.New(),
    splitmsg_ss1:make(map[string]*list.List),
    msg_acceptreqaddrres:list.New(),
    splitmsg_acceptreqaddrres:make(map[string]*list.List),
    msg_acceptlockoutres:list.New(),
    splitmsg_acceptlockoutres:make(map[string]*list.List),
    msg_sendlockoutres:list.New(),
    splitmsg_sendlockoutres:make(map[string]*list.List),
    
    pkx:list.New(),
    pky:list.New(),
    save:list.New(),
    
    bacceptreqaddrres:make(chan bool,1),
    bacceptlockoutres:make(chan bool,1),
    bsendlockoutres:make(chan bool,1),
    bc1:make(chan bool,1),
    bd1_1:make(chan bool,1),
    bc11:make(chan bool,1),
    bkc:make(chan bool,1),
    bcommitbigvab:make(chan bool,1),
    bzkabproof:make(chan bool,1),
    bcommitbigut:make(chan bool,1),
    bcommitbigutd11:make(chan bool,1),
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

    acceptReqAddrChan:make(chan string,1),
    acceptWaitReqAddrChan:make(chan string,1),
    
    acceptLockOutChan:make(chan string,1),
    acceptWaitLockOutChan:make(chan string,1),
    }
}

func (w *RpcReqWorker) Clear() {

    w.sid = ""
    w.groupid = ""
    w.limitnum = ""
    
    var next *list.Element
    
    for e := w.msg_acceptlockoutres.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_acceptlockoutres.Remove(e)
    }
    
    for e := w.msg_sendlockoutres.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_sendlockoutres.Remove(e)
    }
    
    for e := w.msg_acceptreqaddrres.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_acceptreqaddrres.Remove(e)
    }
    
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

    for e := w.msg_commitbigvab.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_commitbigvab.Remove(e)
    }

    for e := w.msg_zkabproof.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_zkabproof.Remove(e)
    }

    for e := w.msg_commitbigut.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_commitbigut.Remove(e)
    }

    for e := w.msg_commitbigutd11.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_commitbigutd11.Remove(e)
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
    if len(w.bacceptlockoutres) == 1 {
	<-w.bacceptlockoutres
    }
    if len(w.bsendlockoutres) == 1 {
	<-w.bsendlockoutres
    }
    if len(w.bacceptreqaddrres) == 1 {
	<-w.bacceptreqaddrres
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
    if len(w.bcommitbigvab) == 1 {
	<-w.bcommitbigvab
    }
    if len(w.bzkabproof) == 1 {
	<-w.bzkabproof
    }
    if len(w.bcommitbigut) == 1 {
	<-w.bcommitbigut
    }
    if len(w.bcommitbigutd11) == 1 {
	<-w.bcommitbigutd11
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
    w.splitmsg_acceptlockoutres = make(map[string]*list.List)
    w.splitmsg_sendlockoutres = make(map[string]*list.List)
    w.splitmsg_acceptreqaddrres = make(map[string]*list.List)
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
    w.splitmsg_commitbigvab = make(map[string]*list.List)
    w.splitmsg_zkabproof = make(map[string]*list.List)
    w.splitmsg_commitbigut = make(map[string]*list.List)
    w.splitmsg_commitbigutd11 = make(map[string]*list.List)
    w.splitmsg_s1 = make(map[string]*list.List)
    w.splitmsg_ss1 = make(map[string]*list.List)
    
    if len(w.acceptWaitReqAddrChan) == 1 {
	<-w.acceptWaitReqAddrChan
    }
    if len(w.acceptReqAddrChan) == 1 {
	<-w.acceptReqAddrChan
    }
    if len(w.acceptWaitLockOutChan) == 1 {
	<-w.acceptWaitLockOutChan
    }
    if len(w.acceptLockOutChan) == 1 {
	<-w.acceptLockOutChan
    }
}

func (w *RpcReqWorker) Clear2() {
    fmt.Println("===========RpcReqWorker.Clear2,w.id = %s ===================",w.id)
    var next *list.Element
    
    for e := w.msg_acceptreqaddrres.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_acceptreqaddrres.Remove(e)
    }
    
    for e := w.msg_acceptlockoutres.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_acceptlockoutres.Remove(e)
    }
    
    for e := w.msg_sendlockoutres.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_sendlockoutres.Remove(e)
    }
    
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
    if len(w.bacceptlockoutres) == 1 {
	<-w.bacceptlockoutres
    }
    if len(w.bsendlockoutres) == 1 {
	<-w.bsendlockoutres
    }
    if len(w.bacceptreqaddrres) == 1 {
	<-w.bacceptreqaddrres
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
    w.splitmsg_acceptlockoutres = make(map[string]*list.List)
    w.splitmsg_sendlockoutres = make(map[string]*list.List)
    w.splitmsg_acceptreqaddrres = make(map[string]*list.List)
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
    
    if len(w.acceptWaitReqAddrChan) == 1 {
	<-w.acceptWaitReqAddrChan
    }
    if len(w.acceptReqAddrChan) == 1 {
	<-w.acceptReqAddrChan
    }
    if len(w.acceptWaitLockOutChan) == 1 {
	<-w.acceptWaitLockOutChan
    }
    if len(w.acceptLockOutChan) == 1 {
	<-w.acceptLockOutChan
    }
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

func ClearChan(ch chan string) {
    l := len(ch)
    for i:=0;i<l;i++ {
	<-ch
    }
}

type WorkReq interface {
    Run(workid int,ch chan interface{}) bool
}

//RecvMsg
type RecvMsg struct {
    msg string
    sender string
}

func DcrmCall(msg interface{},enode string) <-chan string {
    s := msg.(string)
    ch := make(chan string, 1)
    fmt.Println("=============DcrmCall,len(receiv) = %v,enode =%s ==============",len(s),enode)
    ///check
    _,exsit := DcrmCalls.ReadMap(s)
    if exsit == false {
	DcrmCalls.WriteMap(s,"true")
    } else {
	ret := ("fail"+Sep+"already exsit in DcrmCalls"+Sep+"dcrm back-end internal error:already exsit in DcrmCalls"+Sep+"already exsit in DcrmCalls") //TODO "no-data"
	ch <- ret
	return ch
    }
    ///

    ////////
    if s == "" {
	//fail:chret:tip:error
	ret := ("fail"+Sep+"no-data"+Sep+"dcrm back-end internal error:get msg fail"+Sep+"get msg fail") //TODO "no-data"
	ch <- ret 
	return ch
    }

    res,err := UnCompress(s)
    if err != nil {
	//fail:chret:tip:error
	ret := ("fail"+Sep+"no-data"+Sep+"dcrm back-end internal error:uncompress data fail in RecvMsg.Run"+Sep+"uncompress data fail in recvmsg.run") //TODO "no-data"
	ch <- ret 
	return ch
    }

    r,err := Decode2(res,"SendMsg")
    if err != nil {
	//fail:chret:tip:error
	ret := ("fail"+Sep+"no-data"+Sep+"dcrm back-end internal error:decode data to SendMsg fail in RecvMsg.Run"+Sep+"decode data to SendMsg fail in recvmsg.run") //TODO "no-data"
	ch <- ret 
	return ch
    }
    
    rr := r.(*SendMsg)
    if rr.MsgType == "rpc_lockout" {
    }
    if rr.MsgType == "rpc_req_dcrmaddr" {
    }
    ////////

    v := RecvMsg{msg:s,sender:enode}
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:&v,ch:rch}
    RpcReqQueue <- req
    chret,tip,cherr := GetChannelValue(sendtogroup_timeout,rch)
    if cherr != nil {
	////
	if rr.MsgType == "rpc_lockout" {
	}
	if rr.MsgType == "rpc_req_dcrmaddr" {
	}
	////

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

func DcrmCallRet(msg interface{},enode string) {

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
    fmt.Println("=========DcrmCallRet, ret = %s,len(ret) = %v ==============",ss[3],len(ss[3]))
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
	if err != nil {
	    return (*ll)
	}
	iter = iter.Next()
    }

    iter = l.Front()
    for iter != nil {
	ll := iter.Value.(*RpcDcrmRes)
	return (*ll)
	
	iter = iter.Next()
    }
    
    res2 := RpcDcrmRes{Ret:"",Tip:"",Err:nil}
    return res2
}

//=========================================

func Call(msg interface{},enode string) {
    fmt.Println("==============Call,get msg =%s,sender =%s===============",msg.(string),enode)
    s := msg.(string)
    SetUpMsgList(s,enode)
}

func SetUpMsgList(msg string,enode string) {

    v := RecvMsg{msg:msg,sender:enode}
    //rpc-req
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:&v,ch:rch}
    RpcReqQueue <- req
}

type ReqAddrStatus struct {
    Status string
    PubKey string
    Tip string
    Error string
    AllReply string
}

func GetReqAddrStatus(key string) (string,string,error) {
    var da []byte
    datmp,exsit := LdbReqAddr.ReadMap(key)
    if exsit == false {
	da2 := GetReqAddrValueFromDb(key)
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
    if exsit == false {
	fmt.Println("==================GetReqAddrStatus,get accept data fail from db,key =%s ===================",key)
	return "","dcrm back-end internal error:get accept data fail from db",fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
    }

    ds,err := UnCompress(string(da))
    if err != nil {
	fmt.Println("==================GetReqAddrStatus,uncompress accept data fail,key =%s ===================",key)
	return "","dcrm back-end internal error:uncompress accept data fail",err
    }

    dss,err := Decode2(ds,"AcceptReqAddrData")
    if err != nil {
	fmt.Println("==================GetReqAddrStatus,decode accept data fail,key =%s ===================",key)
	return "","dcrm back-end internal error:decode accept data fail",err
    }

    ac := dss.(*AcceptReqAddrData)
    fmt.Println("==================GetReqAddrStatus,ac.Status=%s,ac.PubKey=%s,ac.Tip=%s,ac.Error=%s,ac.AllReply=%s,key =%s ===================",ac.Status,ac.PubKey,ac.Tip,ac.Error,ac.AllReply,key)
    los := &ReqAddrStatus{Status:ac.Status,PubKey:ac.PubKey,Tip:ac.Tip,Error:ac.Error,AllReply:ac.AllReply}
    ret,err := json.Marshal(los)
    if err != nil {
	fmt.Println("==================GetReqAddrStatus,get result fail,err =%v,key =%s ===================",err,key)
    } else {
	fmt.Println("==================GetReqAddrStatus,get result success,ret =%s,key =%s ===================",string(ret),key)
    }

    return string(ret),"",nil
}

type LockOutStatus struct {
    Status string
    OutTxHash string
    Tip string
    Error string
    AllReply string
}

func GetLockOutStatus(key string) (string,string,error) {
    var da []byte
    datmp,exsit := LdbLockOut.ReadMap(key)
    if exsit == false {
	da2 := GetLockOutValueFromDb(key)
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
    if exsit == false {
	fmt.Println("==================GetLockOutStatus,get accept data fail from db,key =%s ===================",key)
	return "","dcrm back-end internal error:get accept data fail from db",fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
    }

    ds,err := UnCompress(string(da))
    if err != nil {
	fmt.Println("==================GetLockOutStatus,uncompress accept data fail,key =%s ===================",key)
	return "","dcrm back-end internal error:uncompress accept data fail",err
    }

    dss,err := Decode2(ds,"AcceptLockOutData")
    if err != nil {
	fmt.Println("==================GetLockOutStatus,decode accept data fail,key =%s ===================",key)
	return "","dcrm back-end internal error:decode accept data fail",err
    }

    ac := dss.(*AcceptLockOutData)
    fmt.Println("==================GetLockOutStatus,ac.Status=%s,ac.OutTxHash=%s,ac.Tip=%s,ac.Error=%s,ac.AllReply=%s,key =%s ===================",ac.Status,ac.OutTxHash,ac.Tip,ac.Error,ac.AllReply,key)
    los := &LockOutStatus{Status:ac.Status,OutTxHash:ac.OutTxHash,Tip:ac.Tip,Error:ac.Error,AllReply:ac.AllReply}
    ret,err := json.Marshal(los)
    if err != nil {
	fmt.Println("==================GetLockOutStatus,get result fail,err =%v,key =%s ===================",err,key)
    } else {
	fmt.Println("==================GetLockOutStatus,get result success,ret =%s,key =%s ===================",string(ret),key)
    }

    return string(ret),"",err
}

type EnAcc struct {
    Enode string
    Accounts []string
}

type EnAccs struct {
    EnodeAccounts []EnAcc
}

type ReqAddrReply struct {
    Key string
    Account string
    Cointype string
    GroupId string
    Nonce string
    LimitNum string
    Mode string
    GroupAccounts []EnAcc
}

func SortCurNodeInfo(value []interface{}) []interface{} {
    if len(value) == 0 {
	return value
    }
    
    var ids sortableIDSSlice
    for k,v := range value {
	uid := DoubleHash(string(v.([]byte)),"ALL")
	ids = append(ids,uid)
	fmt.Println("===============SortCurNodeInfo,11111,index =%v,uid =%v,len(v)=%v,================",k,uid,len(string(v.([]byte))))
    }
    
    sort.Sort(ids)

    var ret = make([]interface{},0)
    for k,v := range ids {
	fmt.Println("===============SortCurNodeInfo,ids index=%v,ids uid =%v================",k,v)
	for kk,vv := range value {
	    uid := DoubleHash(string(vv.([]byte)),"ALL")
	    fmt.Println("===============SortCurNodeInfo,22222,index =%v,uid =%v,len(vv)=%v,================",kk,uid,len(string(vv.([]byte))))
	    if v.Cmp(uid) == 0 {
		ret = append(ret,vv)
		break
	    }
	}
    }

    return ret
}

func GetCurNodeReqAddrInfo(geter_acc string) (string,string,error) {
    var ret []string
    _,lmvalue := LdbReqAddr.ListMap()
    ////for test only
    for kk,vv2 := range lmvalue {
	fmt.Println("================GetCurNodeReqAddrInfo,TEST,list map index =%v,len(value) =%v ===================",kk,len(string(vv2.([]byte))))
	vv3 := vv2.([]byte)
	value := string(vv3)
	fmt.Println("================GetCurNodeReqAddrInfo,TEST,len(value) =%v ===================",len(value))
	////
	ds,err := UnCompress(value)
	if err != nil {
	    fmt.Println("================GetCurNodeReqAddrInfo,TEST,uncompress err =%v ===================",err)
	    continue
	}

	dss,err := Decode2(ds,"AcceptReqAddrData")
	if err != nil {
	    fmt.Println("================GetCurNodeReqAddrInfo,TEST,decode err =%v ===================",err)
	    continue
	}

	ac := dss.(*AcceptReqAddrData)
	if ac == nil {
	    fmt.Println("================GetCurNodeReqAddrInfo,TEST,decode err ===================")
	    continue
	}
	fmt.Println("================GetCurNodeReqAddrInfo,TEST,ac.Account =%s,ac.Status =%s,ac =%v ===================",ac.Account,ac.Status,ac)
    }
    /////////////////

    lmvalue2 := SortCurNodeInfo(lmvalue)
    for _,v := range lmvalue2 {
	if v == nil {
	    continue
	}

	vv := v.([]byte)
	value := string(vv)
	fmt.Println("================GetCurNodeReqAddrInfo,len(value) =%v ===================",len(value))
	////
	ds,err := UnCompress(value)
	if err != nil {
	    fmt.Println("================GetCurNodeReqAddrInfo,uncompress err =%v ===================",err)
	    continue
	}

	dss,err := Decode2(ds,"AcceptReqAddrData")
	if err != nil {
	    fmt.Println("================GetCurNodeReqAddrInfo,decode err =%v ===================",err)
	    continue
	}

	ac := dss.(*AcceptReqAddrData)
	if ac == nil {
	    fmt.Println("================GetCurNodeReqAddrInfo,decode err ===================")
	    continue
	}
	fmt.Println("================GetCurNodeReqAddrInfo,ac.Account =%s,ac.Status =%s,ac =%v ===================",ac.Account,ac.Status,ac)

	eaccs := make([]EnAcc,0)
	/*check := false
	eaccs := make([]EnAcc,0)
	////bug,check valid accepter
	for k,v := range ac.NodeSigs {
	    fmt.Println("=============GetCurNodeReqAddrInfo,check accepter,index =%v=========================",k)
	    tx2 := new(types.Transaction)
	    vs := common.FromHex(v)
	    if err = rlp.DecodeBytes(vs, tx2); err != nil {
		continue
	    }

	    signer := types.NewEIP155Signer(big.NewInt(30400)) //
	    from2, err := types.Sender(signer, tx2)
	    if err != nil {
		signer = types.NewEIP155Signer(big.NewInt(4)) //
		from2, err = types.Sender(signer, tx2)
		if err != nil {
		    continue
		}
	    }

	    eid := string(tx2.Data())
	    accs := make([]string,0)
	    accs = append(accs,from2.Hex())
	    ea := EnAcc{Enode:eid,Accounts:accs}
	    eaccs = append(eaccs,ea)
	    
	    fmt.Println("============GetCurNodeReqAddrInfo,eid = %s,cur_enode =%s,from =%s,from2 =%s===============",eid,cur_enode,geter_acc,from2.Hex())
	    if strings.EqualFold(eid,cur_enode) && strings.EqualFold(geter_acc,from2.Hex()) {
		check = true
		//break
	    }
	}

	if check == false {
	   continue 
	}*/

	if ac.Deal == true || ac.Status == "Success" {
	    fmt.Println("================GetCurNodeReqAddrInfo,this req addr has handle,nonce =%s===================",ac.Nonce)
	    continue
	}

	if ac.Status != "Pending" {
	    fmt.Println("================GetCurNodeReqAddrInfo,this is not pending,nonce =%s===================",ac.Nonce)
	    continue
	}

	key := Keccak256Hash([]byte(strings.ToLower(ac.Account + ":" + "ALL" + ":" + ac.GroupId + ":" + ac.Nonce + ":" + ac.LimitNum + ":" + ac.Mode))).Hex()
	
	los := &ReqAddrReply{Key:key,Account:ac.Account,Cointype:ac.Cointype,GroupId:ac.GroupId,Nonce:ac.Nonce,LimitNum:ac.LimitNum,Mode:ac.Mode,GroupAccounts:eaccs}
	ret2,err := json.Marshal(los)
	fmt.Println("=====================GetCurNodeReqAddrInfo,success get ret =%s,err =%v====================",string(ret2),err)
	
	ret = append(ret,string(ret2))
	////
    }

    ///////
    ss := strings.Join(ret,"|")
    return ss,"",nil
}

type LockOutCurNodeInfo struct {
    Key string
    Account string
    GroupId string
    Nonce string
    DcrmFrom string
    DcrmTo string
    Value string
    Cointype string
    LimitNum string
    Mode string
    GroupAccounts []EnAcc
}

func GetCurNodeLockOutInfo(geter_acc string) (string,string,error) {
    var ret []string
    _,lmvalue := LdbLockOut.ListMap()
    ////for test only
    for kk,vv2 := range lmvalue {
	fmt.Println("================GetCurNodeLockOutInfo,TEST,list map index =%v,len(value) =%v ===================",kk,len(string(vv2.([]byte))))
	vv3 := vv2.([]byte)
	value := string(vv3)
	fmt.Println("================GetCurNodeLockOutInfo,TEST,len(value) =%v ===================",len(value))
	////
	ds,err := UnCompress(value)
	if err != nil {
	    fmt.Println("================GetCurNodeLockOutInfo,TEST,uncompress err =%v ===================",err)
	    continue
	}

	dss,err := Decode2(ds,"AcceptLockOutData")
	if err != nil {
	    fmt.Println("================GetCurNodeLockOutInfo,TEST,decode err =%v ===================",err)
	    continue
	}

	ac := dss.(*AcceptLockOutData)
	if ac == nil {
	    fmt.Println("================GetCurNodeLockOutInfo,TEST,decode err ===================")
	    continue
	}
	fmt.Println("================GetCurNodeLockOutInfo,TEST,ac.Account =%s,ac.Status =%s,ac =%v ===================",ac.Account,ac.Status,ac)
    }
    /////////////////


    lmvalue2 := SortCurNodeInfo(lmvalue)
    for _,v := range lmvalue2 {
	if v == nil {
	    continue
	}

	vv := v.([]byte)
	value := string(vv)
	fmt.Println("================GetCurNodeLockOutInfo,len(value) =%v ===================",len(value))
	////
	ds,err := UnCompress(value)
	if err != nil {
	    fmt.Println("================GetCurNodeLockOutInfo,uncompress err =%v ===================",err)
	    continue
	}

	dss,err := Decode2(ds,"AcceptLockOutData")
	if err != nil {
	    fmt.Println("================GetCurNodeLockOutInfo,decode err =%v ===================",err)
	    continue
	}

	ac := dss.(*AcceptLockOutData)
	if ac == nil {
	    fmt.Println("================GetCurNodeLockOutInfo,decode err ===================")
	    continue
	}
	fmt.Println("================GetCurNodeLockOutInfo,ac.Account =%s,ac.Status=%s,ac =%v ===================",ac.Account,ac.Status,ac)

	//nodesigs := make([]string,0)
	rk := Keccak256Hash([]byte(strings.ToLower(ac.DcrmFrom))).Hex()
	//da,exsit := LdbPubKeyData[rk]
	var da []byte
	datmp,exsit := LdbPubKeyData.ReadMap(rk)
	if exsit == false {
	    da2 := GetPubKeyDataValueFromDb(rk)
	    if da2 == nil {
		exsit = false
	    } else {
		exsit = true
		da = da2
	    }
	} else {
	    da = datmp.([]byte)
	}
	
	if exsit == true {
	    ss,err := UnCompress(string(da))
	    if err == nil {
		pubs,err := Decode2(ss,"PubKeyData")
		if err == nil {
		    pd := pubs.(*PubKeyData)
		    if pd != nil {
	//		nodesigs = pd.NodeSigs
		    }
		}
	    }
	}

	//if len(nodesigs) == 0 {
	//    continue
//	}

	//check := false
	eaccs := make([]EnAcc,0)
	////bug,check valid accepter
	/*for k,v := range nodesigs {
	    fmt.Println("=============GetCurNodeLockOutInfo,check accepter,index =%v=========================",k)
	    tx2 := new(types.Transaction)
	    vs := common.FromHex(v)
	    if err = rlp.DecodeBytes(vs, tx2); err != nil {
		continue
	    }

	    signer := types.NewEIP155Signer(big.NewInt(30400)) //
	    from2, err := types.Sender(signer, tx2)
	    if err != nil {
		signer = types.NewEIP155Signer(big.NewInt(4)) //
		from2, err = types.Sender(signer, tx2)
		if err != nil {
		    continue
		}
	    }
	    
	    eid := string(tx2.Data())
	    fmt.Println("===================GetCurNodeLockOutInfo,eid = %s,cur_enode =%s,from =%s,from2 =%s===============",eid,cur_enode,geter_acc,from2.Hex())
	    
	    accs := make([]string,0)
	    accs = append(accs,from2.Hex())
	    ea := EnAcc{Enode:eid,Accounts:accs}
	    eaccs = append(eaccs,ea)
	    
	    if strings.EqualFold(eid,cur_enode) && strings.EqualFold(geter_acc,from2.Hex()) {
		check = true
		//break
	    }
	}
	
	if check == false {
	   continue 
	}*/

	if ac.Deal == true || ac.Status == "Success" {
	    fmt.Println("===============GetCurNodeLockOutInfo,ac.Deal is true,nonce =%s===============",ac.Nonce)
	    continue
	}

	if ac.Status != "Pending" {
	    fmt.Println("===============GetCurNodeLockOutInfo,this is not pending,nonce =%s===============",ac.Nonce)
	    continue
	}

	key := Keccak256Hash([]byte(strings.ToLower(ac.Account + ":" + ac.GroupId + ":" + ac.Nonce + ":" + ac.DcrmFrom + ":" + ac.LimitNum))).Hex()
	
	los := &LockOutCurNodeInfo{Key:key,Account:ac.Account,GroupId:ac.GroupId,Nonce:ac.Nonce,DcrmFrom:ac.DcrmFrom,DcrmTo:ac.DcrmTo,Value:ac.Value,Cointype:ac.Cointype,LimitNum:ac.LimitNum,Mode:ac.Mode,GroupAccounts:eaccs}
	ret2,err := json.Marshal(los)
	fmt.Println("======================GetCurNodeLockOutInfo,succss get ret =%s,err =%v=================",string(ret2),err)

	ret = append(ret,string(ret2))
	////
    }

    ///////
    ss := strings.Join(ret,"|")
    //fmt.Println("===============GetCurNodeLockOutInfo,ret=%s===============",ss)
    return ss,"",nil
}

func GetAcceptReqAddrRes(account string,cointype string,groupid string,nonce string,threshold string,mode string) (string,bool) {
    key := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype + ":" + groupid + ":" + nonce + ":" + threshold + ":" + mode))).Hex()
    fmt.Println("===================!!!!GetAcceptReqAddrRes,acc =%s,cointype =%s,groupid =%s,nonce =%s,threshold =%s,mode =%s,key =%s!!!!============================",account,cointype,groupid,nonce,threshold,mode,key)
    var da []byte
    datmp,exsit := LdbReqAddr.ReadMap(key)
    if exsit == false {
	da2 := GetReqAddrValueFromDb(key)
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
    if exsit == false {
	fmt.Println("===================!!!!GetAcceptReqAddrRes,no exsit key =%s!!!!============================",key)
	return "dcrm back-end internal error:get accept result from db fail",false
    }

    ds,err := UnCompress(string(da))
    if err != nil {
	fmt.Println("===================!!!!GetAcceptReqAddrRes,uncompress fail, key =%s!!!!============================",key)
	return "dcrm back-end internal error:uncompress accept result fail",false
    }

    dss,err := Decode2(ds,"AcceptReqAddrData")
    if err != nil {
	fmt.Println("===================!!!!GetAcceptReqAddrRes,decode fail, key =%s!!!!============================",key)
	return "dcrm back-end internal error:decode accept result fail",false
    }

    ac := dss.(*AcceptReqAddrData)
    fmt.Println("===================!!!!GetAcceptReqAddrRes,ac.Accept =%s,key =%s!!!!============================",ac.Accept,key)

    var rp bool 
    if strings.EqualFold(ac.Accept,"false") {
	rp = false
    } else {
	rp = true
    }
    
    return "",rp
}

func GetAcceptLockOutRes(account string,groupid string,nonce string,dcrmfrom string,threshold string) (string,bool) {
    key := Keccak256Hash([]byte(strings.ToLower(account + ":" + groupid + ":" + nonce + ":" + dcrmfrom + ":" + threshold))).Hex()
    fmt.Println("===================!!!!GetAcceptLockOutRes,acc =%s,groupid =%s,nonce =%s,dcrmfrom =%s,threshold =%s,key =%s!!!!============================",account,groupid,nonce,dcrmfrom,threshold,key)
    var da []byte
    datmp,exsit := LdbLockOut.ReadMap(key)
    if exsit == false {
	da2 := GetLockOutValueFromDb(key)
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
    if exsit == false {
	fmt.Println("===================!!!!GetAcceptLockOutRes,no exsit key =%s!!!!============================",key)
	return "dcrm back-end internal error:get accept result from db fail",false
    }

    ds,err := UnCompress(string(da))
    if err != nil {
	fmt.Println("===================!!!!GetAcceptLockOutRes,uncompress fail, key =%s!!!!============================",key)
	return "dcrm back-end internal error:uncompress accept result fail",false
    }

    dss,err := Decode2(ds,"AcceptLockOutData")
    if err != nil {
	fmt.Println("===================!!!!GetAcceptLockOutRes,decode fail, key =%s!!!!============================",key)
	return "dcrm back-end internal error:decode accept result fail",false
    }

    ac := dss.(*AcceptLockOutData)
    fmt.Println("===================!!!!GetAcceptLockOutRes,ac.Accept =%s, key =%s!!!!============================",ac.Accept,key)

    var rp bool 
    if strings.EqualFold(ac.Accept,"false") {
	rp = false
    } else {
	rp = true
    }
    
    return "",rp
}

func AcceptReqAddr(account string,cointype string,groupid string,nonce string,threshold string,mode string,deal bool,accept string,status string,pubkey string,tip string,errinfo string,allreply string,workid int) (string,error) {
    key := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype + ":" + groupid + ":" + nonce + ":" + threshold + ":" + mode))).Hex()
    fmt.Println("=====================AcceptReqAddr,accept =%s,acc =%s,cointype =%s,groupid =%s,nonce =%s,threshold =%s,mode =%s,key =%s======================",accept,account,cointype,groupid,nonce,threshold,mode,key)
    //fmt.Println("=====================AcceptReqAddr,deal =%v,accept =%s,status =%s,key =%s======================",deal,accept,status,key)
    var da []byte
    datmp,exsit := LdbReqAddr.ReadMap(key)
    if exsit == false {
	da2 := GetReqAddrValueFromDb(key)
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
    if exsit == false {
	fmt.Println("=====================AcceptReqAddr,no exsit key =%s======================",key)
	return "dcrm back-end internal error:get accept data fail from db",fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
    }

    ds,err := UnCompress(string(da))
    if err != nil {
	fmt.Println("=====================AcceptReqAddr,uncompress fail, key =%s======================",key)
	return "dcrm back-end internal error:uncompress accept data fail",err
    }

    dss,err := Decode2(ds,"AcceptReqAddrData")
    if err != nil {
	fmt.Println("=====================AcceptReqAddr,decode fail, key =%s======================",key)
	return "dcrm back-end internal error:decode accept data fail",err
    }

    ac := dss.(*AcceptReqAddrData)
    //fmt.Println("=====================AcceptReqAddr,ac.Deal = %v,ac.Accept =%s,ac.Status =%s, key =%s======================",ac.Deal,ac.Accept,ac.Status,key)
    
    acp := ac.Accept
    if accept != "" {
	acp = accept
    }

    pk := ac.PubKey
    if pubkey != "" {
	pk = pubkey
    }

    ttip := ac.Tip
    if tip != "" {
	ttip = tip
    }

    eif := ac.Error
    if errinfo != "" {
	eif = errinfo
    }

    sts := ac.Status
    if status != "" {
	sts = status
    }

    arl := ac.AllReply
    if allreply != "" {
	arl = allreply
    }

    ac2:= &AcceptReqAddrData{Account:ac.Account,Cointype:ac.Cointype,GroupId:ac.GroupId,Nonce:ac.Nonce,LimitNum:ac.LimitNum,Mode:ac.Mode,NodeSigs:ac.NodeSigs,Deal:deal,Accept:acp,Status:sts,PubKey:pk,Tip:ttip,Error:eif,AllReply:arl,WorkId:ac.WorkId}
    
    e,err := Encode2(ac2)
    if err != nil {
	return "dcrm back-end internal error:encode accept data fail",err
    }

    es,err := Compress([]byte(e))
    if err != nil {
	return "dcrm back-end internal error:compress accept data fail",err
    }

    kdtmp := KeyData{Key:[]byte(key),Data:es}
    ReqAddrChan <-kdtmp

    fmt.Println("===============AcceptReqAddr,send key date to ReqAddrChan================")

    //LdbReqAddr[key] = []byte(es)
    LdbReqAddr.WriteMap(key,[]byte(es))
    
    if workid >= 0 && workid < len(workers) {
	wtmp := workers[workid]
	if wtmp != nil {
	    if len(wtmp.acceptReqAddrChan) == 0 {
		fmt.Println("===============AcceptReqAddr,reset wtmp.acceptReqAddrChan================")
		wtmp.acceptReqAddrChan <- "go on" 
	    }
	}
    }

    fmt.Println("===============AcceptReqAddr,end================")
    return "",nil
}

//if accept == "",don't set Accept
//if status == "",don't set Status
//if outhash == "",don't set OutHash
//if tip == "",don't set Tip
//if errinfo == "",don't set ErrInfo
//if allreply == "",don't set AllReply 
func AcceptLockOut(account string,groupid string,nonce string,dcrmfrom string,threshold string,deal bool,accept string,status string,outhash string,tip string,errinfo string,allreply string,workid int) (string,error) {
    key := Keccak256Hash([]byte(strings.ToLower(account + ":" + groupid + ":" + nonce + ":" + dcrmfrom + ":" + threshold))).Hex()
    fmt.Println("=====================AcceptLockOut,account =%s,groupid =%s,nonce =%s,dcrmfrom =%s,threshold =%s,key =%s======================",account,groupid,nonce,dcrmfrom,threshold,key)
    fmt.Println("=====================AcceptLockOut,deal =%v,accept =%s,status =%s,key =%s======================",deal,accept,status,key)
    var da []byte
    datmp,exsit := LdbLockOut.ReadMap(key)
    if exsit == false {
	da2 := GetLockOutValueFromDb(key)
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
    if exsit == false {
	fmt.Println("=====================AcceptLockOut,no exsit key =%s======================",key)
	return "dcrm back-end internal error:get accept data fail from db",fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
    }

    ds,err := UnCompress(string(da))
    if err != nil {
	fmt.Println("=====================AcceptLockOut,uncompress fail, key =%s======================",key)
	return "dcrm back-end internal error:uncompress accept data fail",err
    }

    dss,err := Decode2(ds,"AcceptLockOutData")
    if err != nil {
	fmt.Println("=====================AcceptLockOut,decode fail, key =%s======================",key)
	return "dcrm back-end internal error:decode accept data fail",err
    }

    ac := dss.(*AcceptLockOutData)
    fmt.Println("=====================AcceptLockOut,ac.Deal = %v,ac.Accept =%s,ac.Status =%s, key =%s======================",ac.Deal,ac.Accept,ac.Status,key)

    acp := ac.Accept
    if accept != "" {
	acp = accept
    }

    ah := ac.OutTxHash
    if outhash != "" {
	ah = outhash
    }

    ttip := ac.Tip
    if tip != "" {
	ttip = tip
    }

    eif := ac.Error
    if errinfo != "" {
	eif = errinfo
    }

    sts := ac.Status
    if status != "" {
	sts = status
    }

    arl := ac.AllReply
    if allreply != "" {
	arl = allreply
    }

    ac2 := &AcceptLockOutData{Account:ac.Account,GroupId:ac.GroupId,Nonce:ac.Nonce,DcrmFrom:ac.DcrmFrom,DcrmTo:ac.DcrmTo,Value:ac.Value,Cointype:ac.Cointype,LimitNum:ac.LimitNum,Mode:ac.Mode,Deal:deal,Accept:acp,Status:sts,OutTxHash:ah,Tip:ttip,Error:eif,AllReply:arl,WorkId:ac.WorkId}

    e,err := Encode2(ac2)
    if err != nil {
	return "dcrm back-end internal error:encode accept data fail",err
    }

    es,err := Compress([]byte(e))
    if err != nil {
	return "dcrm back-end internal error:compress accept data fail",err
    }

    kdtmp := KeyData{Key:[]byte(key),Data:es}
    LockOutChan <-kdtmp

    LdbLockOut.WriteMap(key,[]byte(es))
    
    if workid >= 0 && workid < len(workers) {
	wtmp := workers[workid]
	if wtmp != nil && len(wtmp.acceptLockOutChan) == 0 {
	    wtmp.acceptLockOutChan <- "go on" 
	}
    }

    return "",nil
}

type LockOutReply struct {
    Enode string
    Reply string
}

type LockOutReplys struct {
    Replys []LockOutReply
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

    ////
    msgdata,errdec := DecryptMsg(res) //for SendMsgToPeer
    if errdec == nil {
	res = msgdata
    }
    ////
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

	var wid int
	if strings.EqualFold(cur_enode,self.sender) { //self send
	    wid = rr.WorkId
	} else {
	    wid = workid
	    
	    //nonce check
	    if rr.MsgType == "rpc_lockout" {
		msgs := strings.Split(rr.Msg,":")
		//nonce check
		cur_nonce_str,_,err := GetLockOutNonce(msgs[0],msgs[4],msgs[1])
		if err != nil {
		    //TODO must set acceptlockout(.....)
		    res2 := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get lockout nonce fail in RecvMsg.Run",Err:fmt.Errorf("get lockout nonce fail in recvmsg.run")}
		    ch <- res2
		    return false
		}

		if strings.EqualFold(msgs[6],cur_nonce_str) == false {
		    //TODO must set acceptlockout(.....)
		    res2 := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:lockout tx nonce error",Err:fmt.Errorf("lockout tx nonce error")}
		    ch <- res2
		    return false
		}
		//
		
		_,err = SetLockOutNonce(msgs[0],msgs[4],msgs[1],msgs[6])
		if err != nil {
		    //TODO must set acceptlockout(.....)
		    res2 := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:set lockout nonce fail in RecvMsg.Run",Err:fmt.Errorf("set lockout nonce fail in recvmsg.run")}
		    ch <- res2
		    return false
		}
		////
	    }
	}

	//rpc_lockout
	if rr.MsgType == "rpc_lockout" {
	    w := workers[workid]
	    w.sid = rr.Nonce
	    //msg = fusionaccount:dcrmaddr:dcrmto:value:cointype:groupid:nonce:threshold:mode
	    msg := rr.Msg
	    msgs := strings.Split(msg,":")
	    w.groupid = msgs[5] 
	    w.limitnum = msgs[7]
	    
	    fmt.Println("==============RecvMsg.Run,lockout,groupid =%s,get mode =%s=================",msgs[5],msgs[8])

	    ////bug
	    if msgs[8] == "0" {// self-group
		ac := &AcceptLockOutData{Account:msgs[0],GroupId:msgs[5],Nonce:msgs[6],DcrmFrom:msgs[1],DcrmTo:msgs[2],Value:msgs[3],Cointype:msgs[4],LimitNum:msgs[7],Mode:msgs[8],Deal:false,Accept:"false",Status:"Pending",OutTxHash:"",Tip:"",Error:"",AllReply:"",WorkId:wid}
		fmt.Println("===================call SaveAcceptLockOutData,workid =%s,acc =%s,groupid =%s,nonce =%s,dcrmfrom =%s,dcrmto =%s,value =%s,cointype =%s,threshold =%s,mode =%s =====================",wid,msgs[0],msgs[5],msgs[6],msgs[1],msgs[2],msgs[3],msgs[4],msgs[7],msgs[8])
		err := SaveAcceptLockOutData(ac)
		if err != nil {
		    fmt.Println("===================call SaveAcceptLockOutData,err =%v =====================",err)
		}

	        ////
	        var reply bool
	        var tip string
	        timeout := make(chan bool, 1)
	        go func(wid int) {
		    GetEnodesInfo(msgs[5]) //bug
		    fmt.Println("==============RecvMsg.Run,lockout,111111,cur_enode =%s==================",cur_enode)
                    agreeWaitTime := 10 * time.Minute
                    agreeWaitTimeOut := time.NewTicker(agreeWaitTime)

		    wtmp2 := workers[wid]

                    for {
                       select {
                       case account := <-wtmp2.acceptLockOutChan:
                           tip,reply = GetAcceptLockOutRes(msgs[0],msgs[5],msgs[6],msgs[1],msgs[7])
                           fmt.Printf("============ (self *RecvMsg) Run() ===========, Current Node Accept lockout Res =%v,account =%s =========== %v\n", reply,account)

			   ///////
			    fmt.Println("==============RecvMsg.Run,lockout,22222,cur_enode =%s==================",cur_enode)
			    mp := []string{w.sid,cur_enode}
			    enode := strings.Join(mp,"-")
			    s0 := "AcceptLockOutRes"
			    var lo_res string
			    if reply == false {
				lo_res = "false"
			    } else {
				lo_res = "true"
			    }
			    s1 := lo_res
			    ss := enode + Sep + s0 + Sep + s1
			    logs.Debug("================RecvMsg.Run,send msg,code is AcceptLockOutRes==================")
			    SendMsgToDcrmGroup(ss,w.groupid)
			    _,tip,err = GetChannelValue(ch_t,w.bacceptlockoutres)
			    if err != nil {
				fmt.Println("================RecvMsg.Run,get accept lockout result err =%v ==================",err)
				AcceptLockOut(msgs[0],msgs[5],msgs[6],msgs[1],msgs[7],false,"false","Timeout","","get other node accept lockout result timeout","get other node accept lockout result timeout","",wid)
				tip = "get other node accept lockout result timeout"
				reply = false
			       timeout <- true
			       return
			    }
			    
			    if w.msg_acceptlockoutres.Len() != (NodeCnt-1) {
				fmt.Println("================RecvMsg.Run,get accept lockout result fail ==================")
				AcceptLockOut(msgs[0],msgs[5],msgs[6],msgs[1],msgs[7],false,"false","Failure","","get other node accept lockout result fail","get other node accept lockout result fail","",wid)
				tip = "dcrm back-end internal error:get accepte lockout result fail."
				reply = false
			       timeout <- true
			       return
			    }
			   
			    rs := make([]LockOutReply,0)
			    cur := LockOutReply{Enode:cur_enode,Reply:lo_res}
			    rs = append(rs,cur)
			    iter := w.msg_acceptlockoutres.Front()
			    for iter != nil {
				mdss := iter.Value.(string)
				ms := strings.Split(mdss,Sep)
				prexs := strings.Split(ms[0],"-")
				node := prexs[1]
				fmt.Println("==============RecvMsg.Run,lockout,333333,get enode =%s==================",node)
				if strings.EqualFold(ms[2],"false") {
				    reply = false
				}
				cur2 := LockOutReply{Enode:node,Reply:ms[2]}
				rs = append(rs,cur2)
				iter = iter.Next()
			    }

			    lors := &LockOutReplys{Replys:rs}
			    all,err := json.Marshal(lors)
			    fmt.Println("===============RecvMsg.Run,all accept lockout result =%s,err =%v ================",string(all),err)
			    if reply == false {
				tip = "don't accept lockout"
				AcceptLockOut(msgs[0],msgs[5],msgs[6],msgs[1],msgs[7],false,"false","Failure","","don't accept lockout","don't accept lockout",string(all),wid) 
			    } else {
				tip = ""
				AcceptLockOut(msgs[0],msgs[5],msgs[6],msgs[1],msgs[7],false,"true","Pending","","","",string(all),wid) 
			    }

			   ///////
                           timeout <- true
	                   return
                       case <-agreeWaitTimeOut.C:
                           fmt.Printf("==== (self *RecvMsg) Run() ====, timerout %v\n", agreeWaitTime)
			   //bug: if self not accept and timeout
			    AcceptLockOut(msgs[0],msgs[5],msgs[6],msgs[1],msgs[7],false,"false","Timeout","","get other node accept lockout result timeout","get other node accept lockout result timeout","",wid)
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

	        fmt.Println("===============RecvMsg.Run,the terminal accept lockout result =%v, ================",reply)
	        if reply == false {
		    //////////////////////lockout result start/////////////////////////
		    fmt.Println("==============!!!rpc lockout error return!!!=====================")
		    if tip == "get other node accept lockout result timeout" {
			AcceptLockOut(msgs[0],msgs[5],msgs[6],msgs[1],msgs[7],false,"","Timeout","","get other node accept lockout result timeout","get other node accept lockout result timeout","",wid) 
		    } else {
			/////////////TODO tmp
			//sid-enode:SendLockOutRes:Success:lockout_tx_hash
			//sid-enode:SendLockOutRes:Fail:err
			mp := []string{w.sid,cur_enode}
			enode := strings.Join(mp,"-")
			s0 := "SendLockOutRes"
			s1 := "Fail"
			s2 := "don't accept lockout."
			ss := enode + Sep + s0 + Sep + s1 + Sep + s2
			logs.Debug("================RecvMsg.Run,send msg,code is SendLockOutRes==================")
			SendMsgToDcrmGroup(ss,w.groupid)
			_,_,err := GetChannelValue(ch_t,w.bsendlockoutres)
			if err != nil {
			    fmt.Println("================RecvMsg,send lockout result err =%v ==================",err)
			    
			    tip = "get other node terminal accept lockout result timeout" ////bug

			    AcceptLockOut(msgs[0],msgs[5],msgs[6],msgs[1],msgs[7],false,"","Timeout","",tip,tip,"",wid) 
			} else if w.msg_sendlockoutres.Len() != (NodeCnt-1) {
			    fmt.Println("================RecvMsg,send lockout result fail ==================")
			    AcceptLockOut(msgs[0],msgs[5],msgs[6],msgs[1],msgs[7],false,"","Failure","","get other node lockout result fail","get other node lockout result fail","",wid)
			} else {
			    reply2 := "false"
			    lohash := ""
			    iter := w.msg_sendlockoutres.Front()
			    for iter != nil {
				mdss := iter.Value.(string)
				ms := strings.Split(mdss,Sep)
				//prexs := strings.Split(ms[0],"-")
				//node := prexs[1]
				if strings.EqualFold(ms[2],"Success") {
				    reply2 = "true"
				    lohash = ms[3]
				    break
				}

				lohash = ms[3]
				iter = iter.Next()
			    }

			    if reply2 == "true" {
				fmt.Println("================RecvMsg,the terminal lockout res is success. nonce =%s ==================",msgs[6])
				AcceptLockOut(msgs[0],msgs[5],msgs[6],msgs[1],msgs[7],true,"true","Success",lohash," "," ","",wid)
			    } else {
				fmt.Println("================RecvMsg,the terminal lockout res is fail. nonce =%s ==================",msgs[6])
				AcceptLockOut(msgs[0],msgs[5],msgs[6],msgs[1],msgs[7],false,"","Failure","",lohash,lohash,"",wid)
			    }
			}
			/////////////////////
		    }
		    ///////////////////////lockout result end////////////////////////
	            
		    res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType,Tip:tip,Err:fmt.Errorf("don't accept lockout.")}
	           ch <- res2
	           return false
	        }
	    } else {
		if len(workers[wid].acceptWaitLockOutChan) == 0 {
		    workers[wid].acceptWaitLockOutChan <- "go on" 
		}
	    }

	    rch := make(chan interface{},1)
	    //msg = fusionaccount:dcrmaddr:dcrmto:value:cointype:groupid:nonce:threshold:mode
	    fmt.Println("===============RecvMsg.Run,value =%s,cointype =%s================",msgs[3],msgs[4])
	    validate_lockout(w.sid,msgs[0],msgs[1],msgs[4],msgs[3],msgs[2],msgs[6],rch)
	    chret,tip,cherr := GetChannelValue(ch_t,rch)
	    if chret != "" {
		fmt.Println("==============RecvMsg.Run,Get LockOut Result.TxHash = %s =================",chret)
		res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType+Sep+chret,Tip:"",Err:nil}
		ch <- res2
		return true
	    }

	    //////////////////////lockout result start/////////////////////////
	    fmt.Println("==============!!!rpc lockout error return!!!=====================")
	    if tip == "get other node accept lockout result timeout" {
		AcceptLockOut(msgs[0],msgs[5],msgs[6],msgs[1],msgs[7],false,"","Timeout","",tip,cherr.Error(),"",wid) 
	    } else {
		/////////////TODO tmp
		//sid-enode:SendLockOutRes:Success:lockout_tx_hash
		//sid-enode:SendLockOutRes:Fail:err
		mp := []string{w.sid,cur_enode}
		enode := strings.Join(mp,"-")
		s0 := "SendLockOutRes"
		s1 := "Fail"
		s2 := cherr.Error()
		ss := enode + Sep + s0 + Sep + s1 + Sep + s2
		logs.Debug("================RecvMsg.Run,send msg,code is SendLockOutRes==================")
		SendMsgToDcrmGroup(ss,w.groupid)
		_,_,err := GetChannelValue(ch_t,w.bsendlockoutres)
		if err != nil {
		    fmt.Println("================RecvMsg,send lockout result err =%v ==================",err)
		    
		    tip = "get other node terminal accept lockout result timeout" ////bug

		    AcceptLockOut(msgs[0],msgs[5],msgs[6],msgs[1],msgs[7],false,"","Timeout","",tip,tip,"",wid) 
		} else if w.msg_sendlockoutres.Len() != (NodeCnt-1) {
		    fmt.Println("================RecvMsg,send lockout result fail ==================")
		    AcceptLockOut(msgs[0],msgs[5],msgs[6],msgs[1],msgs[7],false,"","Failure","","get other node lockout result fail","get other node lockout result fail","",wid)
		} else {
		    reply2 := "false"
		    lohash := ""
		    iter := w.msg_sendlockoutres.Front()
		    for iter != nil {
			mdss := iter.Value.(string)
			ms := strings.Split(mdss,Sep)
			//prexs := strings.Split(ms[0],"-")
			//node := prexs[1]
			if strings.EqualFold(ms[2],"Success") {
			    reply2 = "true"
			    lohash = ms[3]
			    break
			}

			lohash = ms[3]
			iter = iter.Next()
		    }

		    if reply2 == "true" {
			fmt.Println("================RecvMsg,the terminal lockout res is success. nonce =%s ==================",msgs[6])
			AcceptLockOut(msgs[0],msgs[5],msgs[6],msgs[1],msgs[7],true,"true","Success",lohash," "," ","",wid)
		    } else {
			fmt.Println("================RecvMsg,the terminal lockout res is fail. nonce =%s ==================",msgs[6])
			AcceptLockOut(msgs[0],msgs[5],msgs[6],msgs[1],msgs[7],false,"","Failure","",lohash,lohash,"",wid)
		    }
		}
		/////////////////////
	    }
	    ///////////////////////lockout result end////////////////////////

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
	    //msg = account:cointype:groupid:nonce:threshold:mode:tx1:tx2:tx3...txn
	    rch := make(chan interface{},1)
	    w := workers[workid]
	    w.sid = rr.Nonce

	    msgs := strings.Split(rr.Msg,":")
	    if len(msgs) < 6 {
		AcceptReqAddr(msgs[0],msgs[1],msgs[2],msgs[3],msgs[4],msgs[5],false,"","Failure","","dcrm back-end internal error:parameter error in req addr","get msg error.","",wid)
		res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType,Tip:"dcrm back-end internal error:parameter error in req addr",Err:fmt.Errorf("get msg error.")}
		ch <- res2
		return false
	    }
	    
	    w.groupid = msgs[2]
	    w.limitnum = msgs[4]
	    
	    if msgs[5] == "0" {// self-group
		nodesigs := make([]string,0)
		//nums := strings.Split(msgs[4],"/")
		//nodecnt,_ := strconv.Atoi(nums[1])
		//for j:=0;j<nodecnt;j++ {
		//    nodesigs = append(nodesigs,msgs[6+j])
		//}
		//fmt.Println("============RecvMsg.Run,len(msgs)=%v,nums=%s,nodecnt =%v=================",len(msgs),nums,nodecnt)

		ac := &AcceptReqAddrData{Account:msgs[0],Cointype:"ALL",GroupId:msgs[2],Nonce:msgs[3],LimitNum:msgs[4],Mode:msgs[5],NodeSigs:nodesigs,Deal:false,Accept:"false",Status:"Pending",PubKey:"",Tip:"",Error:"",AllReply:"",WorkId:wid}
		fmt.Println("===================call SaveAcceptReqAddrData,workid =%s,acc =%s,cointype =%s,groupid =%s,nonce =%s,threshold =%s,mode =%s =====================",wid,msgs[0],msgs[1],msgs[2],msgs[3],msgs[4],msgs[5])
		err := SaveAcceptReqAddrData(ac)
		if err != nil {
		    fmt.Println("===================call SaveAcceptReqAddrData,err =%v =====================",err)
		}

	        ////
	        var reply bool
	        var tip string
	        timeout := make(chan bool, 1)
	        go func(wid int) {
		    GetEnodesInfo(msgs[2]) //bug
		    //fmt.Println("==============RecvMsg.Run,req addr,111111,cur_enode =%s==================",cur_enode)
                    agreeWaitTime := 10 * time.Minute
                    agreeWaitTimeOut := time.NewTicker(agreeWaitTime)
		    if wid < 0 || wid >= len(workers) || workers[wid] == nil {
			AcceptReqAddr(msgs[0],msgs[1],msgs[2],msgs[3],msgs[4],msgs[5],false,"false","Failure","","workid error","workid error","",wid)
			tip = "worker id error"
			reply = false
		       timeout <- true
		       return
		    }

		    wtmp2 := workers[wid]

                    for {
                       select {
                       case account := <-wtmp2.acceptReqAddrChan:
                           tip,reply = GetAcceptReqAddrRes(msgs[0],msgs[1],msgs[2],msgs[3],msgs[4],msgs[5])
                           fmt.Printf("============ (self *RecvMsg) Run() ===========, Current Node Accept req addr Res =%v,account =%s =========== %v\n", reply,account)

			   ///////
			    //fmt.Println("==============RecvMsg.Run,req addr,22222,cur_enode =%s==================",cur_enode)
			    mp := []string{w.sid,cur_enode}
			    enode := strings.Join(mp,"-")
			    s0 := "AcceptReqAddrRes"
			    var req_res string
			    if reply == false {
				req_res = "false"
			    } else {
				req_res = "true"
			    }

			    s1 := req_res
			    ss := enode + Sep + s0 + Sep + s1
			    SendMsgToDcrmGroup(ss,w.groupid)
			    _,tip,err = GetChannelValue(ch_t,w.bacceptreqaddrres)
			    if err != nil {
				fmt.Println("================RecvMsg.Run,get accept req addr result err =%v ==================",err)
				AcceptReqAddr(msgs[0],msgs[1],msgs[2],msgs[3],msgs[4],msgs[5],false,"false","Timeout","","get other node accept req addr result timeout","get other node accept req addr result timeout","",wid)
				tip = "get other node accept req addr result timeout"
				reply = false
			       timeout <- true
			       return
			    }
			    
			    if w.msg_acceptreqaddrres.Len() != (NodeCnt-1) {
				fmt.Println("================RecvMsg.Run,get accept req addr result fail ==================")
				AcceptReqAddr(msgs[0],msgs[1],msgs[2],msgs[3],msgs[4],msgs[5],false,"false","Failure","","get other node accept req addr result fail","get other node accept req addr result fail","",wid)
				tip = "dcrm back-end internal error:get accepte req addr result fail."
				reply = false
			       timeout <- true
			       return
			    }
			   
			    all := "{"
			    all += "\""
			    all += cur_enode
			    all += "\""
			    all += ":"
			    all += "\""
			    all += req_res
			    all += "\""
			    all += ","
			    iter := w.msg_acceptreqaddrres.Front()
			    for iter != nil {
				mdss := iter.Value.(string)
				ms := strings.Split(mdss,Sep)
				prexs := strings.Split(ms[0],"-")
				node := prexs[1]
				//fmt.Println("==============RecvMsg.Run,req addr,333333,get enode =%s==================",node)
				if strings.EqualFold(ms[2],"false") {
				    reply = false
				}
				all += "\""
				all += node
				all += "\""
				all += ":"
				all += "\""
				all += ms[2] 
				all += "\""
				if iter.Next() != nil {
				    all += ","
				}
				iter = iter.Next()
			    }
			    all += "}"
			    
			    fmt.Println("===============RecvMsg.Run,all accept req addr result =%s, ================",all)
			    if reply == false {
				tip = "don't accept req addr"
				AcceptReqAddr(msgs[0],msgs[1],msgs[2],msgs[3],msgs[4],msgs[5],false,"false","Failure","","don't accept req addr","don't accept req addr",all,wid) 
			    } else {
				tip = ""
				AcceptReqAddr(msgs[0],msgs[1],msgs[2],msgs[3],msgs[4],msgs[5],false,"true","Pending","","","",all,wid) 
			    }

			   ///////
                           timeout <- true
			   fmt.Println("=========================!!!!!!get all accept result,it is true,so set timeout!!!!!!=================")
	                   return
                       case <-agreeWaitTimeOut.C:
                           fmt.Printf("==== (self *RecvMsg) Run() ====, timerout %v\n", agreeWaitTime)
			   //bug: if self not accept and timeout
			    AcceptReqAddr(msgs[0],msgs[1],msgs[2],msgs[3],msgs[4],msgs[5],false,"false","Timeout","","get other node accept req addr result timeout","get other node accept req addr result timeout","",wid)
			    tip = "get other node accept req addr result timeout"
			    reply = false
			    //

                           timeout <- true
                           return
                       }
                   }
	        }(wid)

		if len(workers[wid].acceptWaitReqAddrChan) == 0 {
		    workers[wid].acceptWaitReqAddrChan <- "go on"
		}

	        fmt.Println("===============RecvMsg.Run,reset w.acceptWaitReqAddrChan========================")
	        <-timeout

	        fmt.Println("===============RecvMsg.Run,the terminal accept req addr result =%v, ================",reply)
	        if reply == false {
		    if tip == "get other node accept req addr result timeout" {
			AcceptReqAddr(msgs[0],msgs[1],msgs[2],msgs[3],msgs[4],msgs[5],false,"","Timeout","",tip,"don't accept req addr.","",wid)
		    } else {
			AcceptReqAddr(msgs[0],msgs[1],msgs[2],msgs[3],msgs[4],msgs[5],false,"","Failure","",tip,"don't accept req addr.","",wid)
		    }

	            res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType,Tip:tip,Err:fmt.Errorf("don't accept req addr.")}
	           ch <- res2
	           return false
	        }
	    } else {
		if len(workers[wid].acceptWaitReqAddrChan) == 0 {
		    workers[wid].acceptWaitReqAddrChan <- "go on"
		}
	    }

	    dcrm_genPubKey(w.sid,msgs[0],msgs[1],rch, msgs[5],msgs[3])
	    chret,tip,cherr := GetChannelValue(ch_t,rch)
	    if cherr != nil {
		AcceptReqAddr(msgs[0],msgs[1],msgs[2],msgs[3],msgs[4],msgs[5],false,"","Failure","",tip,cherr.Error(),"",wid)
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
    GroupId string
    LimitNum string
    Mode string
    NodeSigs []string
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

	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)

	err1 := enc.Encode(ch)
	if err1 != nil {
	    return "",err1
	}
	return buff.String(),nil
    case *AcceptLockOutData:
	ch := obj.(*AcceptLockOutData)

	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)

	err1 := enc.Encode(ch)
	if err1 != nil {
	    return "",err1
	}
	return buff.String(),nil
    case *AcceptReqAddrData:
	ch := obj.(*AcceptReqAddrData)
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
	var data bytes.Buffer
	data.Write([]byte(s))
	
	dec := gob.NewDecoder(&data)

	var res  AcceptLockOutData 
	err := dec.Decode(&res)
	if err != nil {
	    return nil,err
	}

	return &res,nil
    }
    
    if datatype == "AcceptReqAddrData" {
	var m AcceptReqAddrData
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
    Nonce string
    LimitNum string
    Mode string
    NodeSigs []string
}

func (self *ReqAddrSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 || workid >= RpcMaxWorker {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:no worker id",Err:GetRetErr(ErrGetWorkerIdError)}
	ch <- res
	return false
    }

    GetEnodesInfo(self.GroupId)
    msg := self.Account + ":" + self.Cointype + ":" + self.GroupId + ":" + self.Nonce + ":" + self.LimitNum + ":" + self.Mode
    //for k,v := range self.NodeSigs {
//	fmt.Println("===========ReqAddrSendMsgToDcrm.Run,get node sigs,index=%v===========",k)
//	msg += ":"
//	msg += v
  //  }

    timestamp := time.Now().Unix()
    tt := strconv.Itoa(int(timestamp))
    nonce := Keccak256Hash([]byte(msg + ":" + tt + ":" + strconv.Itoa(workid))).Hex()
    
    sm := &SendMsg{MsgType:"rpc_req_dcrmaddr",Nonce:nonce,WorkId:workid,Msg:msg}
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

    w := workers[workid]

    for i:=0;i<ReSendTimes;i++ {
	SendToGroupAllNodes(self.GroupId,res)
	time.Sleep(time.Duration(2)*time.Second) //1000 == 1s
    }
    /*if err != nil {
	fmt.Println("=============ReqAddrSendMsgToMsg.Run,send to group all nodes,err =%v ===========",err)
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:send data to group fail in req addr",Err:GetRetErr(ErrSendDataToGroupFail)}
	ch <- res
	return false
    }*/

    fmt.Println("=============ReqAddrSendMsgToMsg.Run,Waiting For Result===========")
    <-w.acceptWaitReqAddrChan
    time.Sleep(time.Duration(1) * time.Second)
    AcceptReqAddr(self.Account,self.Cointype,self.GroupId,self.Nonce,self.LimitNum,self.Mode,false,"true","Pending","","","","",workid)

    chret,tip,cherr := GetChannelValue(sendtogroup_timeout,w.ch)
    fmt.Println("========ReqAddrSendMsgToDcrm.Run,Get Result = %s, err = %v ============",chret,cherr)
    if cherr != nil {
	res2 := RpcDcrmRes{Ret:chret,Tip:tip,Err:cherr}
	ch <- res2
	return false
    }

    res2 := RpcDcrmRes{Ret:chret,Tip:tip,Err:cherr}
    ch <- res2

    return true
}

//msg = fusionaccount:dcrmaddr:dcrmto:value:cointype:groupid:nonce:threshold
type LockOutSendMsgToDcrm struct {
    Account string
    DcrmFrom string
    DcrmTo string
    Value string
    Cointype string
    GroupId string
    Nonce string
    LimitNum string
    Mode string
}

func (self *LockOutSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 || workid >= RpcMaxWorker {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get worker id error",Err:GetRetErr(ErrGetWorkerIdError)}
	ch <- res
	return false
    }

    fmt.Println("==================LockOutSendMsgToDcrm.Run,self.Value = %s,self.Cointype =%s===================",self.Value,self.Cointype)
    GetEnodesInfo(self.GroupId)
    msg := self.Account + ":" + self.DcrmFrom + ":" + self.DcrmTo + ":" + self.Value + ":" + self.Cointype + ":" + self.GroupId + ":" + self.Nonce + ":" + self.LimitNum + ":" + self.Mode
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

    for i:=0;i<ReSendTimes;i++ {
	SendToGroupAllNodes(self.GroupId,res)
	time.Sleep(time.Duration(2)*time.Second) //1000 == 1s
    }
    /*_,err = SendToGroupAllNodes(self.GroupId,res)
    if err != nil {
	fmt.Println("=============LockOutSendMsgToDcrm.Run,send to group all nodes,err =%v ===========",err)
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:send data to group fail",Err:GetRetErr(ErrSendDataToGroupFail)}
	ch <- res
	return false
    }*/

    w := workers[workid]
    ////
    fmt.Println("=============LockOutSendMsgToDcrm.Run,Waiting For Result===========")
    <-w.acceptWaitLockOutChan
    var tip string
    time.Sleep(time.Duration(1) * time.Second)
    AcceptLockOut(self.Account,self.GroupId,self.Nonce,self.DcrmFrom,self.LimitNum,false,"true","Pending","","","","",workid)

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

type GetCurNodeReqAddrInfoSendMsgToDcrm struct {
    Account string  //geter_acc
}

func (self *GetCurNodeReqAddrInfoSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    //fmt.Println("==============GetCurNodeReqAddrInfoSendMsgToDcrm.Run,workid =%v=================",workid)
    if workid < 0 || workid >= RpcMaxWorker {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get worker id fail",Err:GetRetErr(ErrGetWorkerIdError)}
	ch <- res
	return false
    }

    ret,tip,err := GetCurNodeReqAddrInfo(self.Account)
    if err != nil {
	res2 := RpcDcrmRes{Ret:"",Tip:tip,Err:err}
	ch <- res2
	return false
    }

    res2 := RpcDcrmRes{Ret:ret,Tip:"",Err:nil}
    ch <- res2

    return true
}

type GetCurNodeLockOutInfoSendMsgToDcrm struct {
    Account string   //geter_acc
}

func (self *GetCurNodeLockOutInfoSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    //fmt.Println("==============GetCurNodeLockOutInfoSendMsgToDcrm.Run,workid =%v=================",workid)
    if workid < 0 || workid >= RpcMaxWorker {
	res := RpcDcrmRes{Ret:"",Tip:"dcrm back-end internal error:get worker id fail",Err:GetRetErr(ErrGetWorkerIdError)}
	ch <- res
	return false
    }

    ret,tip,err := GetCurNodeLockOutInfo(self.Account)
    if err != nil {
	res2 := RpcDcrmRes{Ret:"",Tip:tip,Err:err}
	ch <- res2
	return false
    }

    res2 := RpcDcrmRes{Ret:ret,Tip:"",Err:nil}
    ch <- res2

    return true
}

type AcceptReqAddrData struct {
    Account string
    Cointype string
    GroupId string
    Nonce string
    LimitNum string
    Mode string
    NodeSigs []string

    Deal bool
    Accept string 
   
    Status string
    PubKey string
    Tip string
    Error string

    AllReply string

    WorkId int
}

func SaveAcceptReqAddrData(ac *AcceptReqAddrData) error {
    if ac == nil {
	return fmt.Errorf("no accept data.")
    }

    key := Keccak256Hash([]byte(strings.ToLower(ac.Account + ":" + ac.Cointype + ":" + ac.GroupId + ":" + ac.Nonce + ":" + ac.LimitNum + ":" + ac.Mode))).Hex()
    fmt.Println("================SaveAcceptReqAddrData,acc =%s,cointype =%s,groupid =%s,nonce =%s,threshold =%s,mode =%s ===================",ac.Account,ac.Cointype,ac.GroupId,ac.Nonce,ac.LimitNum,ac.Mode)
    
    alos,err := Encode2(ac)
    if err != nil {
	return err
    }
    
    ss,err := Compress([]byte(alos))
    if err != nil {
	return err 
    }
   
    fmt.Println("==============SaveAcceptReqAddrData,success write into map,key =%s=================",key)
    kdtmp := KeyData{Key:[]byte(key),Data:ss}
    ReqAddrChan <-kdtmp

    //LdbReqAddr[key] = []byte(ss)
    LdbReqAddr.WriteMap(key,[]byte(ss))
    return nil
}

type AcceptLockOutData struct {
    Account string
    GroupId string
    Nonce string
    DcrmFrom string
    DcrmTo string
    Value string
    Cointype string
    LimitNum string
    Mode string

    Deal bool
    Accept string 
   
    Status string
    OutTxHash string
    Tip string
    Error string

    AllReply string
    WorkId int
}

func SaveAcceptLockOutData(ac *AcceptLockOutData) error {
    if ac == nil {
	return fmt.Errorf("no accept data.")
    }

    key := Keccak256Hash([]byte(strings.ToLower(ac.Account + ":" + ac.GroupId + ":" + ac.Nonce + ":" + ac.DcrmFrom + ":" + ac.LimitNum))).Hex()
    
    alos,err := Encode2(ac)
    if err != nil {
	return err
    }
    
    ss,err := Compress([]byte(alos))
    if err != nil {
	return err 
    }
  
    kdtmp := KeyData{Key:[]byte(key),Data:ss}
    LockOutChan <-kdtmp

    LdbLockOut.WriteMap(key,[]byte(ss))
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

func GetEnodesInfo(GroupId string) {
    if GroupId == "" {
	return
    }
    
    Enode_cnts,_ = GetGroup(GroupId)
    NodeCnt = Enode_cnts
    ThresHold = Enode_cnts
    cur_enode = GetSelfEnode()
}

func CommitRpcReq() {
    for {
	select {
	case req := <-RpcReqQueueCache:
	    RpcReqQueue <- req
	}
	
	time.Sleep(time.Duration(1000000000))  //na, 1 s = 10e9 na /////////!!!!!fix bug:if large sign at same time,it will very slowly!!!!!
    }
}

func SendReqToGroup(msg string,rpctype string) (string,string,error) {
    var req RpcReq
    switch rpctype {
	case "rpc_req_dcrmaddr":
	    //msg = account : cointype : groupid : nonce: threshold : mode : tx1 : tx2 ... : txn
	    msgs := strings.Split(msg,":")
	    sigs := make([]string,0)
	    nums := strings.Split(msgs[4],"/")
	    nodecnt,_ := strconv.Atoi(nums[1])
	    for j:=0;j<nodecnt;j++ {
		sigs = append(sigs,msgs[6+j])
	    }
	    fmt.Println("==========SendReqToGroup,len(msgs)=%v,nums=%s,nodecnt=%v========================",len(msgs),nums,nodecnt)

	    v := ReqAddrSendMsgToDcrm{Account:msgs[0],Cointype:msgs[1],GroupId:msgs[2],Nonce:msgs[3],LimitNum:msgs[4], Mode:msgs[5],NodeSigs:sigs}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	    break
	case "rpc_lockout":
	    //msg = fusionaccount:dcrmaddr:dcrmto:value:cointype:groupid:nonce:threshold:mode
	    m := strings.Split(msg,":")
	    fmt.Println("=============SendReqToGroup,type is rpc_lockout,value =%s,cointype =%s==============",m[3],m[4])
	    v := LockOutSendMsgToDcrm{Account:m[0],DcrmFrom:m[1],DcrmTo:m[2],Value:m[3],Cointype:m[4],GroupId:m[5],Nonce:m[6],LimitNum:m[7],Mode:m[8]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	    break
	case "rpc_get_cur_node_lockout_info":
	    //fmt.Println("=============SendReqToGroup,type is rpc_get_cur_node_lockout_info==============")
	    v := GetCurNodeLockOutInfoSendMsgToDcrm{Account:msg}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	    break
	case "rpc_get_cur_node_reqaddr_info":
	    //fmt.Println("=============SendReqToGroup,type is rpc_get_cur_node_reqaddr_info==============")
	    v := GetCurNodeReqAddrInfoSendMsgToDcrm{Account:msg}
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

    //RpcReqQueue <- req
    RpcReqQueueCache <- req
    chret,tip,cherr := GetChannelValue(t,req.ch)
    if cherr != nil {
	return chret,tip,cherr
    }

    return chret,"",nil
}

func GetChannelValue(t int,obj interface{}) (string,string,error) {
    timeout := make(chan bool, 1)
    go func() {
	 time.Sleep(time.Duration(t)*time.Second) //1000 == 1s
	 timeout <- true
     }()

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

func Find(l *list.List,msg string) bool {
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

	if strings.EqualFold(s,msg) {
	    return true
	}
    }

    return false
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
	case "AcceptReqAddrRes":
	    ///bug
	    if w.msg_acceptreqaddrres.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    if Find(w.msg_acceptreqaddrres,msg) {
		return
	    }

	    w.msg_acceptreqaddrres.PushBack(msg)
	    if w.msg_acceptreqaddrres.Len() == (NodeCnt-1) {
		fmt.Println("=========Get All AcceptReqAddrRes===========","GroupId",w.groupid)
		w.bacceptreqaddrres <- true
	    }
	case "AcceptLockOutRes":
	    ///bug
	    if w.msg_acceptlockoutres.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    if Find(w.msg_acceptlockoutres,msg) {
		return
	    }

	    w.msg_acceptlockoutres.PushBack(msg)
	    if w.msg_acceptlockoutres.Len() == (NodeCnt-1) {
		fmt.Println("=========Get All AcceptLockOutRes===========","GroupId",w.groupid)
		w.bacceptlockoutres <- true
	    }
	case "SendLockOutRes":
	    ///bug
	    if w.msg_sendlockoutres.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    if Find(w.msg_sendlockoutres,msg) {
		return
	    }

	    w.msg_sendlockoutres.PushBack(msg)
	    if w.msg_sendlockoutres.Len() == (NodeCnt-1) {
		fmt.Println("=========Get All SendLockOutRes===========","GroupId",w.groupid)
		w.bsendlockoutres <- true
	    }
	case "C1":
	    ///bug
	    if w.msg_c1.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    if Find(w.msg_c1,msg) {
		return
	    }

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
	    if Find(w.msg_d1_1,msg) {
		return
	    }

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
	    if Find(w.msg_share1,msg) {
		return
	    }

	    w.msg_share1.PushBack(msg)
	    if w.msg_share1.Len() == (NodeCnt-1) {
		fmt.Println("=========Get All SHARE1===========","GroupId",w.groupid)
		w.bshare1 <- true
	    }
	//case "ZKFACTPROOF":
	case "NTILDEH1H2":
	    ///bug
	    if w.msg_zkfact.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    if Find(w.msg_zkfact,msg) {
		return
	    }

	    w.msg_zkfact.PushBack(msg)
	    if w.msg_zkfact.Len() == (NodeCnt-1) {
		fmt.Println("=========Get All NTILDEH1H2,Nonce =%s,GroupId =%s===========",prexs[0],w.groupid)
		//fmt.Println("=========Get All ZKFACTPROOF===========","GroupId",w.groupid)
		w.bzkfact <- true
	    }
	case "ZKUPROOF":
	    ///bug
	    if w.msg_zku.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    if Find(w.msg_zku,msg) {
		return
	    }

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
	    if Find(w.msg_mtazk1proof,msg) {
		return
	    }

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
	    if Find(w.msg_c11,msg) {
		return
	    }

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
	    if Find(w.msg_kc,msg) {
		return
	    }

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
	    if Find(w.msg_mkg,msg) {
		return
	    }

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
	    if Find(w.msg_mkw,msg) {
		return
	    }

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
	    if Find(w.msg_delta1,msg) {
		return
	    }

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
	    if Find(w.msg_d11_1,msg) {
		return
	    }

	    w.msg_d11_1.PushBack(msg)
	    if w.msg_d11_1.Len() == (ThresHold-1) {
		fmt.Println("=========Get All D11===========","GroupId",w.groupid)
		w.bd11_1 <- true
	    }
	case "CommitBigVAB":
	    ///bug
	    if w.msg_commitbigvab.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    if Find(w.msg_commitbigvab,msg) {
		return
	    }

	    w.msg_commitbigvab.PushBack(msg)
	    if w.msg_commitbigvab.Len() == (ThresHold-1) {
		fmt.Println("=========Get All CommitBigVAB,Nonce =%s,GroupId =%s===========",prexs[0],w.groupid)
		w.bcommitbigvab <- true
	    }
	case "ZKABPROOF":
	    ///bug
	    if w.msg_zkabproof.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    if Find(w.msg_zkabproof,msg) {
		return
	    }

	    w.msg_zkabproof.PushBack(msg)
	    if w.msg_zkabproof.Len() == (ThresHold-1) {
		fmt.Println("=========Get All ZKABPROOF,Nonce =%s,GroupId =%s===========",prexs[0],w.groupid)
		w.bzkabproof <- true
	    }
	case "CommitBigUT":
	    ///bug
	    if w.msg_commitbigut.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    if Find(w.msg_commitbigut,msg) {
		return
	    }

	    w.msg_commitbigut.PushBack(msg)
	    if w.msg_commitbigut.Len() == (ThresHold-1) {
		fmt.Println("=========Get All CommitBigUT,Nonce =%s,GroupId =%s===========",prexs[0],w.groupid)
		w.bcommitbigut <- true
	    }
	case "CommitBigUTD11":
	    ///bug
	    if w.msg_commitbigutd11.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    if Find(w.msg_commitbigutd11,msg) {
		return
	    }

	    w.msg_commitbigutd11.PushBack(msg)
	    if w.msg_commitbigutd11.Len() == (ThresHold-1) {
		fmt.Println("=========Get All CommitBigUTD11,Nonce =%s,GroupId =%s===========",prexs[0],w.groupid)
		w.bcommitbigutd11 <- true
	    }
	case "S1":
	    ///bug
	    if w.msg_s1.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    if Find(w.msg_s1,msg) {
		return
	    }

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
	    if Find(w.msg_ss1,msg) {
		return
	    }

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
	    if Find(w.msg_edc11,msg) {
		return
	    }

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
	    if Find(w.msg_edzk,msg) {
		return
	    }

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
	    if Find(w.msg_edd11,msg) {
		return
	    }

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
	    if Find(w.msg_edshare1,msg) {
		return
	    }

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
	    if Find(w.msg_edcfsb,msg) {
		return
	    }

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
	    if Find(w.msg_edc21,msg) {
		return
	    }

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
	    if Find(w.msg_edzkr,msg) {
		return
	    }

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
	    if Find(w.msg_edd21,msg) {
		return
	    }

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
	    if Find(w.msg_edc31,msg) {
		return
	    }

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
	    if Find(w.msg_edd31,msg) {
		return
	    }

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
	    if Find(w.msg_eds,msg) {
		return
	    }

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

func GetAllAccountsDir() string {
    dir := DefaultDataDir()
    dir += "/dcrmdata/allaccounts" + cur_enode
    return dir
}

func GetAcceptLockOutDir() string {
    dir := DefaultDataDir()
    dir += "/dcrmdata/dcrmdb/acceptlockout" + cur_enode
    return dir
}

func GetAcceptReqAddrDir() string {
    dir := DefaultDataDir()
    dir += "/dcrmdata/dcrmdb/acceptreqaddr" + cur_enode
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
			return filepath.Join(home, "Library", "dcrm-walletservice")
		} else if runtime.GOOS == "windows" {
			return filepath.Join(home, "AppData", "Roaming", "dcrm-walletservice")
		} else {
			return filepath.Join(home, ".dcrm-walletservice")
		}
	}
	// As we cannot guess a stable location, return empty and handle later
	return ""
}

type PubAccounts struct {
       Group []AccountsList
}
type AccountsList struct {
       GroupID string
       Accounts []string
}

func GetAccounts(geter_acc, mode string) (interface{}, string, error) {
   if AllAccounts.MapLength() != 0 {
    fmt.Println("================!!!GetAccounts,get pubkey data from AllAccounts success!!!====================")
    gp := make(map[string][]string)
    _,lmvalue := AllAccounts.ListMap()
    for _,v := range lmvalue {
	if v == nil {
	    continue
	}

	vv := v.(*PubKeyData)

	if vv.Pub == "" || vv.GroupId == "" || vv.Mode == "" {
	    continue
	}

	////bug,check valid accepter
	/*check := false
	for k,v2 := range vv.NodeSigs {
	    fmt.Println("=============GetAccounts,check accepter,index =%v=========================",k)
	    tx2 := new(types.Transaction)
	    vs := common.FromHex(v2)
	    if err := rlp.DecodeBytes(vs, tx2); err != nil {
		continue
	    }

	    signer := types.NewEIP155Signer(big.NewInt(30400)) //
	    from2, err := types.Sender(signer, tx2)
	    if err != nil {
		signer = types.NewEIP155Signer(big.NewInt(4)) //
		from2, err = types.Sender(signer, tx2)
		if err != nil {
		    continue
		}
	    }

	    eid := string(tx2.Data())
	    fmt.Println("============GetAccounts,eid = %s,cur_enode =%s,from =%s,from2 =%s===============",eid,cur_enode,geter_acc,from2.Hex())
	    if strings.EqualFold(eid,cur_enode) && strings.EqualFold(geter_acc,from2.Hex()) {
		check = true
		break
	    }
	}

	if check == false {
	    continue
	}*/
	/////

	pb := vv.Pub
	pubkeyhex := hex.EncodeToString([]byte(pb))
	gid := vv.GroupId
	md := vv.Mode
	fmt.Println("==============GetAccounts,pubkeyhex = %s,gid = %s,get mode =%s,param mode =%s ===============",pubkeyhex,gid,md,mode)
	if mode == md {
	    al,exsit := gp[gid]
	    if exsit == true {
		al = append(al,pubkeyhex)
		gp[gid] = al
	    } else {
		a := make([]string,0)
		a = append(a,pubkeyhex)
		gp[gid] = a
	    }
	}
    }

    als := make([]AccountsList, 0)
    for k,v := range gp {
	fmt.Println("==============GetAccounts,33333,key =%s,value =%s ===============",k,v)
	alNew := AccountsList{GroupID: k, Accounts: v}
	als = append(als, alNew)
    }
    
    pa := &PubAccounts{Group: als}
    return pa, "", nil
   }

    return nil,"no accounts",nil
}

