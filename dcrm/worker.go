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
	"container/list"
	"fmt"
	"strings"
	"time"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
)

var (
	RPCReqQueueCache = make(chan RPCReq, RPCMaxQueue)
	//rpc-req //dcrm node
	RPCMaxWorker = 20000
	RPCMaxQueue  = 20000
	RPCReqQueue  chan RPCReq
	workers      []*RPCReqWorker
)

type RPCReq struct {
	rpcdata WorkReq
	ch      chan interface{}
}

//rpc-req
type ReqDispatcher struct {
	// A pool of workers channels that are registered with the dispatcher
	WorkerPool chan chan RPCReq
}

func GetWorkerId(w *RPCReqWorker) (int,error) {
    if w == nil {
	return -1,fmt.Errorf("fail get worker id")
    }

    return w.id,nil
}

type RPCReqWorker struct {
	RPCReqWorkerPool chan chan RPCReq
	RPCReqChannel    chan RPCReq
	rpcquit          chan bool
	id               int
	groupid          string
	limitnum         string
	DcrmFrom         string
	NodeCnt          int
	ThresHold        int
	ch               chan interface{}
	retres           *list.List
	//
	msg_acceptreqaddrres      *list.List
	splitmsg_acceptreqaddrres map[string]*list.List

	msg_acceptlockoutres      *list.List
	splitmsg_acceptlockoutres map[string]*list.List

	msg_acceptreshareres      *list.List
	splitmsg_acceptreshareres map[string]*list.List

	msg_acceptsignres      *list.List
	splitmsg_acceptsignres map[string]*list.List

	msg_sendlockoutres      *list.List
	splitmsg_sendlockoutres map[string]*list.List

	msg_sendreshareres      *list.List
	splitmsg_sendreshareres map[string]*list.List

	msg_sendsignres      *list.List
	splitmsg_sendsignres map[string]*list.List

	msg_c1      *list.List
	splitmsg_c1 map[string]*list.List

	msg_kc      *list.List
	splitmsg_kc map[string]*list.List

	msg_mkg      *list.List
	splitmsg_mkg map[string]*list.List

	msg_mkw      *list.List
	splitmsg_mkw map[string]*list.List

	msg_delta1      *list.List
	splitmsg_delta1 map[string]*list.List

	msg_d1_1      *list.List
	splitmsg_d1_1 map[string]*list.List

	msg_share1      *list.List
	splitmsg_share1 map[string]*list.List

	msg_zkfact      *list.List
	splitmsg_zkfact map[string]*list.List

	msg_zku      *list.List
	splitmsg_zku map[string]*list.List

	msg_mtazk1proof      *list.List
	splitmsg_mtazk1proof map[string]*list.List

	msg_c11      *list.List
	splitmsg_c11 map[string]*list.List

	msg_d11_1      *list.List
	splitmsg_d11_1 map[string]*list.List

	msg_commitbigvab      *list.List
	splitmsg_commitbigvab map[string]*list.List

	msg_zkabproof      *list.List
	splitmsg_zkabproof map[string]*list.List

	msg_commitbigut      *list.List
	splitmsg_commitbigut map[string]*list.List

	msg_commitbigutd11      *list.List
	splitmsg_commitbigutd11 map[string]*list.List

	msg_s1      *list.List
	splitmsg_s1 map[string]*list.List

	msg_ss1      *list.List
	splitmsg_ss1 map[string]*list.List

	msg_paillierkey      *list.List
	splitmsg_paillierkey map[string]*list.List
	
	rsv      *list.List
	
	pkx  *list.List
	pky  *list.List
	save *list.List
	sku1 *list.List

	bacceptreqaddrres chan bool
	bacceptlockoutres chan bool
	bacceptreshareres chan bool
	bacceptsignres chan bool
	bsendlockoutres   chan bool
	bsendreshareres   chan bool
	bsendsignres   chan bool
	bgaccs            chan bool
	bc1               chan bool
	bmkg              chan bool
	bmkw              chan bool
	bdelta1           chan bool
	bd1_1             chan bool
	bshare1           chan bool
	bzkfact           chan bool
	bzku              chan bool
	bmtazk1proof      chan bool
	bkc               chan bool
	bcommitbigvab     chan bool
	bzkabproof        chan bool
	bcommitbigut      chan bool
	bcommitbigutd11   chan bool
	bs1               chan bool
	bss1              chan bool
	bpaillierkey               chan bool
	bc11              chan bool
	bd11_1            chan bool

	sid string //save the key
	bnoreciv          chan bool

	//ed
	bedc11       chan bool
	msg_edc11    *list.List
	bedzk        chan bool
	msg_edzk     *list.List
	bedd11       chan bool
	msg_edd11    *list.List
	bedshare1    chan bool
	msg_edshare1 *list.List
	bedcfsb      chan bool
	msg_edcfsb   *list.List
	edsave       *list.List
	edsku1       *list.List
	edpk         *list.List

	bedc21    chan bool
	msg_edc21 *list.List
	bedzkr    chan bool
	msg_edzkr *list.List
	bedd21    chan bool
	msg_edd21 *list.List
	bedc31    chan bool
	msg_edc31 *list.List
	bedd31    chan bool
	msg_edd31 *list.List
	beds      chan bool
	msg_eds   *list.List

	acceptReqAddrChan     chan string
	acceptWaitReqAddrChan chan string
	acceptLockOutChan     chan string
	acceptWaitLockOutChan chan string
	acceptReShareChan     chan string
	acceptWaitReShareChan chan string
	acceptSignChan     chan string
	acceptWaitSignChan chan string
}

//workers,RpcMaxWorker,RpcReqWorker,RpcReqQueue,RpcMaxQueue,ReqDispatcher
func InitChan() {
	workers = make([]*RPCReqWorker, RPCMaxWorker)
	RPCReqQueue = make(chan RPCReq, RPCMaxQueue)
	reqdispatcher := NewReqDispatcher(RPCMaxWorker)
	reqdispatcher.Run()
}

func NewReqDispatcher(maxWorkers int) *ReqDispatcher {
	pool := make(chan chan RPCReq, maxWorkers)
	return &ReqDispatcher{WorkerPool: pool}
}

func (d *ReqDispatcher) Run() {
	// starting n number of workers
	for i := 0; i < RPCMaxWorker; i++ {
		worker := NewRPCReqWorker(d.WorkerPool)
		worker.id = i
		workers[i] = worker
		worker.Start()
	}

	go d.dispatch()
}

func (d *ReqDispatcher) dispatch() {
	/*for {
		select {
		case req := <-RPCReqQueue:
			// a job request has been received
			go func(req RPCReq) {
				// try to obtain a worker job channel that is available.
				// this will block until a worker is idle
				reqChannel := <-d.WorkerPool

				// dispatch the job to the worker job channel
				reqChannel <- req
			}(req)
		}
	}
	*/

	for {
	    req := <-RPCReqQueue
	    // a job request has been received
	    go func(req RPCReq) {
		    // try to obtain a worker job channel that is available.
		    // this will block until a worker is idle
		    reqChannel := <-d.WorkerPool

		    // dispatch the job to the worker job channel
		    reqChannel <- req
	    }(req)
	}
}

func FindWorker(sid string) (*RPCReqWorker, error) {
	if sid == "" {
		return nil, fmt.Errorf("input worker id error.")
	}

	for i := 0; i < RPCMaxWorker; i++ {
		w := workers[i]

		if w.sid == "" {
			continue
		}

		if strings.EqualFold(w.sid, sid) {
			return w, nil
		}
	}

	return nil, fmt.Errorf("no find worker.")
}

func NewRPCReqWorker(workerPool chan chan RPCReq) *RPCReqWorker {
	return &RPCReqWorker{
		RPCReqWorkerPool:          workerPool,
		RPCReqChannel:             make(chan RPCReq),
		rpcquit:                   make(chan bool),
		retres:                    list.New(),
		ch:                        make(chan interface{}),
		msg_share1:                list.New(),
		splitmsg_share1:           make(map[string]*list.List),
		msg_zkfact:                list.New(),
		splitmsg_zkfact:           make(map[string]*list.List),
		msg_zku:                   list.New(),
		splitmsg_zku:              make(map[string]*list.List),
		msg_mtazk1proof:           list.New(),
		splitmsg_mtazk1proof:      make(map[string]*list.List),
		msg_c1:                    list.New(),
		splitmsg_c1:               make(map[string]*list.List),
		msg_d1_1:                  list.New(),
		splitmsg_d1_1:             make(map[string]*list.List),
		msg_c11:                   list.New(),
		splitmsg_c11:              make(map[string]*list.List),
		msg_kc:                    list.New(),
		splitmsg_kc:               make(map[string]*list.List),
		msg_mkg:                   list.New(),
		splitmsg_mkg:              make(map[string]*list.List),
		msg_mkw:                   list.New(),
		splitmsg_mkw:              make(map[string]*list.List),
		msg_delta1:                list.New(),
		splitmsg_delta1:           make(map[string]*list.List),
		msg_d11_1:                 list.New(),
		splitmsg_d11_1:            make(map[string]*list.List),
		msg_commitbigvab:          list.New(),
		splitmsg_commitbigvab:     make(map[string]*list.List),
		msg_zkabproof:             list.New(),
		splitmsg_zkabproof:        make(map[string]*list.List),
		msg_commitbigut:           list.New(),
		splitmsg_commitbigut:      make(map[string]*list.List),
		msg_commitbigutd11:        list.New(),
		splitmsg_commitbigutd11:   make(map[string]*list.List),
		msg_s1:                    list.New(),
		splitmsg_s1:               make(map[string]*list.List),
		msg_ss1:                   list.New(),
		splitmsg_ss1:              make(map[string]*list.List),
		msg_paillierkey:                   list.New(),
		splitmsg_paillierkey:              make(map[string]*list.List),
		msg_acceptreqaddrres:      list.New(),
		splitmsg_acceptreqaddrres: make(map[string]*list.List),
		msg_acceptlockoutres:      list.New(),
		splitmsg_acceptlockoutres: make(map[string]*list.List),
		msg_acceptreshareres:      list.New(),
		splitmsg_acceptreshareres: make(map[string]*list.List),
		msg_acceptsignres:      list.New(),
		splitmsg_acceptsignres: make(map[string]*list.List),
		msg_sendlockoutres:        list.New(),
		splitmsg_sendlockoutres:   make(map[string]*list.List),
		msg_sendreshareres:        list.New(),
		splitmsg_sendreshareres:   make(map[string]*list.List),
		msg_sendsignres:        list.New(),
		splitmsg_sendsignres:   make(map[string]*list.List),

		rsv:  list.New(),
		pkx:  list.New(),
		pky:  list.New(),
		save: list.New(),
		sku1: list.New(),

		bacceptreqaddrres: make(chan bool, 1),
		bacceptlockoutres: make(chan bool, 1),
		bacceptreshareres: make(chan bool, 1),
		bacceptsignres: make(chan bool, 1),
		bsendlockoutres:   make(chan bool, 1),
		bsendreshareres:   make(chan bool, 1),
		bsendsignres:   make(chan bool, 1),
		bgaccs:            make(chan bool, 1),
		bc1:               make(chan bool, 1),
		bnoreciv:          make(chan bool, 1),
		bd1_1:             make(chan bool, 1),
		bc11:              make(chan bool, 1),
		bkc:               make(chan bool, 1),
		bcommitbigvab:     make(chan bool, 1),
		bzkabproof:        make(chan bool, 1),
		bcommitbigut:      make(chan bool, 1),
		bcommitbigutd11:   make(chan bool, 1),
		bs1:               make(chan bool, 1),
		bss1:              make(chan bool, 1),
		bpaillierkey:              make(chan bool, 1),
		bmkg:              make(chan bool, 1),
		bmkw:              make(chan bool, 1),
		bshare1:           make(chan bool, 1),
		bzkfact:           make(chan bool, 1),
		bzku:              make(chan bool, 1),
		bmtazk1proof:      make(chan bool, 1),
		bdelta1:           make(chan bool, 1),
		bd11_1:            make(chan bool, 1),

		//ed
		bedc11:       make(chan bool, 1),
		msg_edc11:    list.New(),
		bedzk:        make(chan bool, 1),
		msg_edzk:     list.New(),
		bedd11:       make(chan bool, 1),
		msg_edd11:    list.New(),
		bedshare1:    make(chan bool, 1),
		msg_edshare1: list.New(),
		bedcfsb:      make(chan bool, 1),
		msg_edcfsb:   list.New(),
		edsave:       list.New(),
		edsku1:       list.New(),
		edpk:         list.New(),
		bedc21:       make(chan bool, 1),
		msg_edc21:    list.New(),
		bedzkr:       make(chan bool, 1),
		msg_edzkr:    list.New(),
		bedd21:       make(chan bool, 1),
		msg_edd21:    list.New(),
		bedc31:       make(chan bool, 1),
		msg_edc31:    list.New(),
		bedd31:       make(chan bool, 1),
		msg_edd31:    list.New(),
		beds:         make(chan bool, 1),
		msg_eds:      list.New(),

		sid:       "",
		NodeCnt:   5,
		ThresHold: 5,

		acceptReqAddrChan:     make(chan string, 1),
		acceptWaitReqAddrChan: make(chan string, 1),

		acceptLockOutChan:     make(chan string, 1),
		acceptWaitLockOutChan: make(chan string, 1),
		acceptReShareChan:     make(chan string, 1),
		acceptWaitReShareChan: make(chan string, 1),
		acceptSignChan:     make(chan string, 1),
		acceptWaitSignChan: make(chan string, 1),
	}
}

func (w *RPCReqWorker) Clear() {

	common.Debug("======================RpcReqWorker.Clear======================","w.id",w.id,"w.groupid",w.groupid,"key",w.sid)

	w.sid = ""
	w.groupid = ""
	w.limitnum = ""
	w.DcrmFrom = ""
	w.NodeCnt = 5
	w.ThresHold = 5

	var next *list.Element

	for e := w.msg_acceptlockoutres.Front(); e != nil; e = next {
		next = e.Next()
		w.msg_acceptlockoutres.Remove(e)
	}

	for e := w.msg_acceptreshareres.Front(); e != nil; e = next {
		next = e.Next()
		w.msg_acceptreshareres.Remove(e)
	}

	for e := w.msg_acceptsignres.Front(); e != nil; e = next {
		next = e.Next()
		w.msg_acceptsignres.Remove(e)
	}

	for e := w.msg_sendlockoutres.Front(); e != nil; e = next {
		next = e.Next()
		w.msg_sendlockoutres.Remove(e)
	}

	for e := w.msg_sendreshareres.Front(); e != nil; e = next {
		next = e.Next()
		w.msg_sendreshareres.Remove(e)
	}

	for e := w.msg_sendsignres.Front(); e != nil; e = next {
		next = e.Next()
		w.msg_sendsignres.Remove(e)
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

	for e := w.msg_paillierkey.Front(); e != nil; e = next {
		next = e.Next()
		w.msg_paillierkey.Remove(e)
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

	for e := w.sku1.Front(); e != nil; e = next {
		next = e.Next()
		w.sku1.Remove(e)
	}

	for e := w.retres.Front(); e != nil; e = next {
		next = e.Next()
		w.retres.Remove(e)
	}

	for e := w.rsv.Front(); e != nil; e = next {
		next = e.Next()
		w.rsv.Remove(e)
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
	if len(w.bacceptreshareres) == 1 {
		<-w.bacceptreshareres
	}
	if len(w.bacceptsignres) == 1 {
		<-w.bacceptsignres
	}
	if len(w.bsendlockoutres) == 1 {
		<-w.bsendlockoutres
	}
	if len(w.bsendreshareres) == 1 {
		<-w.bsendreshareres
	}
	if len(w.bsendsignres) == 1 {
		<-w.bsendsignres
	}
	if len(w.bacceptreqaddrres) == 1 {
		<-w.bacceptreqaddrres
	}
	if len(w.bgaccs) == 1 {
		<-w.bgaccs
	}
	if len(w.bc1) == 1 {
		<-w.bc1
	}
	if len(w.bnoreciv) == 1 {
		<-w.bnoreciv
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
	if len(w.bpaillierkey) == 1 {
		<-w.bpaillierkey
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
	for e := w.edsku1.Front(); e != nil; e = next {
		next = e.Next()
		w.edsku1.Remove(e)
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
	w.splitmsg_acceptreshareres = make(map[string]*list.List)
	w.splitmsg_acceptsignres = make(map[string]*list.List)
	w.splitmsg_sendlockoutres = make(map[string]*list.List)
	w.splitmsg_sendreshareres = make(map[string]*list.List)
	w.splitmsg_sendsignres = make(map[string]*list.List)
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
	w.splitmsg_paillierkey = make(map[string]*list.List)

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
	if len(w.acceptReShareChan) == 1 {
		<-w.acceptReShareChan
	}
	if len(w.acceptSignChan) == 1 {
		<-w.acceptSignChan
	}
	if len(w.acceptWaitSignChan) == 1 {
		<-w.acceptWaitSignChan
	}
}

func (w *RPCReqWorker) Clear2() {
	common.Debug("======================RpcReqWorker.Clear2======================","w.id",w.id,"w.groupid",w.groupid,"key",w.sid)
	
	var next *list.Element

	for e := w.msg_acceptlockoutres.Front(); e != nil; e = next {
		next = e.Next()
		w.msg_acceptlockoutres.Remove(e)
	}

	for e := w.msg_acceptreshareres.Front(); e != nil; e = next {
		next = e.Next()
		w.msg_acceptreshareres.Remove(e)
	}

	for e := w.msg_acceptsignres.Front(); e != nil; e = next {
		next = e.Next()
		w.msg_acceptsignres.Remove(e)
	}

	for e := w.msg_sendlockoutres.Front(); e != nil; e = next {
		next = e.Next()
		w.msg_sendlockoutres.Remove(e)
	}

	for e := w.msg_sendreshareres.Front(); e != nil; e = next {
		next = e.Next()
		w.msg_sendreshareres.Remove(e)
	}

	for e := w.msg_sendsignres.Front(); e != nil; e = next {
		next = e.Next()
		w.msg_sendsignres.Remove(e)
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

	for e := w.msg_paillierkey.Front(); e != nil; e = next {
		next = e.Next()
		w.msg_paillierkey.Remove(e)
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

	for e := w.sku1.Front(); e != nil; e = next {
		next = e.Next()
		w.sku1.Remove(e)
	}

	for e := w.retres.Front(); e != nil; e = next {
		next = e.Next()
		w.retres.Remove(e)
	}

	for e := w.rsv.Front(); e != nil; e = next {
		next = e.Next()
		w.rsv.Remove(e)
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
	if len(w.bacceptreshareres) == 1 {
		<-w.bacceptreshareres
	}
	if len(w.bacceptsignres) == 1 {
		<-w.bacceptsignres
	}
	if len(w.bsendlockoutres) == 1 {
		<-w.bsendlockoutres
	}
	if len(w.bsendreshareres) == 1 {
		<-w.bsendreshareres
	}
	if len(w.bsendsignres) == 1 {
		<-w.bsendsignres
	}
	if len(w.bacceptreqaddrres) == 1 {
		<-w.bacceptreqaddrres
	}
	if len(w.bgaccs) == 1 {
		<-w.bgaccs
	}
	if len(w.bc1) == 1 {
		<-w.bc1
	}
	if len(w.bnoreciv) == 1 {
		<-w.bnoreciv
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
	if len(w.bpaillierkey) == 1 {
		<-w.bpaillierkey
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
	for e := w.edsku1.Front(); e != nil; e = next {
		next = e.Next()
		w.edsku1.Remove(e)
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
	w.splitmsg_acceptreshareres = make(map[string]*list.List)
	w.splitmsg_acceptsignres = make(map[string]*list.List)
	w.splitmsg_sendlockoutres = make(map[string]*list.List)
	w.splitmsg_sendreshareres = make(map[string]*list.List)
	w.splitmsg_sendsignres = make(map[string]*list.List)
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
	w.splitmsg_paillierkey = make(map[string]*list.List)

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
	if len(w.acceptReShareChan) == 1 {
		<-w.acceptReShareChan
	}
	if len(w.acceptSignChan) == 1 {
		<-w.acceptSignChan
	}
	if len(w.acceptWaitSignChan) == 1 {
		<-w.acceptWaitSignChan
	}
}

func (w *RPCReqWorker) Start() {
	go func() {

		for {
			// register the current worker into the worker queue.
			w.RPCReqWorkerPool <- w.RPCReqChannel
			select {
			case req := <-w.RPCReqChannel:
				req.rpcdata.Run(w.id, req.ch)
				w.Clear()

			case <-w.rpcquit:
				// we have received a signal to stop
				return
			}
		}
	}()
}

func (w *RPCReqWorker) Stop() {
	go func() {
		w.rpcquit <- true
	}()
}

func CommitRpcReq() {
	for {
		req := <-RPCReqQueueCache
		RPCReqQueue <- req
		time.Sleep(time.Duration(1000000000)) //na, 1 s = 10e9 na /////////!!!!!fix bug:if large sign at same time,it will very slowly!!!!!
	}
}

