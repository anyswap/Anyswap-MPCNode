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
	"bytes"
	"compress/zlib"
	"container/list"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsn-dev/dcrm-walletService/crypto/dcrm/dev/lib/ec2"
	"github.com/fsn-dev/dcrm-walletService/crypto/sha3"
	"github.com/fsn-dev/dcrm-walletService/internal/common/hexutil"

	//"github.com/fsn-dev/dcrm-walletService/p2p/rlp"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"

	"github.com/astaxie/beego/logs"
	"github.com/fsn-dev/dcrm-walletService/ethdb"

	//"github.com/fsn-dev/dcrm-walletService/coins/types"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	"github.com/fsn-dev/dcrm-walletService/p2p/discover"
)

var (
	Sep     = "dcrmparm"
	SepSave = "dcrmsepsave"
	SepSg   = "dcrmmsg"
	SepDel  = "dcrmsepdel"

	PaillierKeyLength        = 2048
	sendtogroup_lilo_timeout = 600
	sendtogroup_timeout      = 600
	ch_t                     = 60
	lock5                    sync.Mutex
	lock                     sync.Mutex

	//callback
	GetGroup               func(string) (int, string)
	SendToGroupAllNodes    func(string, string) (string, error)
	GetSelfEnode           func() string
	BroadcastInGroupOthers func(string, string) (string, error)
	SendToPeer             func(string, string) error
	ParseNode              func(string) string
	GetEosAccount          func() (string, string, string)

	KeyFile string

	//AllAccounts     = common.NewSafeMap(10) //make([]*PubKeyData,0)
	//AllAccountsChan = make(chan KeyData, 1000)

	LdbPubKeyData  = common.NewSafeMap(10) //make(map[string][]byte)
	PubKeyDataChan = make(chan KeyData, 1000)

	//LdbReqAddr  = common.NewSafeMap(10) //make(map[string][]byte)
	//ReqAddrChan = make(chan KeyData, 1000)

	//LdbLockOut  = common.NewSafeMap(10) //make(map[string][]byte)
	//LockOutChan = make(chan KeyData, 1000)

	ReSendTimes int //resend p2p msg times
	DcrmCalls   = common.NewSafeMap(10)

	RpcReqQueueCache = make(chan RpcReq, RpcMaxQueue)

	//GAccs         = common.NewSafeMap(10)
	//GAccsDataChan = make(chan KeyData, 1000)
)

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

func PutGroup(groupId string) bool {
	return true

	if groupId == "" {
		return false
	}

	lock.Lock()
	dir := GetGroupDir()
	//db, err := leveldb.OpenFile(dir, nil)

	db, err := ethdb.NewLDBDatabase(dir, 0, 0)
	//bug
	if err != nil {
		for i := 0; i < 100; i++ {
			db, err = ethdb.NewLDBDatabase(dir, 0, 0)
			if err == nil && db != nil {
				break
			}

			time.Sleep(time.Duration(1000000))
		}
	}
	//

	if err != nil {
		lock.Unlock()
		return false
	}

	var data string
	var b bytes.Buffer
	b.WriteString("")
	b.WriteByte(0)
	b.WriteString("")
	iter := db.NewIterator()
	for iter.Next() {
		key := string(iter.Key())
		value := string(iter.Value())
		if strings.EqualFold(key, "GroupIds") {
			data = value
			break
		}
	}
	iter.Release()
	///////
	if data == "" {
		db.Put([]byte("GroupIds"), []byte(groupId))
		db.Close()
		lock.Unlock()
		return true
	}

	m := strings.Split(data, ":")
	for _, v := range m {
		if strings.EqualFold(v, groupId) {
			db.Close()
			lock.Unlock()
			return true
		}
	}

	data += ":" + groupId
	db.Put([]byte("GroupIds"), []byte(data))

	db.Close()
	lock.Unlock()
	return true
}

func GetGroupIdByEnode(enode string) string {
	if enode == "" {
		return ""
	}

	lock.Lock()
	dir := GetGroupDir()
	//db, err := leveldb.OpenFile(dir, nil)

	db, err := ethdb.NewLDBDatabase(dir, 0, 0)
	//bug
	if err != nil {
		for i := 0; i < 100; i++ {
			db, err = ethdb.NewLDBDatabase(dir, 0, 0)
			if err == nil && db != nil {
				break
			}

			time.Sleep(time.Duration(1000000))
		}
	}
	//

	if err != nil {
		lock.Unlock()
		return ""
	}

	var data string
	var b bytes.Buffer
	b.WriteString("")
	b.WriteByte(0)
	b.WriteString("")
	iter := db.NewIterator()
	for iter.Next() {
		key := string(iter.Key())
		value := string(iter.Value())
		if strings.EqualFold(key, "GroupIds") {
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

	m := strings.Split(data, ":")
	for _, v := range m {
		if IsInGroup(enode, v) {
			db.Close()
			lock.Unlock()
			return v
		}
	}

	db.Close()
	lock.Unlock()
	return ""
}

func IsInGroup(enode string, groupId string) bool {
	if groupId == "" || enode == "" {
		return false
	}

	cnt, enodes := GetGroup(groupId)
	if cnt <= 0 || enodes == "" {
		return false
	}

	fmt.Printf("==== dev.IsInGroup() ====, gid: %v, enodes: %v\n", groupId, enodes)
	nodes := strings.Split(enodes, SepSg)
	fmt.Printf("==== dev.IsInGroup() ====, gid: %v, enodes: %v, split: %v, nodes: %v\n", groupId, enodes, SepSg, nodes)
	for _, node := range nodes {
		fmt.Printf("==== dev.IsInGroup() ====, call ParseNode enode: %v\n", node)
		node2 := ParseNode(node)
		if strings.EqualFold(node2, enode) {
			return true
		}
	}

	return false
}

func InitDev(keyfile string) {
	KeyFile = keyfile
	ReSendTimes = 1
	cur_enode = discover.GetLocalID().String() //GetSelfEnode()
	fmt.Printf("%v ==================InitDev,cur_enode = %v ====================\n", common.CurrentTime(), cur_enode)

	LdbPubKeyData = GetAllPubKeyDataFromDb()

	go SavePubKeyDataToDb()
	go CommitRpcReq()
	go ec2.GenRandomInt(2048)
	go ec2.GenRandomSafePrime(2048)
}

func InitGroupInfo(groupId string) {
	//cur_enode = GetSelfEnode()
	cur_enode = discover.GetLocalID().String() //GetSelfEnode()
	fmt.Printf("%v ==================InitGroupInfo,cur_enode = %v ====================\n", common.CurrentTime(), cur_enode)
}

func GenRandomSafePrime(length int) {
	ec2.GenRandomSafePrime(length)
}

////////////////////////dcrm///////////////////////////////
var (
	//rpc-req //dcrm node
	RpcMaxWorker = 5000
	RpcMaxQueue  = 5000
	RpcReqQueue  chan RpcReq
	workers      []*RpcReqWorker
	//rpc-req
	cur_enode string
	//NodeCnt = 5
	//ThresHold = 5
)

type RpcDcrmRes struct {
	Ret string
	Tip string
	Err error
}

type RpcReq struct {
	rpcdata WorkReq
	ch      chan interface{}
}

//rpc-req
type ReqDispatcher struct {
	// A pool of workers channels that are registered with the dispatcher
	WorkerPool chan chan RpcReq
}

func GetWorkerId(w *RpcReqWorker) (int,error) {
    if w == nil {
	return -1,fmt.Errorf("fail get worker id")
    }

    return w.id,nil
}

type RpcReqWorker struct {
	RpcReqWorkerPool chan chan RpcReq
	RpcReqChannel    chan RpcReq
	rpcquit          chan bool
	id               int
	groupid          string
	limitnum         string
	NodeCnt          int
	ThresHold        int
	ch               chan interface{}
	retres           *list.List
	//
	msg_acceptreqaddrres      *list.List
	splitmsg_acceptreqaddrres map[string]*list.List

	msg_acceptlockoutres      *list.List
	splitmsg_acceptlockoutres map[string]*list.List

	msg_sendlockoutres      *list.List
	splitmsg_sendlockoutres map[string]*list.List

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

	pkx  *list.List
	pky  *list.List
	save *list.List

	bacceptreqaddrres chan bool
	bacceptlockoutres chan bool
	bsendlockoutres   chan bool
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
	bc11              chan bool
	bd11_1            chan bool

	sid string //save the txhash

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
}

//workers,RpcMaxWorker,RpcReqWorker,RpcReqQueue,RpcMaxQueue,ReqDispatcher
func InitChan() {
	workers = make([]*RpcReqWorker, RpcMaxWorker)
	RpcReqQueue = make(chan RpcReq, RpcMaxQueue)
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

func FindWorker(sid string) (*RpcReqWorker, error) {
	if sid == "" {
		return nil, fmt.Errorf("input worker id error.")
	}

	for i := 0; i < RpcMaxWorker; i++ {
		w := workers[i]

		if w.sid == "" {
			continue
		}

		if strings.EqualFold(w.sid, sid) {
			return w, nil
		}
	}

	time.Sleep(time.Duration(60) * time.Second) //1000 == 1s //TODO

	for i := 0; i < RpcMaxWorker; i++ {
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

func NewRpcReqWorker(workerPool chan chan RpcReq) *RpcReqWorker {
	return &RpcReqWorker{
		RpcReqWorkerPool:          workerPool,
		RpcReqChannel:             make(chan RpcReq),
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
		msg_acceptreqaddrres:      list.New(),
		splitmsg_acceptreqaddrres: make(map[string]*list.List),
		msg_acceptlockoutres:      list.New(),
		splitmsg_acceptlockoutres: make(map[string]*list.List),
		msg_sendlockoutres:        list.New(),
		splitmsg_sendlockoutres:   make(map[string]*list.List),

		pkx:  list.New(),
		pky:  list.New(),
		save: list.New(),

		bacceptreqaddrres: make(chan bool, 1),
		bacceptlockoutres: make(chan bool, 1),
		bsendlockoutres:   make(chan bool, 1),
		bgaccs:            make(chan bool, 1),
		bc1:               make(chan bool, 1),
		bd1_1:             make(chan bool, 1),
		bc11:              make(chan bool, 1),
		bkc:               make(chan bool, 1),
		bcommitbigvab:     make(chan bool, 1),
		bzkabproof:        make(chan bool, 1),
		bcommitbigut:      make(chan bool, 1),
		bcommitbigutd11:   make(chan bool, 1),
		bs1:               make(chan bool, 1),
		bss1:              make(chan bool, 1),
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
	}
}

func (w *RpcReqWorker) Clear() {

	w.sid = ""
	w.groupid = ""
	w.limitnum = ""
	w.NodeCnt = 5
	w.ThresHold = 5

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
	if len(w.bgaccs) == 1 {
		<-w.bgaccs
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
	fmt.Println("===========RpcReqWorker.Clear2,w.id = %s ===================", w.id)
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
	if len(w.bgaccs) == 1 {
		<-w.bgaccs
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
				req.rpcdata.Run(w.id, req.ch)
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
	for i := 0; i < l; i++ {
		<-ch
	}
}

type WorkReq interface {
	Run(workid int, ch chan interface{}) bool
}

//RecvMsg
type RecvMsg struct {
	msg    string
	sender string
}

func DcrmCall(msg interface{}, enode string) <-chan string {
	s := msg.(string)
	ch := make(chan string, 1)

	///check
	_, exsit := DcrmCalls.ReadMap(s)
	if exsit == false {
		DcrmCalls.WriteMap(s, "true")
	} else {
		common.Info("=============DcrmCall,already exsit in DcrmCalls and return ", "get msg len =", len(s), "sender node =", enode, "", "================")
		ret := ("fail" + Sep + "already exsit in DcrmCalls" + Sep + "dcrm back-end internal error:already exsit in DcrmCalls" + Sep + "already exsit in DcrmCalls") //TODO "no-data"
		ch <- ret
		return ch
	}
	///

	////////
	if s == "" {
		//fail:chret:tip:error
		ret := ("fail" + Sep + "no-data" + Sep + "dcrm back-end internal error:get msg fail" + Sep + "get msg fail") //TODO "no-data"
		ch <- ret
		return ch
	}

	res, err := UnCompress(s)
	if err != nil {
		//fail:chret:tip:error
		ret := ("fail" + Sep + "no-data" + Sep + "dcrm back-end internal error:uncompress data fail in RecvMsg.Run" + Sep + "uncompress data fail in recvmsg.run") //TODO "no-data"
		ch <- ret
		return ch
	}

	r, err := Decode2(res, "SendMsg")
	if err != nil {
		//fail:chret:tip:error
		ret := ("fail" + Sep + "no-data" + Sep + "dcrm back-end internal error:decode data to SendMsg fail in RecvMsg.Run" + Sep + "decode data to SendMsg fail in recvmsg.run") //TODO "no-data"
		ch <- ret
		return ch
	}

	rr := r.(*SendMsg)
	//if rr.MsgType == "rpc_lockout" {
	//}
	//if rr.MsgType == "rpc_req_dcrmaddr" {
	//}
	test := Keccak256Hash([]byte(strings.ToLower(s))).Hex()
	fmt.Printf("%v =============DcrmCall, get msg len = %v,msg hash = %v,sender node = %v,key = %v =======================\n", common.CurrentTime(), len(s), test, enode, rr.Nonce)
	////////

	v := RecvMsg{msg: s, sender: enode}
	rch := make(chan interface{}, 1)
	req := RpcReq{rpcdata: &v, ch: rch}
	RpcReqQueue <- req
	fmt.Printf("%v =============DcrmCall, finish send req to Queue,msg hash = %v,key = %v =======================\n", common.CurrentTime(), test, rr.Nonce)
	chret, tip, cherr := GetChannelValue(sendtogroup_timeout, rch)
	fmt.Printf("%v =============DcrmCall, ret = %v,err = %v,msg hash = %v,key = %v =======================\n", common.CurrentTime(), chret, cherr, test, rr.Nonce)
	if cherr != nil {
		////
		if rr.MsgType == "rpc_lockout" {
		}
		if rr.MsgType == "rpc_req_dcrmaddr" {
		}
		////

		//fail:chret:tip:error
		ret := ("fail" + Sep + chret + Sep + tip + Sep + cherr.Error())
		ch <- ret
		return ch
	}

	//success:chret
	ret := ("success" + Sep + chret)
	ch <- ret
	return ch
}

func DcrmCallRet(msg interface{}, enode string) {

	//msg = success:workid:msgtype:ret  or fail:workid:msgtype:tip:error
	res := msg.(string)
	common.Info("============================!!!!!! DcrmCallRet, ", "get return msg = ", res, "sender node = ", enode, "", "!!!!!!=========================")
	if res == "" {
		return
	}

	ss := strings.Split(res, Sep)
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
	common.Info("==============DcrmCallRet, ", "ret =", ss[3], "ret len =", len(ss[3]))
	workid, err := strconv.Atoi(ss[1])
	if err != nil || workid < 0 || workid >= RpcMaxWorker {
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

		if ss[2] == "rpc_req_dcrmaddr" {
			if w.retres.Len() == w.NodeCnt {
				ret := GetGroupRes(workid)
				w.ch <- ret
			}
		}

		if ss[2] == "rpc_get_lockout_reply" {

			if w.retres.Len() == w.NodeCnt {
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

		if ss[2] == "rpc_req_dcrmaddr" {
			if w.retres.Len() == w.NodeCnt {
				ret := GetGroupRes(workid)
				w.ch <- ret
			}
		}

		if ss[2] == "rpc_get_lockout_reply" {
			if w.retres.Len() == w.NodeCnt {
			}
		}

		return
	}
}

func GetGroupRes(wid int) RpcDcrmRes {
	if wid < 0 || wid >= RpcMaxWorker {
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

		iter = iter.Next()
	}

	res2 := RpcDcrmRes{Ret: "", Tip: "", Err: nil}
	return res2
}

//=========================================

func Call(msg interface{}, enode string) {
	fmt.Printf("%v =========Call,get msg = %v,sender node = %v =================", common.CurrentTime(), msg, enode)
	s := msg.(string)
	test := Keccak256Hash([]byte(strings.ToLower(s))).Hex()
	fmt.Printf("%v =========Call,get msg = %v,msg hash = %v,sender node = %v =================", common.CurrentTime(), msg, test, enode)
	SetUpMsgList(s, enode)
}

func SetUpMsgList(msg string, enode string) {

	v := RecvMsg{msg: msg, sender: enode}
	//rpc-req
	rch := make(chan interface{}, 1)
	req := RpcReq{rpcdata: &v, ch: rch}
	RpcReqQueue <- req
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
	///////
	if exsit == false {
		fmt.Printf("%v =====================GetReqAddrStatus,no exist key, key = %v ======================\n", common.CurrentTime(), key)
		return "", "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	ds, err := UnCompress(string(da))
	if err != nil {
		fmt.Printf("%v =====================GetReqAddrStatus,uncompress fail,err = %v,key = %v ======================\n", common.CurrentTime(), err, key)
		return "", "dcrm back-end internal error:uncompress accept data fail", err
	}

	dss, err := Decode2(ds, "AcceptReqAddrData")
	if err != nil {
		fmt.Printf("%v =====================GetReqAddrStatus,decode fail,err = %v,key = %v ======================\n", common.CurrentTime(), err, key)
		return "", "dcrm back-end internal error:decode accept data fail", err
	}

	ac := dss.(*AcceptReqAddrData)
	los := &ReqAddrStatus{Status: ac.Status, PubKey: ac.PubKey, Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
	ret, err := json.Marshal(los)
	fmt.Printf("%v =====================GetReqAddrStatus,status = %v,ret = %v,err = %v,key = %v ======================\n", common.CurrentTime(),ac.Status,ret,err, key)
	return string(ret), "", nil
}

type LockOutStatus struct {
	Status    string
	OutTxHash string
	Tip       string
	Error     string
	AllReply  []NodeReply 
	TimeStamp string
}

func GetLockOutStatus(key string) (string, string, error) {
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		return "", "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	ds, err := UnCompress(string(da))
	if err != nil {
		return "", "dcrm back-end internal error:uncompress accept data fail", err
	}

	dss, err := Decode2(ds, "AcceptLockOutData")
	if err != nil {
		return "", "dcrm back-end internal error:decode accept data fail", err
	}

	ac := dss.(*AcceptLockOutData)
	los := &LockOutStatus{Status: ac.Status, OutTxHash: ac.OutTxHash, Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
	ret,_ := json.Marshal(los)
	return string(ret), "", err
}

type EnAcc struct {
	Enode    string
	Accounts []string
}

type EnAccs struct {
	EnodeAccounts []EnAcc
}

type ReqAddrReply struct {
	Key       string
	Account   string
	Cointype  string
	GroupId   string
	Nonce     string
	LimitNum  string
	Mode      string
	TimeStamp string
}

func SortCurNodeInfo(value []interface{}) []interface{} {
	if len(value) == 0 {
		return value
	}

	var ids sortableIDSSlice
	for _, v := range value {
		uid := DoubleHash(string(v.([]byte)), "ALL")
		ids = append(ids, uid)
	}

	sort.Sort(ids)

	var ret = make([]interface{}, 0)
	for _, v := range ids {
		for _, vv := range value {
			uid := DoubleHash(string(vv.([]byte)), "ALL")
			if v.Cmp(uid) == 0 {
				ret = append(ret, vv)
				break
			}
		}
	}

	return ret
}

func GetCurNodeReqAddrInfo(geter_acc string) (string, string, error) {
	exsit,da := GetValueFromPubKeyData(strings.ToLower(geter_acc))
	if exsit == false {
	    return "","",nil
	}

	fmt.Printf("%v=================GetCurNodeReqAddrInfo,da = %v,geter_acc = %v ====================\n",common.CurrentTime(),string(da),geter_acc)
	var ret []string
	keys := strings.Split(string(da),":")
	for _,key := range keys {
	    exsit,data := GetValueFromPubKeyData(key)
	    if exsit == false {
		continue
	    }

	    value := string(data)
	    ////
	    ds, err := UnCompress(value)
	    if err != nil {
		    continue
	    }

	    dss, err := Decode2(ds, "AcceptReqAddrData")
	    if err != nil {
		    continue
	    }

	    ac := dss.(*AcceptReqAddrData)
	    if ac == nil {
		    continue
	    }

	    if ac.Mode == "1" {
		    continue
	    }

	    if ac.Deal == true || ac.Status == "Success" {
		    continue
	    }

	    if ac.Status != "Pending" {
		    continue
	    }

	    los := &ReqAddrReply{Key: key, Account: ac.Account, Cointype: ac.Cointype, GroupId: ac.GroupId, Nonce: ac.Nonce, LimitNum: ac.LimitNum, Mode: ac.Mode, TimeStamp: ac.TimeStamp}
	    ret2, err := json.Marshal(los)

	    ret = append(ret, string(ret2))
	    ////

	}

	///////
	ss := strings.Join(ret, "|")
	return ss, "", nil
}

type LockOutCurNodeInfo struct {
	Key       string
	Account   string
	GroupId   string
	Nonce     string
	DcrmFrom  string
	DcrmTo    string
	Value     string
	Cointype  string
	LimitNum  string
	Mode      string
	TimeStamp string
}

func GetCurNodeLockOutInfo(geter_acc string) (string, string, error) {
	exsit,da := GetValueFromPubKeyData(strings.ToLower(geter_acc))
	if exsit == false {
	    return "","",nil
	}

	var ret []string
	keys := strings.Split(string(da),":")
	for _,key := range keys {
	    exsit,data := GetValueFromPubKeyData(key)
	    if exsit == false {
		continue
	    }

	    value := string(data)
	    ////
	    ds, err := UnCompress(value)
	    if err != nil {
		    //	    fmt.Println("================GetCurNodeLockOutInfo,uncompress err =%v ===================",err)
		    continue
	    }

	    dss, err := Decode2(ds, "AcceptReqAddrData")
	    if err != nil {
		    //	    fmt.Println("================GetCurNodeLockOutInfo,decode err =%v ===================",err)
		    continue
	    }

	    ac := dss.(*AcceptReqAddrData)
	    if ac == nil {
		    //	    fmt.Println("================GetCurNodeLockOutInfo,decode err ===================")
		    continue
	    }

	    dcrmpks, _ := hex.DecodeString(ac.PubKey)
	    exsit,data2 := GetValueFromPubKeyData(string(dcrmpks[:]))
	    ss, err := UnCompress(string(data2))
	    if err != nil {
		continue
	    }
	    
	    pubs, err := Decode2(ss, "PubKeyData")
	    if err != nil {
		continue
	    }

	    pd := pubs.(*PubKeyData)
	    if pd == nil {
		continue
	    }

	    if pd.RefLockOutKeys == "" {
		continue
	    }

	    lockoutkeys := strings.Split(pd.RefLockOutKeys,":")
	    for _,lockoutkey := range lockoutkeys {
		exsit,data3 := GetValueFromPubKeyData(lockoutkey)
		if exsit == false {
		    continue
		}

		////
		ds3, err := UnCompress(string(data3))
		if err != nil {
			continue
		}

		dss3, err := Decode2(ds3, "AcceptLockOutData")
		if err != nil {
			continue
		}

		ac3 := dss3.(*AcceptLockOutData)
		if ac3 == nil {
			continue
		}
		
		if ac3.Mode == "1" {
			continue
		}
		
		if ac3.Deal == true || ac3.Status == "Success" {
			continue
		}

		if ac3.Status != "Pending" {
			continue
		}

		keytmp := Keccak256Hash([]byte(strings.ToLower(ac3.Account + ":" + ac3.GroupId + ":" + ac3.Nonce + ":" + ac3.DcrmFrom + ":" + ac3.LimitNum))).Hex()

		los := &LockOutCurNodeInfo{Key: keytmp, Account: ac3.Account, GroupId: ac3.GroupId, Nonce: ac3.Nonce, DcrmFrom: ac3.DcrmFrom, DcrmTo: ac3.DcrmTo, Value: ac3.Value, Cointype: ac3.Cointype, LimitNum: ac3.LimitNum, Mode: ac3.Mode, TimeStamp: ac3.TimeStamp}
		ret2, err := json.Marshal(los)
		ret = append(ret, string(ret2))
	    }
	    ////
	}

	///////
	ss := strings.Join(ret, "|")
	return ss, "", nil
}

func GetAcceptReqAddrRes(account string, cointype string, groupid string, nonce string, threshold string, mode string) (string, bool) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype + ":" + groupid + ":" + nonce + ":" + threshold + ":" + mode))).Hex()
	fmt.Printf("%v ===================!!!!GetAcceptReqAddrRes,acc =%v,cointype =%v,groupid =%v,nonce =%v,threshold =%v,mode =%v,key =%v !!!!============================\n", common.CurrentTime(), account, cointype, groupid, nonce, threshold, mode, key)
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		fmt.Printf("%v ===================!!!!GetAcceptReqAddrRes,no exsit key =%v !!!!============================\n", common.CurrentTime(), key)
		return "dcrm back-end internal error:get accept result from db fail", false
	}

	ds, err := UnCompress(string(da))
	if err != nil {
		fmt.Printf("%v ===================!!!!GetAcceptReqAddrRes,uncompress fail,err = %v,key =%v !!!!============================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:uncompress accept result fail", false
	}

	dss, err := Decode2(ds, "AcceptReqAddrData")
	if err != nil {
		fmt.Printf("%v ===================!!!!GetAcceptReqAddrRes,decode fail,err = %v,key =%v !!!!============================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:decode accept result fail", false
	}

	ac := dss.(*AcceptReqAddrData)
	fmt.Printf("%v ===================!!!! GetAcceptReqAddrRes,ac.Accept =%v,key =%v !!!!============================\n", common.CurrentTime(),ac.Accept, key)

	var rp bool
	if strings.EqualFold(ac.Accept, "false") {
		rp = false
	} else {
		rp = true
	}

	return "", rp
}

func GetAcceptLockOutRes(account string, groupid string, nonce string, dcrmfrom string, threshold string) (string, bool) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + groupid + ":" + nonce + ":" + dcrmfrom + ":" + threshold))).Hex()
	fmt.Printf("%v ===================!!!! GetAcceptLockOutRes,acc =%v,groupid =%v,nonce =%v,dcrmfrom =%v,threshold =%v,key =%v !!!!============================\n", common.CurrentTime(), account, groupid, nonce, dcrmfrom, threshold, key)
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		fmt.Printf("%v ===================!!!! GetAcceptLockOutRes,no exsit key =%v !!!!============================\n", common.CurrentTime(), key)
		return "dcrm back-end internal error:get accept result from db fail", false
	}

	ds, err := UnCompress(string(da))
	if err != nil {
		fmt.Printf("%v ===================!!!! GetAcceptLockOutRes,uncompress data fail, err = %v ,key =%v !!!!============================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:uncompress accept result fail", false
	}

	dss, err := Decode2(ds, "AcceptLockOutData")
	if err != nil {
		fmt.Printf("%v ===================!!!! GetAcceptLockOutRes,decode data fail, err = %v ,key =%v !!!!============================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:decode accept result fail", false
	}

	ac := dss.(*AcceptLockOutData)
	fmt.Printf("%v ===================!!!! GetAcceptLockOutRes,ac.Accept =%v, key =%v !!!!============================\n", common.CurrentTime(), ac.Accept, key)

	var rp bool
	if strings.EqualFold(ac.Accept, "false") {
		rp = false
	} else {
		rp = true
	}

	return "", rp
}

func AcceptReqAddr(account string, cointype string, groupid string, nonce string, threshold string, mode string, deal bool, accept string, status string, pubkey string, tip string, errinfo string, allreply []NodeReply, workid int) (string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype + ":" + groupid + ":" + nonce + ":" + threshold + ":" + mode))).Hex()
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		fmt.Printf("%v =====================AcceptReqAddr,no exist key, key = %v ======================\n", common.CurrentTime(), key)
		return "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	ds, err := UnCompress(string(da))
	if err != nil {
		fmt.Printf("%v =====================AcceptReqAddr,uncompress fail,err = %v,key = %v ======================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:uncompress accept data fail", err
	}

	dss, err := Decode2(ds, "AcceptReqAddrData")
	if err != nil {
		fmt.Printf("%v =====================AcceptReqAddr,decode fail,err = %v,key = %v ======================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:decode accept data fail", err
	}

	ac := dss.(*AcceptReqAddrData)

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
	if allreply != nil && len(allreply) != 0 {
		arl = allreply
	}

	wid := ac.WorkId
	if workid >= 0 {
		wid = workid
	}

	ac2 := &AcceptReqAddrData{Account: ac.Account, Cointype: ac.Cointype, GroupId: ac.GroupId, Nonce: ac.Nonce, LimitNum: ac.LimitNum, Mode: ac.Mode, TimeStamp: ac.TimeStamp, Deal: deal, Accept: acp, Status: sts, PubKey: pk, Tip: ttip, Error: eif, AllReply: arl, WorkId: wid}

	e, err := Encode2(ac2)
	if err != nil {
		fmt.Printf("%v =====================AcceptReqAddr,encode fail,err = %v,key = %v ======================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:encode accept data fail", err
	}

	es, err := Compress([]byte(e))
	if err != nil {
		fmt.Printf("%v =====================AcceptReqAddr,compress fail,err = %v,key = %v ======================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:compress accept data fail", err
	}

	kdtmp := KeyData{Key: []byte(key), Data: es}
	PubKeyDataChan <- kdtmp

	LdbPubKeyData.WriteMap(key, []byte(es))
	return "", nil
}

//if accept == "",don't set Accept
//if status == "",don't set Status
//if outhash == "",don't set OutHash
//if tip == "",don't set Tip
//if errinfo == "",don't set ErrInfo
//if allreply == "",don't set AllReply
func AcceptLockOut(account string, groupid string, nonce string, dcrmfrom string, threshold string, deal bool, accept string, status string, outhash string, tip string, errinfo string, allreply []NodeReply, workid int) (string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + groupid + ":" + nonce + ":" + dcrmfrom + ":" + threshold))).Hex()
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		fmt.Printf("%v =====================AcceptLockOut, no exist key = %v =================================\n", common.CurrentTime(), key)
		return "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	ds, err := UnCompress(string(da))
	if err != nil {
		fmt.Printf("%v =====================AcceptLockOut, uncompress fail,err = %v, key = %v =================================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:uncompress accept data fail", err
	}

	dss, err := Decode2(ds, "AcceptLockOutData")
	if err != nil {
		fmt.Printf("%v =====================AcceptLockOut, decode fail,err = %v, key = %v =================================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:decode accept data fail", err
	}

	ac := dss.(*AcceptLockOutData)

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
	if allreply != nil && len(allreply) != 0 {
		arl = allreply
	}

	wid := ac.WorkId
	if workid >= 0 {
		wid = workid
	}

	ac2 := &AcceptLockOutData{Account: ac.Account, GroupId: ac.GroupId, Nonce: ac.Nonce, DcrmFrom: ac.DcrmFrom, DcrmTo: ac.DcrmTo, Value: ac.Value, Cointype: ac.Cointype, LimitNum: ac.LimitNum, Mode: ac.Mode, TimeStamp: ac.TimeStamp, Deal: deal, Accept: acp, Status: sts, OutTxHash: ah, Tip: ttip, Error: eif, AllReply: arl, WorkId: wid}

	e, err := Encode2(ac2)
	if err != nil {
		fmt.Printf("%v =====================AcceptLockOut, encode fail,err = %v, key = %v =================================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:encode accept data fail", err
	}

	es, err := Compress([]byte(e))
	if err != nil {
		fmt.Printf("%v =====================AcceptLockOut, compress fail,err = %v, key = %v =================================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:compress accept data fail", err
	}

	kdtmp := KeyData{Key: []byte(key), Data: es}
	PubKeyDataChan <- kdtmp

	LdbPubKeyData.WriteMap(key, []byte(es))
	return "", nil
}

type LockOutReply struct {
	Enode string
	Reply string
}

type LockOutReplys struct {
	Replys []LockOutReply
}

func (self *RecvMsg) Run(workid int, ch chan interface{}) bool {
	if workid < 0 || workid >= RpcMaxWorker { //TODO
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
	/*msgdata, errdec := DecryptMsg(res) //for SendMsgToPeer
	if errdec == nil {
		res = msgdata
	}*///---tmp---
	////
	mm := strings.Split(res, Sep)
	if len(mm) >= 2 {
		//msg:  hash-enode:C1:X1:X2
		DisMsg(res)
		return true
	}

	res, err := UnCompress(res)
	if err != nil {
		fmt.Printf("%v ===================RecvMsg.Run,the msg is not hash-enode:C1:X1:X2, uncompress fail,msg hash = %v,err = %v ==============================\n", common.CurrentTime(), test, err)
		res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:uncompress data fail in RecvMsg.Run", Err: fmt.Errorf("uncompress data fail in recvmsg.run")}
		ch <- res2
		return false
	}

	r, err := Decode2(res, "SendMsg")
	if err != nil {
		fmt.Printf("%v ===================RecvMsg.Run,the msg is not hash-enode:C1:X1:X2, decode fail,msg hash = %v,err = %v ==============================\n", common.CurrentTime(), test, err)
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

		fmt.Printf("%v ===================RecvMsg.Run,the msg is not hash-enode:C1:X1:X2, msg hash = %v,wid = %v,key = %v ==============================\n", common.CurrentTime(), test, wid, rr.Nonce)

		//rpc_lockout
		if rr.MsgType == "rpc_lockout" {
			w := workers[workid]
			w.sid = rr.Nonce
			//msg = fusionaccount:dcrmaddr:dcrmto:value:cointype:groupid:nonce:threshold:mode:key:timestamp
			msg := rr.Msg
			msgs := strings.Split(msg, ":")
			w.groupid = msgs[5]
			w.limitnum = msgs[7]
			w.NodeCnt, _ = GetGroup(w.groupid)
			w.ThresHold = w.NodeCnt

			if strings.EqualFold(cur_enode, self.sender) { //self send
				AcceptLockOut(msgs[0], msgs[5], msgs[6], msgs[1], msgs[7], false, "false", "Pending", "", "", "", nil, wid)
			} else {
				//nonce check
				exsit,_ := GetValueFromPubKeyData(rr.Nonce)
				///////
				if exsit == true {
					fmt.Printf("%v ================RecvMsg.Run,lockout nonce error, key = %v ==================\n", common.CurrentTime(), rr.Nonce)
					//TODO must set acceptlockout(.....)
					res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:lockout tx nonce error", Err: fmt.Errorf("lockout tx nonce error")}
					ch <- res2
					return false
				}

				cur_nonce, _, _ := GetLockOutNonce(msgs[0], msgs[4], msgs[1])
				cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
				new_nonce_num, _ := new(big.Int).SetString(msgs[6], 10)
				if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
					_, err = SetLockOutNonce(msgs[0], msgs[4], msgs[1], msgs[6])
					if err != nil {
						fmt.Printf("%v ================RecvMsg.Run,set lockout nonce fail, key = %v ==================\n", common.CurrentTime(), rr.Nonce)
						//TODO must set acceptlockout(.....)
						res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:set lockout nonce fail in RecvMsg.Run", Err: fmt.Errorf("set lockout nonce fail in recvmsg.run")}
						ch <- res2
						return false
					}
				}

				//if msgs[8] == "0" {// self-group
				ars := GetAllReplyFromGroup(w.id,msgs[5],true)
				ac := &AcceptLockOutData{Account: msgs[0], GroupId: msgs[5], Nonce: msgs[6], DcrmFrom: msgs[1], DcrmTo: msgs[2], Value: msgs[3], Cointype: msgs[4], LimitNum: msgs[7], Mode: msgs[8], TimeStamp: msgs[10], Deal: false, Accept: "false", Status: "Pending", OutTxHash: "", Tip: "", Error: "", AllReply: ars, WorkId: wid}
				err := SaveAcceptLockOutData(ac)
				fmt.Printf("%v ===================finish call SaveAcceptLockOutData, err = %v,wid = %v,account = %v,group id = %v,nonce = %v,dcrm from = %v,dcrm to = %v,value = %v,cointype = %v,threshold = %v,mode = %v,key = %v =========================\n", common.CurrentTime(), err, wid, msgs[0], msgs[5], msgs[6], msgs[1], msgs[2], msgs[3], msgs[4], msgs[7], msgs[8], rr.Nonce)
				if err != nil {
					res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:set AcceptLockOutData fail in RecvMsg.Run", Err: fmt.Errorf("set AcceptLockOutData fail in recvmsg.run")}
					ch <- res2
					return false
				}
				////
				dcrmkey := Keccak256Hash([]byte(strings.ToLower(msgs[1]))).Hex()
				exsit,da := GetValueFromPubKeyData(dcrmkey)
				if exsit {
				    ss, err := UnCompress(string(da))
				    if err == nil {
					pubs, err := Decode2(ss, "PubKeyData")
					if err == nil {
					    dcrmpub := (pubs.(*PubKeyData)).Pub
					    exsit,da2 := GetValueFromPubKeyData(dcrmpub)
					    if exsit {
						ss2, err := UnCompress(string(da2))
						if err == nil {
						    pubs2, err := Decode2(ss2, "PubKeyData")
						    if err == nil {
							keys := (pubs2.(*PubKeyData)).RefLockOutKeys
							if keys == "" {
							    keys = rr.Nonce
							} else {
							    keys = keys + ":" + rr.Nonce
							}

							pubs3 := &PubKeyData{Key:(pubs2.(*PubKeyData)).Key,Account: (pubs2.(*PubKeyData)).Account, Pub: (pubs2.(*PubKeyData)).Pub, Save: (pubs2.(*PubKeyData)).Save, Nonce: (pubs2.(*PubKeyData)).Nonce, GroupId: (pubs2.(*PubKeyData)).GroupId, LimitNum: (pubs2.(*PubKeyData)).LimitNum, Mode: (pubs2.(*PubKeyData)).Mode,RefLockOutKeys:keys}
							epubs, err := Encode2(pubs3)
							if err == nil {
							    ss3, err := Compress([]byte(epubs))
							    if err == nil {
								kd := KeyData{Key: []byte(dcrmpub), Data: ss3}
								PubKeyDataChan <- kd
								LdbPubKeyData.WriteMap(dcrmpub, []byte(ss3))
								fmt.Printf("%v ==============================RecvMsg.Run,reset PubKeyData success, key = %v ============================================\n", common.CurrentTime(),rr.Nonce)
							    }
							}
						    }
						}
					    }
					}
				    }
				}
				////
			}

			////bug
			if msgs[8] == "0" { // self-group
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
							//tip, reply = GetAcceptLockOutRes(msgs[0], msgs[5], msgs[6], msgs[1], msgs[7])
							ars := GetAllReplyFromGroup(w.id,msgs[5],true)
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

							if reply == false {
								tip = "don't accept lockout"
								AcceptLockOut(msgs[0], msgs[5], msgs[6], msgs[1], msgs[7], false, "false", "Failure", "", "don't accept lockout", "don't accept lockout", ars, wid)
							} else {
								tip = ""
								AcceptLockOut(msgs[0], msgs[5], msgs[6], msgs[1], msgs[7], false, "true", "Pending", "", "", "", ars, wid)
							}

							///////
							timeout <- true
							return
						case <-agreeWaitTimeOut.C:
							fmt.Printf("%v ================== (self *RecvMsg) Run() , agree wait timeout. key = %v,=====================\n", common.CurrentTime(), rr.Nonce)
							ars := GetAllReplyFromGroup(w.id,msgs[5],true)
							//bug: if self not accept and timeout
							AcceptLockOut(msgs[0], msgs[5], msgs[6], msgs[1], msgs[7], false, "false", "Timeout", "", "get other node accept lockout result timeout", "get other node accept lockout result timeout", ars, wid)
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

				fmt.Printf("%v ================== (self *RecvMsg) Run() , the terminal accept lockout result = %v,key = %v,============================\n", common.CurrentTime(), reply, rr.Nonce)

				if reply == false {
					//////////////////////lockout result start/////////////////////////
					if tip == "get other node accept lockout result timeout" {
						ars := GetAllReplyFromGroup(w.id,msgs[5],true)
						AcceptLockOut(msgs[0], msgs[5], msgs[6], msgs[1], msgs[7], false, "", "Timeout", "", "get other node accept lockout result timeout", "get other node accept lockout result timeout", ars, wid)
					} else {
						/////////////TODO tmp
						//sid-enode:SendLockOutRes:Success:lockout_tx_hash
						//sid-enode:SendLockOutRes:Fail:err
						mp := []string{w.sid, cur_enode}
						enode := strings.Join(mp, "-")
						s0 := "SendLockOutRes"
						s1 := "Fail"
						s2 := "don't accept lockout."
						ss := enode + Sep + s0 + Sep + s1 + Sep + s2
						SendMsgToDcrmGroup(ss, w.groupid)
						fmt.Printf("%v ================RecvMsg.Run,send SendLockOutRes msg to other nodes finish,key = %v =============\n", common.CurrentTime(), rr.Nonce)
						_, _, err := GetChannelValue(ch_t, w.bsendlockoutres)
						fmt.Printf("%v ================RecvMsg.Run,the SendLockOutRes result from other nodes, err = %v,key = %v =============\n", common.CurrentTime(), err, rr.Nonce)
						ars := GetAllReplyFromGroup(w.id,msgs[5],true)
						if err != nil {
							tip = "get other node terminal accept lockout result timeout" ////bug
							AcceptLockOut(msgs[0], msgs[5], msgs[6], msgs[1], msgs[7], false, "", "Timeout", "", tip, tip, ars, wid)
						} else if w.msg_sendlockoutres.Len() != (w.NodeCnt - 1) {
							fmt.Printf("%v ================RecvMsg,the result SendLockOutRes msg from other nodes fail,key = %v =======================\n", common.CurrentTime(), rr.Nonce)
							AcceptLockOut(msgs[0], msgs[5], msgs[6], msgs[1], msgs[7], false, "", "Failure", "", "get other node lockout result fail", "get other node lockout result fail", ars, wid)
						} else {
							reply2 := "false"
							lohash := ""
							iter := w.msg_sendlockoutres.Front()
							for iter != nil {
								mdss := iter.Value.(string)
								ms := strings.Split(mdss, Sep)
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
								fmt.Printf("%v ================RecvMsg,the terminal lockout res is success. key = %v ==================\n", common.CurrentTime(), rr.Nonce)
								AcceptLockOut(msgs[0], msgs[5], msgs[6], msgs[1], msgs[7], true, "true", "Success", lohash, " ", " ", ars, wid)
							} else {
								fmt.Printf("%v ================RecvMsg,the terminal lockout res is fail. key = %v ==================\n", common.CurrentTime(), rr.Nonce)
								AcceptLockOut(msgs[0], msgs[5], msgs[6], msgs[1], msgs[7], false, "", "Failure", "", lohash, lohash, ars, wid)
							}
						}
						/////////////////////
					}
					///////////////////////lockout result end////////////////////////

					res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + Sep + rr.MsgType, Tip: tip, Err: fmt.Errorf("don't accept lockout.")}
					ch <- res2
					return false
				}
			} else {
				if len(workers[wid].acceptWaitLockOutChan) == 0 {
					workers[wid].acceptWaitLockOutChan <- "go on"
				}

				if !strings.EqualFold(cur_enode, self.sender) { //no self send
					ars := GetAllReplyFromGroup(w.id,msgs[5],true)
					AcceptLockOut(msgs[0], msgs[5], msgs[6], msgs[1], msgs[7], false, "true", "Pending", "", "", "", ars, wid)
				}
			}

			rch := make(chan interface{}, 1)
			//msg = fusionaccount:dcrmaddr:dcrmto:value:cointype:groupid:nonce:threshold:mode:key:timestamp
			fmt.Printf("%v ================== (self *RecvMsg) Run() , start call validate_lockout,key = %v,=====================\n", common.CurrentTime(), rr.Nonce)
			validate_lockout(w.sid, msgs[0], msgs[1], msgs[4], msgs[3], msgs[2], msgs[6], rch)
			fmt.Printf("%v ================== (self *RecvMsg) Run() , finish call validate_lockout,key = %v ============================\n", common.CurrentTime(), rr.Nonce)
			chret, tip, cherr := GetChannelValue(ch_t, rch)
			fmt.Printf("%v ================== (self *RecvMsg) Run() , finish and get validate_lockout return value = %v,err = %v,key = %v ============================\n", common.CurrentTime(), chret, cherr, rr.Nonce)
			if chret != "" {
				res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + Sep + rr.MsgType + Sep + chret, Tip: "", Err: nil}
				ch <- res2
				return true
			}

			//////////////////////lockout result start/////////////////////////
			ars := GetAllReplyFromGroup(w.id,msgs[5],true)
			if tip == "get other node accept lockout result timeout" {
				AcceptLockOut(msgs[0], msgs[5], msgs[6], msgs[1], msgs[7], false, "", "Timeout", "", tip, cherr.Error(), ars, wid)
			} else {
				/////////////TODO tmp
				//sid-enode:SendLockOutRes:Success:lockout_tx_hash
				//sid-enode:SendLockOutRes:Fail:err
				mp := []string{w.sid, cur_enode}
				enode := strings.Join(mp, "-")
				s0 := "SendLockOutRes"
				s1 := "Fail"
				s2 := cherr.Error()
				ss := enode + Sep + s0 + Sep + s1 + Sep + s2
				SendMsgToDcrmGroup(ss, w.groupid)
				fmt.Printf("%v ================RecvMsg.Run,send SendLockOutRes msg to other nodes finish,key = %v =============\n", common.CurrentTime(), rr.Nonce)
				_, _, err := GetChannelValue(ch_t, w.bsendlockoutres)
				fmt.Printf("%v ================RecvMsg.Run,the SendLockOutRes result from other nodes finish,key = %v =============\n", common.CurrentTime(), rr.Nonce)
				if err != nil {
					tip = "get other node terminal accept lockout result timeout" ////bug
					AcceptLockOut(msgs[0], msgs[5], msgs[6], msgs[1], msgs[7], false, "", "Timeout", "", tip, tip, ars, wid)
				} else if w.msg_sendlockoutres.Len() != (w.NodeCnt - 1) {
					fmt.Printf("%v ================RecvMsg.Run,the SendLockOutRes result from other nodes fail,key = %v =============\n", common.CurrentTime(), rr.Nonce)
					AcceptLockOut(msgs[0], msgs[5], msgs[6], msgs[1], msgs[7], false, "", "Failure", "", "get other node lockout result fail", "get other node lockout result fail", ars, wid)
				} else {
					reply2 := "false"
					lohash := ""
					iter := w.msg_sendlockoutres.Front()
					for iter != nil {
						mdss := iter.Value.(string)
						ms := strings.Split(mdss, Sep)
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
						fmt.Printf("%v ================RecvMsg,the terminal lockout res is success. key = %v ==================\n", common.CurrentTime(), rr.Nonce)
						AcceptLockOut(msgs[0], msgs[5], msgs[6], msgs[1], msgs[7], true, "true", "Success", lohash, " ", " ", ars, wid)
					} else {
						fmt.Printf("%v ================RecvMsg,the terminal lockout res is fail. key = %v ==================\n", common.CurrentTime(), rr.Nonce)
						AcceptLockOut(msgs[0], msgs[5], msgs[6], msgs[1], msgs[7], false, "", "Failure", "", lohash, lohash, ars, wid)
					}
				}
				/////////////////////
			}
			///////////////////////lockout result end////////////////////////

			if cherr != nil {
				res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + Sep + rr.MsgType, Tip: tip, Err: cherr}
				ch <- res2
				return false
			}

			fmt.Printf("%v ==============RecvMsg.Run,LockOut send tx to net fail, key = %v =======================\n", common.CurrentTime(), rr.Nonce)
			res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + Sep + rr.MsgType, Tip: tip, Err: fmt.Errorf("send tx to net fail.")}
			ch <- res2
			return true
		}

		//rpc_req_dcrmaddr
		if rr.MsgType == "rpc_req_dcrmaddr" {
			//msg = account:cointype:groupid:nonce:threshold:mode:key:timestamp
			rch := make(chan interface{}, 1)
			w := workers[workid]
			w.sid = rr.Nonce

			msgs := strings.Split(rr.Msg, ":")
			w.groupid = msgs[2]
			w.limitnum = msgs[4]
			w.NodeCnt, _ = GetGroup(w.groupid)
			w.ThresHold = w.NodeCnt

			if strings.EqualFold(cur_enode, self.sender) { //self send
				AcceptReqAddr(msgs[0], msgs[1], msgs[2], msgs[3], msgs[4], msgs[5], false, "false", "Pending", "", "", "", nil, wid)
			} else {
				//nonce check
				exsit,_ := GetValueFromPubKeyData(rr.Nonce)
				if exsit == true {
					fmt.Printf("%v =======================RecvMsg.Run,req addr nonce error, account = %v,group id = %v,threshold = %v,mode = %v,nonce = %v,key = %v =========================\n", common.CurrentTime(), msgs[0], msgs[2], msgs[4], msgs[5], msgs[3], rr.Nonce)
					//TODO must set acceptreqaddr(.....)
					res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:req addr nonce error", Err: fmt.Errorf("req addr nonce error")}
					ch <- res2
					return false
				}

				cur_nonce, _, _ := GetReqAddrNonce(msgs[0])
				cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
				new_nonce_num, _ := new(big.Int).SetString(msgs[3], 10)
				if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
					_, err = SetReqAddrNonce(msgs[0], msgs[3])
					fmt.Printf("%v =======================RecvMsg.Run,SetReqAddrNonce, account = %v,group id = %v,threshold = %v,mode = %v,nonce = %v,err = %v,key = %v =========================\n", common.CurrentTime(), msgs[0], msgs[2], msgs[4], msgs[5], msgs[3], err, rr.Nonce)
					if err != nil {
						//TODO must set acceptreqaddr(.....)
						res2 := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:set req addr nonce fail in RecvMsg.Run", Err: fmt.Errorf("set req addr nonce fail in recvmsg.run")}
						ch <- res2
						return false
					}
				}

				//if msgs[5] == "0" {// self-group
				ars := GetAllReplyFromGroup(w.id,msgs[2],false)	
				ac := &AcceptReqAddrData{Account: msgs[0], Cointype: "ALL", GroupId: msgs[2], Nonce: msgs[3], LimitNum: msgs[4], Mode: msgs[5], TimeStamp: msgs[7], Deal: false, Accept: "false", Status: "Pending", PubKey: "", Tip: "", Error: "", AllReply: ars, WorkId: wid}
				err := SaveAcceptReqAddrData(ac)
				fmt.Printf("%v ===================call SaveAcceptReqAddrData finish, wid = %v,account = %v,cointype = %v,group id = %v,nonce = %v, threshold = %v,mode = %v,err = %v,key = %v,msg hash = %v, ========================\n", common.CurrentTime(), wid, msgs[0], msgs[1], msgs[2], msgs[3], msgs[4], msgs[5], err, rr.Nonce, test)
				if err != nil {
					////TODO
				}

				if msgs[5] == "1" {
				    exsit,da := GetValueFromPubKeyData(strings.ToLower(msgs[0]))
				    if exsit == false {
					kdtmp := KeyData{Key: []byte(strings.ToLower(msgs[0])), Data: rr.Nonce}
					PubKeyDataChan <- kdtmp
					LdbPubKeyData.WriteMap(strings.ToLower(msgs[0]), []byte(rr.Nonce))
				    } else {
					//
					found := false
					keys := strings.Split(string(da),":")
					for _,v := range keys {
					    if strings.EqualFold(v,rr.Nonce) {
						found = true
						break
					    }
					}
					//
					if !found {
					    da2 := string(da) + ":" + rr.Nonce
					    kdtmp := KeyData{Key: []byte(strings.ToLower(msgs[0])), Data: da2}
					    PubKeyDataChan <- kdtmp
					    LdbPubKeyData.WriteMap(strings.ToLower(msgs[0]), []byte(da2))
					}
				    }
				}
				//}
				////
			}

			if msgs[5] == "0" { // self-group
				////
				var reply bool
				var tip string
				timeout := make(chan bool, 1)
				go func(wid int) {
					cur_enode = discover.GetLocalID().String() //GetSelfEnode()
					agreeWaitTime := 10 * time.Minute
					agreeWaitTimeOut := time.NewTicker(agreeWaitTime)
					if wid < 0 || wid >= len(workers) || workers[wid] == nil {
						ars := GetAllReplyFromGroup(w.id,msgs[2],false)	
						AcceptReqAddr(msgs[0], msgs[1], msgs[2], msgs[3], msgs[4], msgs[5], false, "false", "Failure", "", "workid error", "workid error", ars, wid)
						tip = "worker id error"
						reply = false
						timeout <- true
						return
					}

					wtmp2 := workers[wid]
					fmt.Printf("%v ================== (self *RecvMsg) Run(),wid = %v,key = %v ============================\n", common.CurrentTime(), wid, rr.Nonce)

					for {
						select {
						case account := <-wtmp2.acceptReqAddrChan:
							common.Debug("(self *RecvMsg) Run(),", "account= ", account, "key = ", rr.Nonce)
							//tip, reply = GetAcceptReqAddrRes(msgs[0], msgs[1], msgs[2], msgs[3], msgs[4], msgs[5])
							ars := GetAllReplyFromGroup(w.id,msgs[2],false)	
							fmt.Printf("%v ================== (self *RecvMsg) Run(),get all AcceptReqAddrRes, result = %v,key = %v ============================\n", common.CurrentTime(), ars, rr.Nonce)
							
							//bug
							reply = true
							for _,nr := range ars {
							    if !strings.EqualFold(nr.Status,"Agree") {
								reply = false
								break
							    }
							}
							//

							if reply == false {
								tip = "don't accept req addr"
								AcceptReqAddr(msgs[0], msgs[1], msgs[2], msgs[3], msgs[4], msgs[5], false, "false", "Failure", "", "don't accept req addr", "don't accept req addr", ars, wid)
							} else {
								tip = ""
								AcceptReqAddr(msgs[0], msgs[1], msgs[2], msgs[3], msgs[4], msgs[5], false, "true", "Pending", "", "", "", ars, wid)
							}

							///////
							timeout <- true
							return
						case <-agreeWaitTimeOut.C:
							fmt.Printf("%v ================== (self *RecvMsg) Run(), agree wait timeout, key = %v ============================\n", common.CurrentTime(), rr.Nonce)
							ars := GetAllReplyFromGroup(w.id,msgs[2],false)	
							//bug: if self not accept and timeout
							AcceptReqAddr(msgs[0], msgs[1], msgs[2], msgs[3], msgs[4], msgs[5], false, "false", "Timeout", "", "get other node accept req addr result timeout", "get other node accept req addr result timeout", ars, wid)
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

				<-timeout

				fmt.Printf("%v ================== (self *RecvMsg) Run(), the terminal accept req addr result = %v, key = %v ============================\n", common.CurrentTime(), reply, rr.Nonce)

				ars := GetAllReplyFromGroup(w.id,msgs[2],false)	
				if reply == false {
					if tip == "get other node accept req addr result timeout" {
						AcceptReqAddr(msgs[0], msgs[1], msgs[2], msgs[3], msgs[4], msgs[5], false, "", "Timeout", "", tip, "don't accept req addr.", ars, wid)
					} else {
						AcceptReqAddr(msgs[0], msgs[1], msgs[2], msgs[3], msgs[4], msgs[5], false, "", "Failure", "", tip, "don't accept req addr.", ars, wid)
					}

					res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + Sep + rr.MsgType, Tip: tip, Err: fmt.Errorf("don't accept req addr.")}
					ch <- res2
					return false
				}
			} else {
				if len(workers[wid].acceptWaitReqAddrChan) == 0 {
					workers[wid].acceptWaitReqAddrChan <- "go on"
				}

				if !strings.EqualFold(cur_enode, self.sender) { //no self send
					ars := GetAllReplyFromGroup(w.id,msgs[2],false)	
					AcceptReqAddr(msgs[0], msgs[1], msgs[2], msgs[3], msgs[4], msgs[5], false, "true", "Pending", "", "", "", ars, wid)
				}
			}

			///////////////////////
			/*if msgs[5] == "0" {
				timeout2 := make(chan bool, 1)
				go func(rk string) {
					for {
						_, exsit := GAccs.ReadMap(rk)
						if exsit == false {
							time.Sleep(time.Duration(1) * time.Second) //1000 == 1s
						} else {
							timeout2 <- true
							break
						}
					}
				}(rr.Nonce)

				fmt.Printf("%v ================== (self *RecvMsg) Run(), start wait group accounts, key = %v ============================\n", common.CurrentTime(), rr.Nonce)
				_, _, err = GetChannelValue(50, timeout2)
				fmt.Printf("%v ================== (self *RecvMsg) Run(), finish wait group accounts, err = %v,key = %v ============================\n", common.CurrentTime(), err, rr.Nonce)
				if err != nil {
					ars := GetAllReplyFromGroup(w.id,msgs[2],false)	
					AcceptReqAddr(msgs[0], msgs[1], msgs[2], msgs[3], msgs[4], msgs[5], false, "false", "Failure", "", "get group account sigs data timeout", "get group account sigs data timeout", ars, wid)
					res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + Sep + rr.MsgType, Tip: "get group account sigs data timeout", Err: fmt.Errorf("get group account sigs data timeout")}
					ch <- res2
					return false
				}
			}*/
			///////////////////////

			fmt.Printf("%v ================== (self *RecvMsg) Run(), start call dcrm_genPubKey,key = %v ============================\n", common.CurrentTime(), rr.Nonce)
			dcrm_genPubKey(w.sid, msgs[0], msgs[1], rch, msgs[5], msgs[3])
			fmt.Printf("%v ================== (self *RecvMsg) Run(), finish call dcrm_genPubKey,key = %v ============================\n", common.CurrentTime(), rr.Nonce)
			chret, tip, cherr := GetChannelValue(ch_t, rch)
			fmt.Printf("%v ================== (self *RecvMsg) Run() , finish dcrm_genPubKey,get return value = %v,err = %v,key = %v,=====================\n", common.CurrentTime(), chret, cherr, rr.Nonce)
			if cherr != nil {
				ars := GetAllReplyFromGroup(w.id,msgs[2],false)	
				AcceptReqAddr(msgs[0], msgs[1], msgs[2], msgs[3], msgs[4], msgs[5], false, "", "Failure", "", tip, cherr.Error(), ars, wid)
				res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + Sep + rr.MsgType, Tip: tip, Err: cherr}
				ch <- res2
				return false
			}

			res2 := RpcDcrmRes{Ret: strconv.Itoa(rr.WorkId) + Sep + rr.MsgType + Sep + chret, Tip: "", Err: nil}
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
	Nonce   string
	WorkId  int
	Msg     string
}

type PubKeyData struct {
        Key string
	Account  string
	Pub      string
	Save     string
	Nonce    string
	GroupId  string
	LimitNum string
	Mode     string
	RefLockOutKeys string //key1:key2...
}

func Encode2(obj interface{}) (string, error) {
	switch obj.(type) {
	case *SendMsg:
		/*ch := obj.(*SendMsg)
		ret,err := json.Marshal(ch)
		if err != nil {
		    return "",err
		}
		return string(ret),nil*/
		ch := obj.(*SendMsg)

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil
	case *PubKeyData:
		ch := obj.(*PubKeyData)

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil
	case *AcceptLockOutData:
		ch := obj.(*AcceptLockOutData)

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil
	case *AcceptReqAddrData:
		ch := obj.(*AcceptReqAddrData)
		ret,err := json.Marshal(ch)
		if err != nil {
		    return "",err
		}
		return string(ret),nil
		/*ch := obj.(*AcceptReqAddrData)

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil*/
	default:
		return "", fmt.Errorf("encode obj fail.")
	}
}

func Decode2(s string, datatype string) (interface{}, error) {

	if datatype == "SendMsg" {
		/*var m SendMsg
		err := json.Unmarshal([]byte(s), &m)
		if err != nil {
		    fmt.Println("================Decode2,json Unmarshal err =%v===================",err)
		    return nil,err
		}

		return &m,nil*/
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res SendMsg
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "PubKeyData" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res PubKeyData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "AcceptLockOutData" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res AcceptLockOutData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "AcceptReqAddrData" {
		var m AcceptReqAddrData
		err := json.Unmarshal([]byte(s), &m)
		if err != nil {
		    return nil,err
		}

		return &m,nil
		/*var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res AcceptReqAddrData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil*/
	}

	return nil, fmt.Errorf("decode obj fail.")
}

///////

////compress
func Compress(c []byte) (string, error) {
	if c == nil {
		return "", fmt.Errorf("compress fail.")
	}

	var in bytes.Buffer
	w, err := zlib.NewWriterLevel(&in, zlib.BestCompression-1)
	if err != nil {
		return "", err
	}

	w.Write(c)
	w.Close()

	s := in.String()
	return s, nil
}

////uncompress
func UnCompress(s string) (string, error) {

	if s == "" {
		return "", fmt.Errorf("param error.")
	}

	var data bytes.Buffer
	data.Write([]byte(s))

	r, err := zlib.NewReader(&data)
	if err != nil {
		return "", err
	}

	var out bytes.Buffer
	io.Copy(&out, r)
	return out.String(), nil
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
	Account   string
	Cointype  string
	GroupId   string
	Nonce     string
	LimitNum  string
	Mode      string
	TimeStamp string
	Key       string
}

func (self *ReqAddrSendMsgToDcrm) Run(workid int, ch chan interface{}) bool {
	if workid < 0 || workid >= RpcMaxWorker {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no worker id", Err: GetRetErr(ErrGetWorkerIdError)}
		ch <- res
		return false
	}

	cur_enode = discover.GetLocalID().String() //GetSelfEnode()
	msg := self.Account + ":" + self.Cointype + ":" + self.GroupId + ":" + self.Nonce + ":" + self.LimitNum + ":" + self.Mode + ":" + self.Key + ":" + self.TimeStamp

	sm := &SendMsg{MsgType: "rpc_req_dcrmaddr", Nonce: self.Key, WorkId: workid, Msg: msg}
	res, err := Encode2(sm)
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:encode SendMsg fail in req addr", Err: err}
		ch <- res
		return false
	}

	res, err = Compress([]byte(res))
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:compress SendMsg data fail in req addr", Err: err}
		ch <- res
		return false
	}

	w := workers[workid]

	for i := 0; i < ReSendTimes; i++ {
		test := Keccak256Hash([]byte(strings.ToLower(res))).Hex()
		fmt.Printf("%v ===================ReqAddrSendMsgToDcrm.Run, begin send msg to all nodes. msg hash = %v,key = %v============================\n", common.CurrentTime(), test, self.Key)

		SendToGroupAllNodes(self.GroupId, res)
	}

	fmt.Printf("%v ===================ReqAddrSendMsgToDcrm.Run, Waiting For Result.key = %v============================\n", common.CurrentTime(), self.Key)
	<-w.acceptWaitReqAddrChan

	tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
	///////
	if self.Mode == "0" {
		mp := []string{self.Key, cur_enode}
		enode := strings.Join(mp, "-")
		s0 := "AcceptReqAddrRes"
		s1 := "true"
		ss := enode + Sep + s0 + Sep + s1 + Sep + tt
		SendMsgToDcrmGroup(ss, self.GroupId)
		DisMsg(ss)
		fmt.Printf("%v ===================ReqAddrSendMsgToDcrm.Run, finish send AcceptReqAddrRes to other nodes. key = %v============================\n", common.CurrentTime(), self.Key)
	}

	time.Sleep(time.Duration(1) * time.Second)
	ars := GetAllReplyFromGroup(-1,self.GroupId,false)	
	AcceptReqAddr(self.Account, self.Cointype, self.GroupId, self.Nonce, self.LimitNum, self.Mode, false, "true", "Pending", "", "", "", ars, workid)
	fmt.Printf("%v ===================ReqAddrSendMsgToDcrm.Run, finish agree this req addr oneself.key = %v============================\n", common.CurrentTime(), self.Key)
	chret, tip, cherr := GetChannelValue(sendtogroup_timeout, w.ch)
	fmt.Printf("%v ===================ReqAddrSendMsgToDcrm.Run, Get Result. result = %v,cherr = %v,key = %v============================\n", common.CurrentTime(), chret, cherr, self.Key)
	if cherr != nil {
		res2 := RpcDcrmRes{Ret: chret, Tip: tip, Err: cherr}
		ch <- res2
		return false
	}

	res2 := RpcDcrmRes{Ret: chret, Tip: tip, Err: cherr}
	ch <- res2

	return true
}

//msg = fusionaccount:dcrmaddr:dcrmto:value:cointype:groupid:nonce:threshold
type LockOutSendMsgToDcrm struct {
	Account   string
	DcrmFrom  string
	DcrmTo    string
	Value     string
	Cointype  string
	GroupId   string
	Nonce     string
	LimitNum  string
	Mode      string
	TimeStamp string
	Key       string
}

func (self *LockOutSendMsgToDcrm) Run(workid int, ch chan interface{}) bool {
	if workid < 0 || workid >= RpcMaxWorker {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get worker id error", Err: GetRetErr(ErrGetWorkerIdError)}
		ch <- res
		return false
	}

	cur_enode = discover.GetLocalID().String() //GetSelfEnode()
	msg := self.Account + ":" + self.DcrmFrom + ":" + self.DcrmTo + ":" + self.Value + ":" + self.Cointype + ":" + self.GroupId + ":" + self.Nonce + ":" + self.LimitNum + ":" + self.Mode + ":" + self.Key + ":" + self.TimeStamp

	sm := &SendMsg{MsgType: "rpc_lockout", Nonce: self.Key, WorkId: workid, Msg: msg}
	res, err := Encode2(sm)
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:encode SendMsg fail in lockout", Err: err}
		ch <- res
		return false
	}

	res, err = Compress([]byte(res))
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:compress SendMsg data error in lockout", Err: err}
		ch <- res
		return false
	}

	for i := 0; i < ReSendTimes; i++ {
		test := Keccak256Hash([]byte(strings.ToLower(res))).Hex()
		fmt.Printf("%v ===================LockOutSendMsgToDcrm.Run,begin send msg to all nodes. msg hash = %v,key = %v ====================\n", common.CurrentTime(), test, self.Key)

		SendToGroupAllNodes(self.GroupId, res)
	}

	w := workers[workid]
	////
	fmt.Printf("%v =============LockOutSendMsgToDcrm.Run,Waiting For Result, key = %v ========================\n", common.CurrentTime(), self.Key)
	<-w.acceptWaitLockOutChan
	var tip string

	///////
	tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
	if self.Mode == "0" {
		mp := []string{self.Key, cur_enode}
		enode := strings.Join(mp, "-")
		s0 := "AcceptLockOutRes"
		s1 := "true"
		ss := enode + Sep + s0 + Sep + s1 + Sep + tt
		SendMsgToDcrmGroup(ss, self.GroupId)
		DisMsg(ss)
		fmt.Printf("%v ================== LockOutSendMsgToDcrm.Run , finish send AcceptLockOutRes to other nodes, key = %v ============================\n", common.CurrentTime(), self.Key)
	}

	time.Sleep(time.Duration(1) * time.Second)
	ars := GetAllReplyFromGroup(-1,self.GroupId,true)
	AcceptLockOut(self.Account, self.GroupId, self.Nonce, self.DcrmFrom, self.LimitNum, false, "true", "Pending", "", "", "", ars, workid)
	fmt.Printf("%v ===================LockOutSendMsgToDcrm.Run, finish agree this lockout oneself. key = %v ============================\n", common.CurrentTime(), self.Key)
	
	chret, tip, cherr := GetChannelValue(sendtogroup_lilo_timeout, w.ch)
	fmt.Printf("%v ==============LockOutSendMsgToDcrm.Run,Get Result = %v, err = %v, key = %v =================\n", common.CurrentTime(), chret, cherr, self.Key)
	if cherr != nil {
		res2 := RpcDcrmRes{Ret: "", Tip: tip, Err: cherr}
		ch <- res2
		return false
	}

	res2 := RpcDcrmRes{Ret: chret, Tip: tip, Err: cherr}
	ch <- res2

	return true
}

type GetCurNodeReqAddrInfoSendMsgToDcrm struct {
	Account string //geter_acc
}

func (self *GetCurNodeReqAddrInfoSendMsgToDcrm) Run(workid int, ch chan interface{}) bool {
	if workid < 0 || workid >= RpcMaxWorker {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get worker id fail", Err: GetRetErr(ErrGetWorkerIdError)}
		ch <- res
		return false
	}

	ret, tip, err := GetCurNodeReqAddrInfo(self.Account)
	if err != nil {
		res2 := RpcDcrmRes{Ret: "", Tip: tip, Err: err}
		ch <- res2
		return false
	}

	res2 := RpcDcrmRes{Ret: ret, Tip: "", Err: nil}
	ch <- res2

	return true
}

type GetCurNodeLockOutInfoSendMsgToDcrm struct {
	Account string //geter_acc
}

func (self *GetCurNodeLockOutInfoSendMsgToDcrm) Run(workid int, ch chan interface{}) bool {
	if workid < 0 || workid >= RpcMaxWorker {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get worker id fail", Err: GetRetErr(ErrGetWorkerIdError)}
		ch <- res
		return false
	}

	ret, tip, err := GetCurNodeLockOutInfo(self.Account)
	if err != nil {
		res2 := RpcDcrmRes{Ret: "", Tip: tip, Err: err}
		ch <- res2
		return false
	}

	res2 := RpcDcrmRes{Ret: ret, Tip: "", Err: nil}
	ch <- res2

	return true
}

func GetAllReplyFromGroup(wid int,gid string,lockout bool) []NodeReply {
    if gid == "" {
	return nil
    }

    var ars []NodeReply
    _, enodes := GetGroup(gid)
	fmt.Printf("==== dev.GetAllReplyFromGroup() ====, gid: %v, enodes: %v\n", gid, enodes)
    nodes := strings.Split(enodes, SepSg)
	fmt.Printf("==== dev.GetAllReplyFromGroup() ====, gid: %v, enodes: %v, split: %v, nodes: %v\n", gid, enodes, SepSg, nodes)
    
    if wid < 0 || wid >= len(workers) {
	for _, node := range nodes {
		fmt.Printf("==== dev.GetAllReplyFromGroup() ====, call ParseNode enode: %v\n", node)
		node2 := ParseNode(node)
		sta := "Pending"
		ts := ""
		nr := NodeReply{Enode:node2,Status:sta,TimeStamp:ts}
		ars = append(ars,nr)
	}

	return ars
    }

    w := workers[wid]
    if w == nil {
	return nil
    }

    if lockout == true {
	for _, node := range nodes {
		fmt.Printf("==== dev.GetAllReplyFromGroup() ==== 2 , call ParseNode enode: %v\n", node)
		node2 := ParseNode(node)
		sta := "Pending"
		ts := ""
		iter := w.msg_acceptlockoutres.Front()
		for iter != nil {
		    mdss := iter.Value.(string)
		    ms := strings.Split(mdss, Sep)
		    prexs := strings.Split(ms[0], "-")
		    node3 := prexs[1]
		    if strings.EqualFold(node3,node2) {
			if strings.EqualFold(ms[2],"false") {
			    sta = "DisAgree"
			} else {
			    sta = "Agree"
			}

			ts = ms[3]
			break
		    }
		    
		    iter = iter.Next()
		}
		
		nr := NodeReply{Enode:node2,Status:sta,TimeStamp:ts}
		ars = append(ars,nr)
	}
    } else {
	for _, node := range nodes {
		fmt.Printf("==== dev.GetAllReplyFromGroup() ==== 3 , call ParseNode enode: %v\n", node)
	    node2 := ParseNode(node)
	    sta := "Pending"
	    ts := ""
	    iter := w.msg_acceptreqaddrres.Front()
	    for iter != nil {
		mdss := iter.Value.(string)
		ms := strings.Split(mdss, Sep)
		prexs := strings.Split(ms[0], "-")
		node3 := prexs[1]
		if strings.EqualFold(node3,node2) {
		    if strings.EqualFold(ms[2],"false") {
			sta = "DisAgree"
		    } else {
			sta = "Agree"
		    }

		    ts = ms[3]
		    break
		}
		
		iter = iter.Next()
	    }
	    
	    nr := NodeReply{Enode:node2,Status:sta,TimeStamp:ts}
	    ars = append(ars,nr)
	}
    }

    return ars
}

type NodeReply struct {
    Enode string
    Status string
    TimeStamp string
}

type AcceptReqAddrData struct {
	Account   string
	Cointype  string
	GroupId   string
	Nonce     string
	LimitNum  string
	Mode      string
	TimeStamp string

	Deal   bool
	Accept string

	Status string
	PubKey string
	Tip    string
	Error  string

	AllReply []NodeReply

	WorkId int
}

func SaveAcceptReqAddrData(ac *AcceptReqAddrData) error {
	if ac == nil {
		return fmt.Errorf("no accept data.")
	}

	key := Keccak256Hash([]byte(strings.ToLower(ac.Account + ":" + ac.Cointype + ":" + ac.GroupId + ":" + ac.Nonce + ":" + ac.LimitNum + ":" + ac.Mode))).Hex()

	alos, err := Encode2(ac)
	if err != nil {
		return err
	}

	ss, err := Compress([]byte(alos))
	if err != nil {
		return err
	}

	kdtmp := KeyData{Key: []byte(key), Data: ss}
	PubKeyDataChan <- kdtmp

	LdbPubKeyData.WriteMap(key, []byte(ss))
	return nil
}

type AcceptLockOutData struct {
	Account   string
	GroupId   string
	Nonce     string
	DcrmFrom  string
	DcrmTo    string
	Value     string
	Cointype  string
	LimitNum  string
	Mode      string
	TimeStamp string

	Deal   bool
	Accept string

	Status    string
	OutTxHash string
	Tip       string
	Error     string

	AllReply []NodeReply
	WorkId   int
}

func SaveAcceptLockOutData(ac *AcceptLockOutData) error {
	if ac == nil {
		return fmt.Errorf("no accept data.")
	}

	key := Keccak256Hash([]byte(strings.ToLower(ac.Account + ":" + ac.GroupId + ":" + ac.Nonce + ":" + ac.DcrmFrom + ":" + ac.LimitNum))).Hex()

	alos, err := Encode2(ac)
	if err != nil {
		return err
	}

	ss, err := Compress([]byte(alos))
	if err != nil {
		return err
	}

	kdtmp := KeyData{Key: []byte(key), Data: ss}
	PubKeyDataChan <- kdtmp

	LdbPubKeyData.WriteMap(key, []byte(ss))
	return nil
}

func CommitRpcReq() {
	for {
		select {
		case req := <-RpcReqQueueCache:
			RpcReqQueue <- req
		}

		time.Sleep(time.Duration(1000000000)) //na, 1 s = 10e9 na /////////!!!!!fix bug:if large sign at same time,it will very slowly!!!!!
	}
}

func SendReqDcrmAddr(acc string, cointype string, gid string, nonce string, threshold string, mode string, timestamp string, key string) (string, string, error) {
	v := ReqAddrSendMsgToDcrm{Account: acc, Cointype: cointype, GroupId: gid, Nonce: nonce, LimitNum: threshold, Mode: mode, TimeStamp: timestamp, Key: key}
	rch := make(chan interface{}, 1)
	req := RpcReq{rpcdata: &v, ch: rch}

	RpcReqQueueCache <- req
	chret, tip, cherr := GetChannelValue(600, req.ch)

	if cherr != nil {
		return chret, tip, cherr
	}

	return chret, "", nil
}

func SendLockOut(acc string, dcrmfrom string, dcrmto string, value string, cointype string, gid string, nonce string, threshold string, mode string, timestamp string, key string) (string, string, error) {
	v := LockOutSendMsgToDcrm{Account: acc, DcrmFrom: dcrmfrom, DcrmTo: dcrmto, Value: value, Cointype: cointype, GroupId: gid, Nonce: nonce, LimitNum: threshold, Mode: mode, TimeStamp: timestamp, Key: key}
	rch := make(chan interface{}, 1)
	req := RpcReq{rpcdata: &v, ch: rch}

	RpcReqQueueCache <- req
	chret, tip, cherr := GetChannelValue(600, req.ch)

	if cherr != nil {
		return chret, tip, cherr
	}

	return chret, "", nil
}

func SendReqToGroup(msg string, rpctype string) (string, string, error) {
	var req RpcReq
	var keytest string
	switch rpctype {
	case "rpc_get_cur_node_lockout_info":
		v := GetCurNodeLockOutInfoSendMsgToDcrm{Account: msg}
		rch := make(chan interface{}, 1)
		req = RpcReq{rpcdata: &v, ch: rch}
		break
	case "rpc_get_cur_node_reqaddr_info":
		v := GetCurNodeReqAddrInfoSendMsgToDcrm{Account: msg}
		rch := make(chan interface{}, 1)
		req = RpcReq{rpcdata: &v, ch: rch}
		break
	default:
		return "", "", nil
	}

	var t int
	if rpctype == "rpc_lockout" {
		t = sendtogroup_lilo_timeout
	} else {
		t = sendtogroup_timeout
	}

	//RpcReqQueue <- req
	RpcReqQueueCache <- req
	if rpctype == "rpc_lockout" || rpctype == "rpc_req_dcrmaddr" {
		common.Info("=======================call dev.SendReqToGroup,send reqaddr req to Queue Cache finish.", "key = ", keytest, "", "==========================")
	}
	chret, tip, cherr := GetChannelValue(t, req.ch)
	if rpctype == "rpc_lockout" || rpctype == "rpc_req_dcrmaddr" {
		common.Info("=======================call dev.SendReqToGroup,calc dcrm addrs finish.", "ret = ", chret, "tip = ", tip, "cherr = ", cherr, "key = ", keytest, "", "==========================")
	}
	if cherr != nil {
		return chret, tip, cherr
	}

	return chret, "", nil
}

func GetChannelValue(t int, obj interface{}) (string, string, error) {
	timeout := make(chan bool, 1)
	go func() {
		time.Sleep(time.Duration(t) * time.Second) //1000 == 1s
		timeout <- true
	}()

	switch obj.(type) {
	case chan interface{}:
		ch := obj.(chan interface{})
		select {
		case v := <-ch:
			ret, ok := v.(RpcDcrmRes)
			if ok == true {
				return ret.Ret, ret.Tip, ret.Err
			}
		case <-timeout:
			return "", "dcrm back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	case chan string:
		ch := obj.(chan string)
		select {
		case v := <-ch:
			return v, "", nil
		case <-timeout:
			return "", "dcrm back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	case chan int64:
		ch := obj.(chan int64)
		select {
		case v := <-ch:
			return strconv.Itoa(int(v)), "", nil
		case <-timeout:
			return "", "dcrm back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	case chan int:
		ch := obj.(chan int)
		select {
		case v := <-ch:
			return strconv.Itoa(v), "", nil
		case <-timeout:
			return "", "dcrm back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	case chan bool:
		ch := obj.(chan bool)
		select {
		case v := <-ch:
			if !v {
				return "false", "", nil
			} else {
				return "true", "", nil
			}
		case <-timeout:
			return "", "dcrm back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	default:
		return "", "dcrm back-end internal error:unknown channel type", fmt.Errorf("unknown ch type.")
	}

	return "", "dcrm back-end internal error:unknown error.", fmt.Errorf("get value fail.")
}

//error type 1
type Err struct {
	Info string
}

func (e Err) Error() string {
	return e.Info
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

//msg: hash-enode:C1:X1:X2
func DisMsg(msg string) {

	if msg == "" {
		return
	}

	test := Keccak256Hash([]byte(strings.ToLower(msg))).Hex()
	fmt.Printf("%v ===============DisMsg,get msg = %v,msg hash = %v,=================\n", common.CurrentTime(), msg, test)

	//orderbook matchres
	mm := strings.Split(msg, Sep)
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
		key := prexs[0]
		fmt.Printf("%v ===============DisMsg,get group accounts data,msg = %v,msg hash = %v,key = %v=================\n", common.CurrentTime(), msg, test, key)
		nodecnt,_ := strconv.Atoi(mm[2])
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
			keys := strings.Split(string(da),":")
			for _,v := range keys {
			    if strings.EqualFold(v,key) {
				found = true
				break
			    }
			}
			//
			if !found {
			    da2 := string(da) + ":" + key
			    kdtmp := KeyData{Key: []byte(strings.ToLower(acc)), Data: da2}
			    PubKeyDataChan <- kdtmp
			    LdbPubKeyData.WriteMap(strings.ToLower(acc), []byte(da2))
			}
		    }
		}

		return
	}
	/////////////////

	//msg:  hash-enode:C1:X1:X2
	w, err := FindWorker(prexs[0])
	if err != nil || w == nil {
		fmt.Printf("%v ===============DisMsg,no find worker,msg = %v,msg hash = %v,err = %v,key = %v=================\n", common.CurrentTime(), msg, test, err, prexs[0])
		return
	}

	fmt.Printf("%v ===============DisMsg,get worker, worker id = %v,msg = %v,msg hash = %v,key = %v=================\n", common.CurrentTime(), w.id,msg, test, prexs[0])

	msgCode := mm[1]
	switch msgCode {
	case "AcceptReqAddrRes":
		///bug
		if w.msg_acceptreqaddrres.Len() >= w.NodeCnt {
			fmt.Printf("%v ===============DisMsg, w.msg_acceptreqaddrres.Len() = %v,w.NodeCnt = %v,msg = %v,msg hash = %v,key = %v=================\n", common.CurrentTime(), w.msg_acceptreqaddrres.Len(), w.NodeCnt, msg, test, prexs[0])
			return
		}

		///
		if Find(w.msg_acceptreqaddrres, msg) {
			fmt.Printf("%v ===============DisMsg, msg has exist in w.msg_acceptreqaddrres, w.msg_acceptreqaddrres.Len() = %v,w.NodeCnt = %v,msg = %v,msg hash = %v,key = %v=================\n", common.CurrentTime(), w.msg_acceptreqaddrres.Len(), w.NodeCnt, msg, test, prexs[0])
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

			tmp := strings.Split(s, Sep)
			tmp2 := tmp[0:3]
			fmt.Printf("%v ===============DisMsg, msg = %v,s = %v,key = %v=================\n", common.CurrentTime(), msg, s,prexs[0])
			if testEq(mm2, tmp2) {
				fmt.Printf("%v ===============DisMsg, test eq return true,msg = %v,s = %v,key = %v=================\n", common.CurrentTime(), msg, s,prexs[0])
				return
			}
		}
		//////

		w.msg_acceptreqaddrres.PushBack(msg)
		if w.msg_acceptreqaddrres.Len() == w.NodeCnt {
			fmt.Printf("%v ===============DisMsg, Get All AcceptReqAddrRes, w.msg_acceptreqaddrres.Len() = %v, w.NodeCnt = %v, msg = %v, msg hash = %v, key = %v=================\n", common.CurrentTime(), w.msg_acceptreqaddrres.Len(), w.NodeCnt, msg, test, prexs[0])
			w.bacceptreqaddrres <- true
			///////
			exsit,da := GetValueFromPubKeyData(prexs[0])
			if exsit == false {
				fmt.Printf("%v ==================DisMsg,no exist reqaddr data, worker id = %v,key = %v =======================\n", common.CurrentTime(), w.id, prexs[0])
				return
			}

			ds, err := UnCompress(string(da))
			if err != nil {
				fmt.Printf("%v ==================DisMsg,uncompress reqaddr data fail, err = %v, worker id = %v,key = %v =======================\n", common.CurrentTime(), err, w.id, prexs[0])
				return
			}

			dss, err := Decode2(ds, "AcceptReqAddrData")
			if err != nil {
				fmt.Printf("%v ==================DisMsg,decode reqaddr data fail, err = %v, worker id = %v,key = %v =======================\n", common.CurrentTime(), err, w.id, prexs[0])
				return
			}

			ac := dss.(*AcceptReqAddrData)
			if ac == nil {
				fmt.Printf("%v ==================DisMsg,ac is nil, worker id = %v,key = %v =======================\n", common.CurrentTime(), w.id, prexs[0])
				return
			}
			///////

			fmt.Printf("%v ==================DisMsg,get wid = %v,key = %v =======================\n", common.CurrentTime(), ac.WorkId, prexs[0])
			workers[ac.WorkId].acceptReqAddrChan <- "go on"
		}
	case "AcceptLockOutRes":
		///bug
		if w.msg_acceptlockoutres.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_acceptlockoutres, msg) {
			return
		}

		w.msg_acceptlockoutres.PushBack(msg)
		if w.msg_acceptlockoutres.Len() == w.NodeCnt {
			common.Info("===================Get All AcceptLockOutRes ", "msg hash = ", test, "", "====================")
			w.bacceptlockoutres <- true
			/////
			exsit,da := GetValueFromPubKeyData(prexs[0])
			if exsit == false {
				return
			}

			ds, err := UnCompress(string(da))
			if err != nil {
				return
			}

			dss, err := Decode2(ds, "AcceptLockOutData")
			if err != nil {
				return
			}

			ac := dss.(*AcceptLockOutData)
			if ac == nil {
				return
			}
			workers[ac.WorkId].acceptLockOutChan <- "go on"
			/////
		}
	case "SendLockOutRes":
		///bug
		if w.msg_sendlockoutres.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msg_sendlockoutres, msg) {
			return
		}

		w.msg_sendlockoutres.PushBack(msg)
		if w.msg_sendlockoutres.Len() == (w.NodeCnt - 1) {
			common.Info("===================Get All SendLockOutRes ", "msg hash = ", test, "", "====================")
			w.bsendlockoutres <- true
		}
	case "C1":
		///bug
		if w.msg_c1.Len() >= (w.NodeCnt - 1) {
			fmt.Println("=================Get C1 fail 11111,msg =%v,prex =%s================", msg, prexs[0])
			return
		}
		///
		if Find(w.msg_c1, msg) {
			fmt.Println("=================C1 has exsit,msg=%v,prex =%s================", msg, prexs[0])
			return
		}

		//fmt.Println("=================Get C1 msg =%v,prex =%s===================",msg,prexs[0])
		w.msg_c1.PushBack(msg)
		if w.msg_c1.Len() == (w.NodeCnt - 1) {
			common.Info("===================Get All C1 ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
			w.bc1 <- true
		}
	case "D1":
		///bug
		if w.msg_d1_1.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msg_d1_1, msg) {
			return
		}

		w.msg_d1_1.PushBack(msg)
		if w.msg_d1_1.Len() == (w.NodeCnt - 1) {
			common.Info("===================Get All D1 ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
			w.bd1_1 <- true
		}
	case "SHARE1":
		///bug
		if w.msg_share1.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msg_share1, msg) {
			return
		}

		w.msg_share1.PushBack(msg)
		if w.msg_share1.Len() == (w.NodeCnt - 1) {
			common.Info("===================Get All SHARE1 ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
			w.bshare1 <- true
		}
	//case "ZKFACTPROOF":
	case "NTILDEH1H2":
		///bug
		if w.msg_zkfact.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msg_zkfact, msg) {
			return
		}

		w.msg_zkfact.PushBack(msg)
		if w.msg_zkfact.Len() == (w.NodeCnt - 1) {
			common.Info("===================Get All NTILDEH1H2 ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
			w.bzkfact <- true
		}
	case "ZKUPROOF":
		///bug
		if w.msg_zku.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msg_zku, msg) {
			return
		}

		w.msg_zku.PushBack(msg)
		if w.msg_zku.Len() == (w.NodeCnt - 1) {
			common.Info("===================Get All ZKUPROOF ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
			w.bzku <- true
		}
	case "MTAZK1PROOF":
		///bug
		if w.msg_mtazk1proof.Len() >= (w.ThresHold - 1) {
			return
		}
		///
		if Find(w.msg_mtazk1proof, msg) {
			return
		}

		w.msg_mtazk1proof.PushBack(msg)
		if w.msg_mtazk1proof.Len() == (w.ThresHold - 1) {
			common.Info("===================Get All MTAZK1PROOF ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
			w.bmtazk1proof <- true
		}
		//sign
	case "C11":
		///bug
		if w.msg_c11.Len() >= (w.ThresHold - 1) {
			fmt.Println("=================get C11 fail,msg =%v,prex =%s===================", msg, prexs[0])
			return
		}
		///
		if Find(w.msg_c11, msg) {
			fmt.Println("=================C11 exsit,msg =%v,prex =%s===================", msg, prexs[0])
			return
		}

		//fmt.Println("=================Get C11 msg =%v,prex =%s===================",msg,prexs[0])
		w.msg_c11.PushBack(msg)
		if w.msg_c11.Len() == (w.ThresHold - 1) {
			common.Info("===================Get All C11 ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
			w.bc11 <- true
		}
	case "KC":
		///bug
		if w.msg_kc.Len() >= (w.ThresHold - 1) {
			return
		}
		///
		if Find(w.msg_kc, msg) {
			return
		}

		w.msg_kc.PushBack(msg)
		if w.msg_kc.Len() == (w.ThresHold - 1) {
			common.Info("===================Get All KC ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
			w.bkc <- true
		}
	case "MKG":
		///bug
		if w.msg_mkg.Len() >= (w.ThresHold - 1) {
			return
		}
		///
		if Find(w.msg_mkg, msg) {
			return
		}

		w.msg_mkg.PushBack(msg)
		if w.msg_mkg.Len() == (w.ThresHold - 1) {
			common.Info("===================Get All MKG ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
			w.bmkg <- true
		}
	case "MKW":
		///bug
		if w.msg_mkw.Len() >= (w.ThresHold - 1) {
			return
		}
		///
		if Find(w.msg_mkw, msg) {
			return
		}

		w.msg_mkw.PushBack(msg)
		if w.msg_mkw.Len() == (w.ThresHold - 1) {
			common.Info("===================Get All MKW ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
			w.bmkw <- true
		}
	case "DELTA1":
		///bug
		if w.msg_delta1.Len() >= (w.ThresHold - 1) {
			return
		}
		///
		if Find(w.msg_delta1, msg) {
			return
		}

		w.msg_delta1.PushBack(msg)
		if w.msg_delta1.Len() == (w.ThresHold - 1) {
			common.Info("===================Get All DELTA1 ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
			w.bdelta1 <- true
		}
	case "D11":
		///bug
		if w.msg_d11_1.Len() >= (w.ThresHold - 1) {
			return
		}
		///
		if Find(w.msg_d11_1, msg) {
			return
		}

		w.msg_d11_1.PushBack(msg)
		if w.msg_d11_1.Len() == (w.ThresHold - 1) {
			common.Info("===================Get All D11 ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
			w.bd11_1 <- true
		}
	case "CommitBigVAB":
		///bug
		if w.msg_commitbigvab.Len() >= (w.ThresHold - 1) {
			return
		}
		///
		if Find(w.msg_commitbigvab, msg) {
			return
		}

		w.msg_commitbigvab.PushBack(msg)
		if w.msg_commitbigvab.Len() == (w.ThresHold - 1) {
			common.Info("===================Get All CommitBigVAB ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
			w.bcommitbigvab <- true
		}
	case "ZKABPROOF":
		///bug
		if w.msg_zkabproof.Len() >= (w.ThresHold - 1) {
			return
		}
		///
		if Find(w.msg_zkabproof, msg) {
			return
		}

		w.msg_zkabproof.PushBack(msg)
		if w.msg_zkabproof.Len() == (w.ThresHold - 1) {
			common.Info("===================Get All ZKABPROOF ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
			w.bzkabproof <- true
		}
	case "CommitBigUT":
		///bug
		if w.msg_commitbigut.Len() >= (w.ThresHold - 1) {
			return
		}
		///
		if Find(w.msg_commitbigut, msg) {
			return
		}

		w.msg_commitbigut.PushBack(msg)
		if w.msg_commitbigut.Len() == (w.ThresHold - 1) {
			common.Info("===================Get All CommitBigUT ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
			w.bcommitbigut <- true
		}
	case "CommitBigUTD11":
		///bug
		if w.msg_commitbigutd11.Len() >= (w.ThresHold - 1) {
			return
		}
		///
		if Find(w.msg_commitbigutd11, msg) {
			return
		}

		w.msg_commitbigutd11.PushBack(msg)
		if w.msg_commitbigutd11.Len() == (w.ThresHold - 1) {
			common.Info("===================Get All CommitBigUTD11 ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
			w.bcommitbigutd11 <- true
		}
	case "S1":
		///bug
		if w.msg_s1.Len() >= (w.ThresHold - 1) {
			return
		}
		///
		if Find(w.msg_s1, msg) {
			return
		}

		w.msg_s1.PushBack(msg)
		if w.msg_s1.Len() == (w.ThresHold - 1) {
			common.Info("===================Get All S1 ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
			w.bs1 <- true
		}
	case "SS1":
		///bug
		if w.msg_ss1.Len() >= (w.ThresHold - 1) {
			return
		}
		///
		if Find(w.msg_ss1, msg) {
			return
		}

		w.msg_ss1.PushBack(msg)
		if w.msg_ss1.Len() == (w.ThresHold - 1) {
			common.Info("===================Get All SS1 ", "msg hash = ", test, "prex = ", prexs[0], "", "====================")
			w.bss1 <- true
		}

	//////////////////ed
	case "EDC11":
		logs.Debug("=========DisMsg,it is ed and it is EDC11.=============", "len msg_edc11", w.msg_edc11.Len(), "len msg", len(msg))
		///bug
		if w.msg_edc11.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msg_edc11, msg) {
			return
		}

		w.msg_edc11.PushBack(msg)
		logs.Debug("=========DisMsg,EDC11 msg.=============", "len c11", w.msg_edc11.Len(), "nodecnt-1", (w.NodeCnt - 1))
		if w.msg_edc11.Len() == (w.NodeCnt - 1) {
			logs.Debug("=========DisMsg,get all EDC11 msg.=============")
			w.bedc11 <- true
		}
	case "EDZK":
		logs.Debug("=========DisMsg,it is ed and it is EDZK.=============", "len msg_edzk", w.msg_edzk.Len(), "len msg", len(msg))
		///bug
		if w.msg_edzk.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msg_edzk, msg) {
			return
		}

		w.msg_edzk.PushBack(msg)
		logs.Debug("=========DisMsg,EDZK msg.=============", "len zk", w.msg_edzk.Len(), "nodecnt-1", (w.NodeCnt - 1))
		if w.msg_edzk.Len() == (w.NodeCnt - 1) {
			logs.Debug("=========DisMsg,get all EDZK msg.=============")
			w.bedzk <- true
		}
	case "EDD11":
		logs.Debug("=========DisMsg,it is ed and it is EDD11.=============", "len msg_edd11", w.msg_edd11.Len(), "len msg", len(msg))
		///bug
		if w.msg_edd11.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msg_edd11, msg) {
			return
		}

		w.msg_edd11.PushBack(msg)
		logs.Debug("=========DisMsg,EDD11 msg.=============", "len d11", w.msg_edd11.Len(), "nodecnt-1", (w.NodeCnt - 1))
		if w.msg_edd11.Len() == (w.NodeCnt - 1) {
			logs.Debug("=========DisMsg,get all EDD11 msg.=============")
			w.bedd11 <- true
		}
	case "EDSHARE1":
		logs.Debug("=========DisMsg,it is ed and it is EDSHARE1.=============", "len msg_edshare1", w.msg_edshare1.Len(), "len msg", len(msg))
		///bug
		if w.msg_edshare1.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msg_edshare1, msg) {
			return
		}

		w.msg_edshare1.PushBack(msg)
		logs.Debug("=========DisMsg,EDSHARE1 msg.=============", "len share1", w.msg_edshare1.Len(), "nodecnt-1", (w.NodeCnt - 1))
		if w.msg_edshare1.Len() == (w.NodeCnt - 1) {
			logs.Debug("=========DisMsg,get all EDSHARE1 msg.=============")
			w.bedshare1 <- true
		}
	case "EDCFSB":
		logs.Debug("=========DisMsg,it is ed and it is EDCFSB.=============", "len msg_edcfsb", w.msg_edcfsb.Len(), "len msg", len(msg))
		///bug
		if w.msg_edcfsb.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msg_edcfsb, msg) {
			return
		}

		w.msg_edcfsb.PushBack(msg)
		logs.Debug("=========DisMsg,EDCFSB msg.=============", "len cfsb", w.msg_edcfsb.Len(), "nodecnt-1", (w.NodeCnt - 1))
		if w.msg_edcfsb.Len() == (w.NodeCnt - 1) {
			logs.Debug("=========DisMsg,get all EDCFSB msg.=============")
			w.bedcfsb <- true
		}
	case "EDC21":
		logs.Debug("=========DisMsg,it is ed and it is EDC21.=============", "len msg_edc21", w.msg_edc21.Len(), "len msg", len(msg))
		///bug
		if w.msg_edc21.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msg_edc21, msg) {
			return
		}

		w.msg_edc21.PushBack(msg)
		logs.Debug("=========DisMsg,EDC21 msg.=============", "len c21", w.msg_edc21.Len(), "nodecnt-1", (w.NodeCnt - 1))
		if w.msg_edc21.Len() == (w.NodeCnt - 1) {
			logs.Debug("=========DisMsg,get all EDC21 msg.=============")
			w.bedc21 <- true
		}
	case "EDZKR":
		logs.Debug("=========DisMsg,it is ed and it is EDZKR.=============", "len msg_edzkr", w.msg_edzkr.Len(), "len msg", len(msg))
		///bug
		if w.msg_edzkr.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msg_edzkr, msg) {
			return
		}

		w.msg_edzkr.PushBack(msg)
		logs.Debug("=========DisMsg,EDZKR msg.=============", "len zkr", w.msg_edzkr.Len(), "nodecnt-1", (w.NodeCnt - 1))
		if w.msg_edzkr.Len() == (w.NodeCnt - 1) {
			logs.Debug("=========DisMsg,get all EDZKR msg.=============")
			w.bedzkr <- true
		}
	case "EDD21":
		logs.Debug("=========DisMsg,it is ed and it is EDD21.=============", "len msg_edd21", w.msg_edd21.Len(), "len msg", len(msg))
		///bug
		if w.msg_edd21.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msg_edd21, msg) {
			return
		}

		w.msg_edd21.PushBack(msg)
		logs.Debug("=========DisMsg,EDD21 msg.=============", "len d21", w.msg_edd21.Len(), "nodecnt-1", (w.NodeCnt - 1))
		if w.msg_edd21.Len() == (w.NodeCnt - 1) {
			logs.Debug("=========DisMsg,get all EDD21 msg.=============")
			w.bedd21 <- true
		}
	case "EDC31":
		logs.Debug("=========DisMsg,it is ed and it is EDC31.=============", "len msg_edc31", w.msg_edc31.Len(), "len msg", len(msg))
		///bug
		if w.msg_edc31.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msg_edc31, msg) {
			return
		}

		w.msg_edc31.PushBack(msg)
		logs.Debug("=========DisMsg,EDC31 msg.=============", "len c31", w.msg_edc31.Len(), "nodecnt-1", (w.NodeCnt - 1))
		if w.msg_edc31.Len() == (w.NodeCnt - 1) {
			logs.Debug("=========DisMsg,get all EDC31 msg.=============")
			w.bedc31 <- true
		}
	case "EDD31":
		logs.Debug("=========DisMsg,it is ed and it is EDD31.=============", "len msg_edd31", w.msg_edd31.Len(), "len msg", len(msg))
		///bug
		if w.msg_edd31.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msg_edd31, msg) {
			return
		}

		w.msg_edd31.PushBack(msg)
		logs.Debug("=========DisMsg,EDD31 msg.=============", "len d31", w.msg_edd31.Len(), "nodecnt-1", (w.NodeCnt - 1))
		if w.msg_edd31.Len() == (w.NodeCnt - 1) {
			logs.Debug("=========DisMsg,get all EDD31 msg.=============")
			w.bedd31 <- true
		}
	case "EDS":
		logs.Debug("=========DisMsg,it is ed and it is EDS.=============", "len msg_eds", w.msg_eds.Len(), "len msg", len(msg))
		///bug
		if w.msg_eds.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msg_eds, msg) {
			return
		}

		w.msg_eds.PushBack(msg)
		logs.Debug("=========DisMsg,EDS msg.=============", "len s", w.msg_eds.Len(), "nodecnt-1", (w.NodeCnt - 1))
		if w.msg_eds.Len() == (w.NodeCnt - 1) {
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
	//dir += "/dcrmdata/dcrmdb" + GetSelfEnode() + "group"
	dir += "/dcrmdata/dcrmdb" + discover.GetLocalID().String() + "group"
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

func GetGAccsDir() string {
	dir := DefaultDataDir()
	dir += "/dcrmdata/dcrmdb/gaccs" + cur_enode
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
	GroupID  string
	Accounts []PubKeyInfo
}

//////tmp code
/*func CheckAcc(eid string, geter_acc string, rk string) bool {

	//fmt.Println("================!!!CheckAcc!!!====================")
	if eid == "" || geter_acc == "" || rk == "" {
		//fmt.Println("================!!!CheckAcc,param error.!!!====================")
		return false
	}

	var da []byte
	datmp, exsit := GAccs.ReadMap(rk)
	if exsit == false {
		//fmt.Println("===================CheckAcc,no exsit key=%s======================",rk)
		da2 := GetGAccsValueFromDb(rk)
		if da2 == nil {
			//	    fmt.Println("===================CheckAcc,no exsit,2222, key=%s======================",rk)
			exsit = false
		} else {
			//	    fmt.Println("===================CheckAcc,exsit,4444, key=%s======================",rk)
			exsit = true
			da = da2
		}
	} else {
		//	fmt.Println("===================CheckAcc,exsit ,1111,data =%v,key=%s======================",datmp,rk)
		da = []byte(fmt.Sprintf("%v", datmp))
		exsit = true
	}

	if exsit == true {
		//	fmt.Println("===================CheckAcc,exsit ,2222,data =%v,key=%s======================",string(da),rk)
		mms := strings.Split(string(da), common.Sep)
		for k, mm := range mms {
			if strings.EqualFold(mm, eid) {
				if len(mms) >= (k+1) && strings.EqualFold(mms[k+1], geter_acc) {
					//	    fmt.Println("=============CheckAcc,return true,eid =%s,geter acc =%s,key=%s====================",eid,geter_acc,rk)
					return true
				}
			}
		}
	}

	//fmt.Println("=============CheckAcc,return false,eid =%s,geter acc =%s,key=%s====================",eid,geter_acc,rk)
	return false
}
*/
/////////////

type PubKeyInfo struct {
    PubKey string
    ThresHold string
    TimeStamp string
}

func GetValueFromPubKeyData(key string) (bool,[]byte) {
    if key == "" {
	return false,nil
    }

    var data []byte
    datmp, exsit := LdbPubKeyData.ReadMap(key)
    if exsit == false {
	    da := GetPubKeyDataValueFromDb(key)
	    if da == nil {
		    exsit = false
	    } else {
		    exsit = true
		    data = da
		    //fmt.Printf("%v==============GetValueFromPubKeyData,get data from db = %v================\n",common.CurrentTime(),string(data))
	    }
    } else {
	    //data = []byte(fmt.Sprintf("%v", datmp))
	    data = datmp.([]byte)
	    //fmt.Printf("%v==============GetValueFromPubKeyData,get data from memory = %v================\n",common.CurrentTime(),string(data))
	    exsit = true
    }

    return exsit,data
}

func GetAccounts(geter_acc, mode string) (interface{}, string, error) {
    exsit,da := GetValueFromPubKeyData(strings.ToLower(geter_acc))
	if exsit == false {
	    fmt.Printf("%v================GetAccounts, no exist, geter_acc = %v,=================\n",common.CurrentTime(),geter_acc)
	    return nil,"",fmt.Errorf("get value from pubkeydata fail.")
	}

	gp := make(map[string][]PubKeyInfo)
	keys := strings.Split(string(da),":")
	for _,key := range keys {
	    exsit,data := GetValueFromPubKeyData(key)
	    if exsit == false {
		continue
	    }

	    value := string(data)
	    ds, err := UnCompress(value)
	    if err != nil {
		    continue
	    }

	    dss, err := Decode2(ds, "AcceptReqAddrData")
	    if err != nil {
		    continue
	    }

	    ac := dss.(*AcceptReqAddrData)
	    if ac == nil {
		    continue
	    }

	    if ac.Mode == "1" {
		    if !strings.EqualFold(ac.Account,geter_acc) {
			fmt.Printf("%v================GetAccounts, ac.Account = %v,geter_acc = %v,key = %v,=================\n",common.CurrentTime(),ac.Account,geter_acc,key)
			continue
		    }
	    }

	    dcrmpks, _ := hex.DecodeString(ac.PubKey)
	    exsit,data2 := GetValueFromPubKeyData(string(dcrmpks[:]))
	    ss, err := UnCompress(string(data2))
	    if err != nil {
		continue
	    }
	    
	    pubs, err := Decode2(ss, "PubKeyData")
	    if err != nil {
		continue
	    }

	    pd := pubs.(*PubKeyData)
	    if pd == nil {
		continue
	    }

	    pb := pd.Pub
	    pubkeyhex := hex.EncodeToString([]byte(pb))
	    gid := pd.GroupId
	    md := pd.Mode
	    limit := pd.LimitNum
	    if mode == md {
		    al, exsit := gp[gid]
		    if exsit {
			    tmp := PubKeyInfo{PubKey:pubkeyhex,ThresHold:limit,TimeStamp:""}
			    al = append(al, tmp)
			    gp[gid] = al
		    } else {
			    a := make([]PubKeyInfo, 0)
			    tmp := PubKeyInfo{PubKey:pubkeyhex,ThresHold:limit,TimeStamp:""}
			    a = append(a, tmp)
			    gp[gid] = a
		    }
	    }
	}

	als := make([]AccountsList, 0)
	for k, v := range gp {
		alNew := AccountsList{GroupID: k, Accounts: v}
		als = append(als, alNew)
	}

	pa := &PubAccounts{Group: als}
	return pa, "", nil
}

