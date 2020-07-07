/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  huangweijun@fusion.org
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

package discover

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsn-dev/dcrm-walletService/crypto"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	"github.com/fsn-dev/dcrm-walletService/p2p/rlp"
	"github.com/syndtr/goleveldb/leveldb"
)

var (
	setgroupNumber = 0
	setgroup       = 0
	Dcrmdelimiter  = "dcrmmsg"
	Dcrm_groupList *Group
	Xp_groupList   *Group
	tmpdcrmmsg     = &getdcrmmessage{Number: [3]byte{0, 0, 0}, Msg: ""}
	setlocaliptrue = false
	LocalIP        string
	RemoteIP       net.IP
	RemotePort     = uint16(0)
	RemoteUpdate   = true
	SelfEnode      = ""
	SelfIPPort     = ""
	changed        = 0
	Xp_changed     = 0

	SDK_groupList map[NodeID]*Group = make(map[NodeID]*Group)
	GroupSDK      sync.Mutex
	groupSDKList  []*Node

	groupDbLock      sync.Mutex
	sequenceLock     sync.Mutex
	sequenceDone     sync.Map
	sequenceDoneRecv sync.Map
	Sequence                                  = uint64(1)
	SelfID                                    = ""
	SelfNodeID NodeID
	p2pSuffix                               = "p2p"
	p2pDir                                  = ""
	nodeOnline       map[NodeID]*OnLineStatus = make(map[NodeID]*OnLineStatus)

	updateGroupsNode bool = false// update node dynamically
	addNodes map[NodeID]int = make(map[NodeID]int)
	addNodesLock sync.Mutex
	loadedSeeds map[NodeID]int = make(map[NodeID]int)
	loadedDone bool = false
	SDK_groupListChan chan int = make(chan int, 1)
)
var (
	Dcrm_groupMemNum = 0
	Xp_groupMemNum   = 0
	SDK_groupNum     = 0
)

type OnLineStatus struct {
	Status bool
	Lock   sync.Mutex
}

const (
	SendWaitTime = 1 * time.Minute
	pingCount    = 10

	Dcrmprotocol_type = iota + 1
	Xprotocol_type
	Sdkprotocol_type

	Dcrm_findGroupPacket = iota + 10 + neighborsPacket //14
	Xp_findGroupPacket
	Sdk_findGroupPacket
	Dcrm_groupPacket
	Sdk_groupPacket
	Xp_groupPacket
	Dcrm_groupInfoPacket
	Sdk_groupStatusPacket
	PeerMsgPacket
	getDcrmPacket
	getSdkPacket
	Xp_getCCPacket
	getXpPacket
	gotDcrmPacket
	gotSdkPacket
	gotXpPacket

	Ack_Packet
)

type (
	findgroup struct {
		ID         NodeID
		P2pType    byte
		Target     NodeID // doesn't need to be an actual public key
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	Ack struct {
		Sequence   uint64
		Expiration uint64
	}

	Group struct {
		sync.Mutex
		ID NodeID
		//Gname      string
		Mode string // 2/3
		msg  string
		//status        string
		count   int
		P2pType byte
		Nodes   []RpcNode
		Type    string // group type: 1+2, 1+1+1
		//userID      []string
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	GroupSDKList struct {
		Nodes []*Node
	}

	message struct {
		//sync.Mutex
		Msg        string
		Expiration uint64
	}

	getdcrmmessage struct {
		//sync.Mutex
		Number     [3]byte
		P2pType    byte
		Target     NodeID // doesn't need to be an actual public key
		Msg        string
		Sequence   uint64
		Expiration uint64
	}

	dcrmmessage struct {
		//sync.Mutex
		Number     [3]byte
		Target     NodeID // doesn't need to be an actual public key
		P2pType    byte
		Msg        string
		Sequence   uint64
		Expiration uint64
	}
)

func InitP2pDir() {
	p2pDir = common.DefaultDataDir()
}

func (req *findgroup) name() string { return "FINDGROUP/v4" }

func getGroupList(gid NodeID, p2pType int) *Group { //nooo
	switch p2pType {
	case Sdkprotocol_type:
		return getGroupSDK(gid)
	case Dcrmprotocol_type:
		return Dcrm_groupList
	case Xprotocol_type:
		return Xp_groupList
	}
	return nil
}

func getGroupSDK(gid NodeID) *Group { //nooo
	for id, g := range SDK_groupList {
		//if g.status != "SUCCESS" {
		//	continue
		//}
		index := id.String()
		gf := gid.String()
		fmt.Printf("%v ==== getGroupSDK() ====, id: %v, gid: %v\n", common.CurrentTime(), id, gid)
		if index[:8] == gf[:8] {
			return g
		}
	}
	return nil
}

func getGroupChange(p2pType int) *int {
	switch p2pType {
	case Dcrmprotocol_type:
		return &changed
	case Xprotocol_type:
		return &Xp_changed
	}
	return nil
}

func getCCPacket(p2pType int) int {
	switch p2pType {
	case Sdkprotocol_type:
		return getSdkPacket
	case Dcrmprotocol_type:
		return getDcrmPacket
	case Xprotocol_type:
		return Xp_getCCPacket
	}
	return 0
}
func getGroupPacket(p2pType int) int {
	switch p2pType {
	case Sdkprotocol_type:
		return Sdk_groupPacket
	case Dcrmprotocol_type:
		return Dcrm_groupPacket
	case Xprotocol_type:
		return Xp_groupPacket
	}
	return 0
}

func getFindGroupPacket(p2pType int) int {
	switch p2pType {
	case Sdkprotocol_type:
		return Sdk_findGroupPacket
	case Dcrmprotocol_type:
		return Dcrm_findGroupPacket
	case Xprotocol_type:
		return Xp_findGroupPacket
	}
	return 0
}

func getGroupMemNum(p2pType int) int {
	switch p2pType {
	case Sdkprotocol_type:
		return SDK_groupNum
	case Dcrmprotocol_type:
		return Dcrm_groupMemNum
	case Xprotocol_type:
		return Xp_groupMemNum
	}
	return 0
}

func getGotPacket(p2pType int) int {
	switch p2pType {
	case Sdkprotocol_type:
		return gotSdkPacket
	case Dcrmprotocol_type:
		return gotDcrmPacket
	case Xprotocol_type:
		return gotXpPacket
	}
	return 0
}

// findgroup sends a findgroup request to the bootnode and waits until
// the node has sent up to a group.
func (t *udp) findgroup(gid, toid NodeID, toaddr *net.UDPAddr, target NodeID, p2pType int) ([]*Node, error) { //nooo
	//log.Debug("====  (t *udp) findgroup()  ====", "gid", gid, "p2pType", p2pType)
	nodes := make([]*Node, 0, bucketSize)
	nreceived := 0
	groupPacket := getGroupPacket(p2pType)
	findgroupPacket := getFindGroupPacket(p2pType)
	groupMemNum := getGroupMemNum(p2pType)
	errc := t.pending(toid, byte(groupPacket), func(r interface{}) bool {
		reply := r.(*Group)
		//log.Debug("findgroup", "reply", reply, "r", r)
		for _, rn := range reply.Nodes {
			nreceived++
			n, err := t.nodeFromRPC(toaddr, rpcNode(rn))
			if err != nil {
				fmt.Printf("Invalid neighbor node received, ip: %v, addr: %v, err: %v\n", rn.IP, toaddr, err)
				continue
			}
			nodes = append(nodes, n)
		}
		//log.Debug("findgroup", "return nodes", nodes)
		return nreceived >= groupMemNum
	})
	//log.Debug("findgroup, t.send", "toaddr", toaddr, "gid", gid, "p2pType", p2pType, "send packet", byte(findgroupPacket), "p2ptype", byte(p2pType))
	_, errs := t.send(toaddr, byte(findgroupPacket), &findgroup{
		ID:         gid,
		P2pType:    byte(p2pType),
		Target:     target,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	if errs != nil {
		fmt.Printf("==== (t *udp) sendMsgToPeer ====, errs: %v\n", errs)
	}
	err := <-errc
	return nodes, err
}

func (req *findgroup) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	//log.Debug("====  (req *findgroup) handle()  ====", "from", from, "fromID", fromID)
	if expired(req.Expiration) {
		return errExpired
	}
	if !t.db.hasBond(fromID) {
		// No bond exists, we don't process the packet. This prevents
		// an attack vector where the discovery protocol could be used
		// to amplify traffic in a DDOS attack. A malicious actor
		// would send a findnode request with the IP address and UDP
		// port of the target as the source address. The recipient of
		// the findnode packet would then send a neighbors packet
		// (which is a much bigger packet than findnode) to the victim.
		return errUnknownNode
	}
	groupPacket := getGroupPacket(int(req.P2pType))
	if p := getGroupInfo(req.ID, int(req.P2pType)); p != nil {
		//log.Debug("====  (req *findgroup) handle()  ====", "getGroupInfo", p)
		_, errs := t.send(from, byte(groupPacket), p)
		if errs != nil {
			fmt.Printf("==== (t *udp) sendMsgToPeer ====, errs: %v\n", errs)
		}
	}
	return nil
}

func (req *getdcrmmessage) name() string { return "GETDCRMMSG/v4" }
func (req *dcrmmessage) name() string    { return "DCRMMSG/v4" }

var number [3]byte

func SendToGroupCC(toid NodeID, toaddr *net.UDPAddr, msg string, p2pType int) (string, error) {
	return Table4group.net.sendToGroupCC(toid, toaddr, msg, p2pType)
}

func (t *udp) udpSendMsg(toid NodeID, toaddr *net.UDPAddr, msg string, number [3]byte, p2pType int, ret bool) (string, error) {
	sequenceLock.Lock()
	s := Sequence
	Sequence += 1
	sequenceLock.Unlock()

	getPacket := 0
	if ret == true {
		getPacket = getGotPacket(p2pType)
	} else {
		getPacket = getCCPacket(p2pType)
	}
	reqGet := &getdcrmmessage{
		Target:     toid,
		Number:     number,
		P2pType:    byte(p2pType),
		Msg:        msg,
		Sequence:   s,
	}
	req := &dcrmmessage{
		Target:     toid,
		Number:     number,
		P2pType:    byte(p2pType),
		Msg:        msg,
		Sequence:   s,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	}
	timeout := false
	go func() {
		msgHash := crypto.Keccak256Hash([]byte(strings.ToLower(msg))).Hex()
		go func() {
			SendWaitTimeOut := time.NewTicker(SendWaitTime)
			select {
			case <-SendWaitTimeOut.C:
				timeout = true
			}
		}()
		for {
			if timeout == true {
				fmt.Printf("%v ====  (t *udp) udpSendMsg()  ====, send toaddr: %v, err: timeout\n", common.CurrentTime(), toaddr)
				break
			}
			errc := t.pending(toid, byte(Ack_Packet), func(r interface{}) bool {
				fmt.Printf("%v recv ack ====  (t *udp) udpSendMsg()  ====, from: %v, sequence: %v, ackSequence: %v\n", common.CurrentTime(), toaddr, s, r.(*Ack).Sequence)
				return true
			})
			var errs error
			if ret == true {
				req.Expiration = uint64(time.Now().Add(expiration).Unix())
				_, errs = t.send(toaddr, byte(getPacket), req)
				fmt.Printf("%v ==== (t *udp) udpSendMsg()  ==== p2pBroatcast, send toaddr: %v, sequence: %v, errs: %v, msgHash: %v, dcrmmessage\n", common.CurrentTime(), toaddr, s, errs, msgHash)
			} else {
				reqGet.Expiration = uint64(time.Now().Add(expiration).Unix())
				_, errs = t.send(toaddr, byte(getPacket), reqGet)
				fmt.Printf("%v ==== (t *udp) udpSendMsg()  ==== p2pBroatcast, send toaddr: %v, sequence: %v, errs: %v, msgHash: %v, getdcrmmessage\n", common.CurrentTime(), toaddr, s, errs, msgHash)
			}
			time.Sleep(time.Duration(5) * time.Second)
			err := <-errc
			if errs != nil || err != nil {
				continue
			}
			fmt.Printf("%v ====  (t *udp) udpSendMsg()  ====, send toaddr: %v, SUCCESS\n", common.CurrentTime(), toaddr)
			break

		}
	}()
	if timeout == true {
		return "", errors.New("timeout")
	}
	return "", nil
}

func (req *Ack) name() string { return "ACK/v4" }
func (req *Ack) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	if !t.handleReply(fromID, byte(Ack_Packet), req) {
		fmt.Printf("%v ====  (t *udp) udpSendMsg()  ====, handleReply, toaddr: %v\n", common.CurrentTime(), from)
	}
	return nil
}

// sendgroup sends to group dcrm and waits until
// the node has reply.
func (t *udp) sendToGroupCC(toid NodeID, toaddr *net.UDPAddr, msg string, p2pType int) (string, error) {
	var err error = nil
	retmsg := ""
	number[0]++
	if len(msg) <= 800 {
		number[1] = 1
		number[2] = 1
		_, err = t.udpSendMsg(toid, toaddr, msg, number, p2pType, false)
		if err != nil {
			fmt.Printf("%v ==== (t *udp) sendMsgToPeer ====, err: %v\n", common.CurrentTime(), err)
		}
	} else if len(msg) > 800 && len(msg) < 1600 {
		number[1] = 1
		number[2] = 2
		_, err = t.udpSendMsg(toid, toaddr, msg[0:800], number, p2pType, false)
		if err != nil {
			fmt.Printf("%v ==== (t *udp) sendMsgToPeer ====, err: %v\n", common.CurrentTime(), err)
		} else {
			number[1] = 2
			number[2] = 2
			_, err = t.udpSendMsg(toid, toaddr, msg[800:], number, p2pType, false)
			if err != nil {
				fmt.Printf("%v ==== (t *udp) sendMsgToPeer ====, err: %v\n", common.CurrentTime(), err)
			}
		}
	} else {
		return "", errors.New("send fail, msg size > 1600")
	}
	return retmsg, err
}

func (req *getdcrmmessage) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	//if expired(req.Expiration) {
	//	return errExpired
	//}
	fmt.Printf("%v send ack ==== (req *getdcrmmessage) handle() ====, to: %v, squence: %v\n", common.CurrentTime(), from, req.Sequence)
	t.send(from, byte(Ack_Packet), &Ack{
		Sequence:   req.Sequence,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	ss := fmt.Sprintf("get-%v-%v", fromID, req.Sequence)
	fmt.Printf("%v ==== (req *getdcrmmessage) handle() ====, from: %v, sequence: %v\n", common.CurrentTime(), from, req.Sequence)
	sequenceLock.Lock()
	if _, ok := sequenceDoneRecv.Load(ss); ok {
		fmt.Printf("%v ==== (req *getdcrmmessage) handle() ====, from: %v, req.Sequence: %v exist\n", common.CurrentTime(), from, req.Sequence)
		sequenceLock.Unlock()
		return nil
	}
	sequenceDoneRecv.Store(ss, 1)
	sequenceLock.Unlock()

	msgp := req.Msg
	num := req.Number
	if num[2] > 1 {
		if tmpdcrmmsg.Number[0] == 0 || num[0] != tmpdcrmmsg.Number[0] {
			tmpdcrmmsg = &(*req)
			return nil
		}
		if tmpdcrmmsg.Number[1] == num[1] {
			return nil
		}
		var buffer bytes.Buffer
		if tmpdcrmmsg.Number[1] < num[1] {
			buffer.WriteString(tmpdcrmmsg.Msg)
			buffer.WriteString(req.Msg)
		} else {
			buffer.WriteString(req.Msg)
			buffer.WriteString(tmpdcrmmsg.Msg)
		}
		msgp = buffer.String()
	}

	go func() {
		msgHash := crypto.Keccak256Hash([]byte(strings.ToLower(msgp))).Hex()
		fmt.Printf("%v ==== (req *getdcrmmessage) handle() ==== p2pBroatcast, recv from target: %v, from: %v, msgHash: %v callback callMsgEvent\n", common.CurrentTime(), fromID, from, msgHash)
		msgc := callMsgEvent(msgp, int(req.P2pType), fromID.String())
		msg := <-msgc
		_, err := t.udpSendMsg(fromID, from, msg, number, int(req.P2pType), true)
		if err != nil {
			fmt.Printf("dcrm handle, send to target: %v, from: %v, msg(len = %v), err: %v\n", fromID, from, len(msg), err)
		}
	}()
	return nil
}

func RemoveSequenceDoneRecv(id string) {
	sequenceLock.Lock()
	defer sequenceLock.Unlock()
	sequenceDoneRecv.Range(func(k, v interface{}) bool {
		kid := k.(string)
		kslice := strings.Split(kid, "-")
		if kslice[0] == id {
			sequenceDoneRecv.Delete(k)
		}
		return true
	})
}

func (req *dcrmmessage) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	//if expired(req.Expiration) {
	//        return errExpired
	//}
	msgHash := crypto.Keccak256Hash([]byte(strings.ToLower(req.Msg))).Hex()
	fmt.Printf("%v ==== (req *dcrmmessage) handle() ==== p2pBroatcast, recv from target: %v, from: %v, msgHash: %v\n", common.CurrentTime(), fromID, from, msgHash)
	fmt.Printf("%v send ack ==== (req *dcrmmessage) handle() ====, to: %v, msg: %v\n", common.CurrentTime(), from, req.Msg)
	t.send(from, byte(Ack_Packet), &Ack{
		Sequence:   req.Sequence,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	ss := fmt.Sprintf("%v-%v", fromID, req.Sequence)
	fmt.Printf("%v ==== (req *dcrmmessage) handle() ====, recvMsg: %v\n", common.CurrentTime(), ss)
	sequenceLock.Lock()
	if _, ok := sequenceDoneRecv.Load(ss); ok {
		fmt.Printf("%v ==== (req *dcrmmessage) handle() ====, from: %v, req.Sequence: %v exist\n", common.CurrentTime(), from, req.Sequence)
		sequenceLock.Unlock()
		return nil
	}
	sequenceDoneRecv.Store(ss, 1)
	sequenceLock.Unlock()
	fmt.Printf("%v ==== (req *dcrmmessage) handle() ==== p2pBroatcast, recv from target: %v, from: %v, msgHash: %v, callback callCCReturn\n", common.CurrentTime(), fromID, from, msgHash)
	go callCCReturn(req.Msg, int(req.P2pType), fromID.String())
	return nil
}

func getGroupInfo(gid NodeID, p2pType int) *Group { //nooo
	groupList := getGroupList(gid, p2pType)
	fmt.Printf("%v getGroupInfo, gid: %v, groupList: %v, setgroup: %v, p2pType: %v\n", common.CurrentTime(), gid, groupList, setgroup, p2pType)
	if /*setgroup == 1 &&*/ groupList != nil /*&& groupList.count == groupMemNum*/ {
		groupList.Lock()
		defer groupList.Unlock()
		p := groupList
		p.P2pType = byte(p2pType)
		p.Expiration = uint64(time.Now().Add(expiration).Unix())
		return p
	}
	return nil
}

func InitGroup() {
	//	GroupSDK.Lock()
	//	defer GroupSDK.Unlock()
	setgroup = 1
	//	setgroupNumber = groupsNum
	//SDK_groupNum = nodesNum
	//	Dcrm_groupMemNum = nodesNum
	//	Xp_groupMemNum   = nodesNum
	//	Dcrm_groupList = &Group{msg: "dcrm", count: 0, Expiration: ^uint64(0)}
	//	Xp_groupList = &Group{msg: "dcrm", count: 0, Expiration: ^uint64(0)}
	//	RecoverGroupSDKList()// List
	//	RecoverGroupAll(SDK_groupList)// Group
	//	for i, g := range SDK_groupList {
	//		fmt.Printf("InitGroup, SDK_groupList gid: %v, g: %v\n", i, g)
	//		sendGroupInfo(g, int(g.P2pType))
	//	}
}

func SendToGroup(gid NodeID, msg string, allNodes bool, p2pType int, gg []*Node) (string, error) {
	fmt.Printf("%v ==== SendToGroup() ====, gid: %v, allNodes: %v, p2pType: %v\n", common.CurrentTime(), gid, allNodes, p2pType)
	//gg := getGroupSDK(gid)
	groupMemNum := 0
	g := make([]*Node, 0, bucketSize)
	if gg != nil {
		//for _, rn := range gg.Nodes {
		//	n := NewNode(rn.ID, rn.IP, rn.UDP, rn.TCP)
		//	err := n.validateComplete()
		//	if err != nil {
		//		fmt.Printf("Invalid neighbor node received, ip: %v, err: %v\n", rn.IP, err)
		//		continue
		//	}
		//	g = append(g, n)
		//}
		g = gg
		groupMemNum = len(gg)
	} else {
		fmt.Printf("Not found gid(%v) from local, from bootnode ...\n", gid)
		bn := Table4group.nursery[0]
		if bn == nil {
			return "", errors.New("SendToGroup, bootnode is nil")
		}
		ipa := &net.UDPAddr{IP: bn.IP, Port: int(bn.UDP)}
		g = GetGroup(gid, bn.ID, ipa, bn.ID, p2pType)
		groupMemNum := getGroupMemNum(p2pType)
		if g == nil || len(g) != groupMemNum {
			fmt.Printf("SendToGroup(), group is nil or wrong len\n")
			return "", errors.New("SendToGroup(), group is nil or wrong len")
		}
	}

	sent := make([]int, groupMemNum+1)
	retMsg := ""
	count := 0
	for i := 1; i <= groupMemNum; {
		rand.Seed(time.Now().UnixNano())
		r := rand.Intn(groupMemNum) % groupMemNum
		j := 1
		for ; j < i; j++ {
			if r+1 == sent[j] {
				break
			}
		}
		if j < i {
			continue
		}
		sent[i] = r + 1
		i += 1
		n := g[r]
		if n.ID.String() == GetLocalID().String() {
			go SendToMyselfAndReturn(n.ID.String(), msg, p2pType)
		} else {
			ipa := &net.UDPAddr{IP: n.IP, Port: int(n.UDP)}
			_, err := Table4group.net.sendToGroupCC(n.ID, ipa, msg, p2pType)
			if err != nil {
				fmt.Printf("%v SendToGroup, sendToGroupCC(n.ID: %v, ipa: %v) error: %v\n", common.CurrentTime(), n.ID, ipa, err)
				retMsg = fmt.Sprintf("%v; SendToGroup, sendToGroupCC(n.ID: %v, ipa: %v) error", retMsg, n.ID, ipa)
			} else {
				retMsg = fmt.Sprintf("%v; sendToGroupCC(n.ID: %v, ipa: %v) Success", retMsg, n.ID, ipa)
			}
		}
		count += 1
		if allNodes == false {
			break
		}
	}
	if (allNodes == false && count == 1) || (allNodes == true && count == groupMemNum) {
		return retMsg, nil
	}
	fmt.Println(retMsg)
	return "", errors.New(retMsg)
}

func PingNode(id NodeID, ip net.IP, port int) error {
	n := NewNode(id, ip, uint16(port), uint16(port))
	err := n.validateComplete()
	if err != nil {
		return err
	}
	ipa := &net.UDPAddr{IP: ip, Port: port}
	return Table4group.net.ping(id, ipa)
}

func GetGroup(gid, id NodeID, addr *net.UDPAddr, target NodeID, p2pType int) []*Node {
	GroupSDK.Lock()
	defer GroupSDK.Unlock()
	if SDK_groupList != nil && SDK_groupList[gid] != nil {
		nodes := make([]*Node, 0, bucketSize)
		for _, rn := range SDK_groupList[gid].Nodes {
			n := NewNode(rn.ID, rn.IP, rn.UDP, rn.TCP)
			err := n.validateComplete()
			if err != nil {
				fmt.Printf("Invalid neighbor node received, ip: %v, addr: %v, err: %v\n", rn.IP, addr, err)
				continue
			}
			nodes = append(nodes, n)
		}
		return nodes
	}
	g, _ := Table4group.net.findgroup(gid, id, addr, target, p2pType)
	return g
}

func setGroup(n *Node, replace string) {
	if setgroupNumber == 0 {
		setGroupSDK(n, replace, Sdkprotocol_type)
		return
	} else if setgroupNumber == 1 {
		setGroupCC(n, replace, Xprotocol_type) // same nodes
	} else {
		groupChanged := getGroupChange(Dcrmprotocol_type)
		if *groupChanged == 2 {
			setGroupCC(n, replace, Xprotocol_type) // deferent nodes
		}
	}
	setGroupCC(n, replace, Dcrmprotocol_type)
}

func sendGroupToNode(groupList *Group, p2pType int, node *Node) { //nooo
	ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
	go SendToPeer(groupList.ID, node.ID, ipa, "", p2pType)
	if p2pType == Dcrmprotocol_type || p2pType == Sdkprotocol_type {
		var tmp int = 0
		for i := 0; i < groupList.count; i++ {
			n := groupList.Nodes[i]
			tmp++
			if n.ID != node.ID {
				continue
			}
			cDgid := fmt.Sprintf("%v", groupList.ID) + "|" + "1dcrmslash1:" + strconv.Itoa(tmp) + "#" + "Init"
			fmt.Printf("%v ==== sendGroupToNode() ====, cDgid = %v\n", common.CurrentTime(), cDgid)
			ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
			SendMsgToNode(node.ID, ipa, cDgid)
			break
		}
	}
}

func sendGroupInfo(gid NodeID, nodes []RpcNode, p2pType int) { //nooo
	fmt.Printf("%v ==== sendGroupInfo() ====, gid: %v, nodes: %v\n", common.CurrentTime(), gid, nodes)
	for i := 0; i < len(nodes); i++ {
		fmt.Printf("==== sendGroupInfo() ====, gid: %v, node: %v\n", gid, nodes[i])
		node := nodes[i]
		//e := fmt.Sprintf("enode://%v@%v:%v", node.ID, node.IP, node.UDP)
		//if e == SelfEnode {
		//	go callGroupEvent(req.ID, req.Mode, nodes, int(req.P2pType), req.Type)
		//}
		ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
		go SendToPeer(gid, node.ID, ipa, "", p2pType)
	}
}

func sendGroupInit2Node(gid NodeID, node RpcNode, i int) {
	cDgid := fmt.Sprintf("%v", gid) + "|" + "1dcrmslash1:" + strconv.Itoa(i) + "#" + "Init"
	ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
	SendMsgToNode(node.ID, ipa, cDgid)
}

func sendGroupInit(groupList *Group, p2pType int) { //nooo
	//enodes := fmt.Sprintf("%v,%v,%v", groupList.ID, count, enode)
	if p2pType == Dcrmprotocol_type || p2pType == Sdkprotocol_type {
		for i := 0; i < groupList.count; i++ {
			node := groupList.Nodes[i]
			gid := groupList.ID
			tmpi := i
			go sendGroupInit2Node(gid, node, tmpi)
		}
	}
}

func addGroupSDK(n *Node, p2pType int) { //nooo
	groupTmp := new(Group)
	groupTmp.Nodes = make([]RpcNode, SDK_groupNum)
	for i, node := range groupSDKList {
		groupTmp.Nodes[i] = RpcNode(nodeToRPC(node))
		groupTmp.count++
	}
	groupTmp.Nodes[len(groupSDKList)] = RpcNode(nodeToRPC(n))
	groupTmp.count++
	groupTmp.ID = n.ID
	groupTmp.Mode = fmt.Sprintf("%v/%v", groupTmp.count, groupTmp.count)
	groupTmp.P2pType = byte(p2pType)
	groupTmp.Type = "1+2"
	SDK_groupList[groupTmp.ID] = groupTmp
}

func StartCreateSDKGroup(gid NodeID, threshold string, enode []*Node, Type string, exist bool, subGroup bool) string {
	fmt.Printf("%v ==== StartCreateSDKGroup() ====, gid: %v\n", common.CurrentTime(), gid)
	buildSDKGroup(gid, threshold, enode, Type, exist, subGroup)
	return ""
}

func buildSDKGroup(gid NodeID, threshold string, enode []*Node, Type string, exist bool, subGroup bool) {
	es := strings.Split(threshold, "/")
	if len(es) != 2 {
		fmt.Printf("args threshold(%v) format is wrong", threshold)
		return
	}
	nodeNum0, _ := strconv.Atoi(es[0])
	GroupSDK.Lock()
	defer GroupSDK.Unlock()
	fmt.Printf("%v ==== buildSDKGroup() ====, gid: %v, enode: %v\n", common.CurrentTime(), gid, enode)
	groupTmp := new(Group)
	groupTmp.Mode = threshold
	groupTmp.Type = Type
	cnodes := len(enode)
	if subGroup {
		cnodes = nodeNum0
	}
	groupTmp.Nodes = make([]RpcNode, cnodes)
	tmpNodes := make([]RpcNode, len(enode))
	for i, node := range enode {
		tmpNodes[i] = RpcNode(nodeToRPC(node))
		fmt.Printf("==== buildSDKGroup() ====, tmpNodes: %v\n", tmpNodes)
		if subGroup {
			if i >= nodeNum0 {
				continue
			}
		}
		groupTmp.Nodes[i] = RpcNode(nodeToRPC(node))
		groupTmp.count++
	}
	groupTmp.ID = gid
	SDK_groupList[groupTmp.ID] = groupTmp
	fmt.Printf("==== buildSDKGroup() ====, gid: %v, group: %v\n", gid, groupTmp)
	if exist != true {
		sendGroupInit(SDK_groupList[gid], Sdkprotocol_type)
	}
	sendGroupInfo(gid, tmpNodes, Sdkprotocol_type)
}

func updateGroup(n *Node, p2pType int) { //nooo
	for _, g := range SDK_groupList {
		for i, node := range g.Nodes {
			if node.ID == n.ID {
				g.Nodes = append(g.Nodes[:i], g.Nodes[i+1:]...)
				g.Nodes = append(g.Nodes, RpcNode(nodeToRPC(n)))
				sendGroupInfo(g.ID, g.Nodes, p2pType)
				sendGroupInit(g, p2pType)
				StoreGroupToDb(g)
				break
			}
		}
	}
}

func updateGroupNode(n *Node, p2pType int) {
	for _, g := range SDK_groupList {
		for _, node := range g.Nodes {
			if node.ID == n.ID {
				sendGroupToNode(g, p2pType, n)
				break
			}
		}
	}
}

func checkNodeIDExist(n *Node) (bool, bool) { //exist, update //nooo
	groupTmp := SDK_groupList[n.ID]
	for _, node := range groupTmp.Nodes {
		if node.ID == n.ID {
			if string(node.IP) != string(n.IP) || node.UDP != n.UDP {
				return true, true
			}
			return true, false
		}
	}
	return false, true
}

func UpdateGroupSDKNode(nodeID NodeID, ipport net.Addr) {
	n, err := ParseNode(fmt.Sprintf("enode://%v@%v", nodeID, ipport))
	if err == nil {
		GroupSDK.Lock()
		defer GroupSDK.Unlock()
		updateGroupSDKNode(n, Sdkprotocol_type)
		fmt.Printf("%v ==== UpdateGroupSDKNode() ====, nodeID: %v, ipport: %v\n", common.CurrentTime(), nodeID, ipport)
	}
}

func updateGroupSDKNode(nd *Node, p2pType int) { //nooo
	n := RpcNode(nodeToRPC(nd))
	for gid, g := range SDK_groupList {
		for i, node := range g.Nodes {
			if node.ID == n.ID {
				ipp1 := fmt.Sprintf("%v:%v", node.IP, node.UDP)
				ipp2 := fmt.Sprintf("%v:%v", n.IP, n.UDP)
				fmt.Printf("%v ==== updateGroupSDKNode() ====, nodeID: %v, %v vs %v\n", common.CurrentTime(), n.ID, ipp2, ipp1)
				if ipp1 != ipp2 {
					fmt.Printf("%v ==== updateGroupSDKNode() ====, %v vs %v\n", common.CurrentTime(), ipp2, ipp1)
					g.Nodes[i] = n
					fmt.Printf("%v ==== updateGroupSDKNode() ====, update group(gid=%v) enode %v -> %v\n", common.CurrentTime(), gid, node, n)
					//sendGroupInfo(g, p2pType)
					sendGroupInit(g, p2pType)
					StoreGroupToDb(g)
					break
				}
				//ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
				//go SendToPeer(gid, node.ID, ipa, "", Sdkprotocol_type)
				tmpi := i
				go sendGroupInit2Node(gid, node, tmpi)
				break
			}
		}
	}
}

func checkGroupSDKListExist(n *Node) (bool, bool) { //return: exist, update //nooo
	for i, node := range groupSDKList {
		if node.ID == n.ID {
			ip1 := fmt.Sprintf("%v", node.IP)
			ip2 := fmt.Sprintf("%v", n.IP)
			if ip1 != ip2 || node.UDP != n.UDP {
				fmt.Printf("%v ==== checkGroupSDKListExist() ====, string(node.IP)=%v, string(n.IP)=%v, node.UDP=%v, n.UDP=%v\n", common.CurrentTime(), ip1, ip2, node.UDP, n.UDP)
				fmt.Printf("%v ==== checkGroupSDKListExist() ====, enode %v -> %v(new connect)\n", common.CurrentTime(), groupSDKList[i], n)
				groupSDKList[i] = n
				return true, true
			}
			return true, false
		}
	}
	return false, true
}

func setGroupSDK(n *Node, replace string, p2pType int) {
	GroupSDK.Lock()
	defer GroupSDK.Unlock()
	fmt.Printf("==== setGroupSDK() ====, node: %v, add/replace: %v\n", n, replace)
	if replace == "add" {
		if setgroup == 0 {
			//check 1+1+1 group
			updateGroupSDKNode(n, p2pType)
			return
		} else {
			return// not auto create group for bootnode
		}
		et, ut := checkGroupSDKListExist(n)
		if et == true {
			if ut == true {
				go updateGroup(n, p2pType)
			} else {
				go updateGroupNode(n, p2pType)
			}
			return
		}
		fmt.Printf("==== setGroupSDK() ====, len(groupSDKList) = %v, SDK_groupNum = %v\n", len(groupSDKList), SDK_groupNum)
		if len(groupSDKList) == (SDK_groupNum - 1) {
			if SDK_groupList[n.ID] == nil { // not exist group
				addGroupSDK(n, p2pType)
			} else {
				et, up := checkNodeIDExist(n)
				if et == true && up == true {
					if SDK_groupList[n.ID] != nil { // exist group
						delete(SDK_groupList, n.ID)
					}
					addGroupSDK(n, p2pType)
				}
			}
			fmt.Printf("==== setGroupSDK() ====, nodeID: %v, group: %v\n", n.ID, SDK_groupList[n.ID])
			sendGroupInfo(n.ID, SDK_groupList[n.ID].Nodes, p2pType)
			sendGroupInit(SDK_groupList[n.ID], p2pType)
			StoreGroupToDb(SDK_groupList[n.ID])
		} else { // add self node
			if len(groupSDKList) < SDK_groupNum {
				//e := fmt.Sprintf("enode://%v@%v:%v", node.ID, node.IP, node.UDP)
				groupSDKList = append(groupSDKList, n)
				fmt.Printf("==== setGroupSDK() ====, len(groupSDKList) = %v\n", len(groupSDKList))
				if len(groupSDKList) == (SDK_groupNum - 1) {
					StoreGroupSDKListToDb()
				}
			}
		}
	} else {
		if setgroup == 1 {
			fmt.Printf("==== setGroupSDK() ====, node: %v, add/replace: %v\n", n, replace)
		}
		//if SDK_groupList[n.ID] != nil { // exist group
		//	delete(SDK_groupList, n.ID)
		//}
	}
}

//send group info
func setGroupCC(n *Node, replace string, p2pType int) {
	groupList := getGroupList(NodeID{}, p2pType)
	groupChanged := getGroupChange(p2pType)
	groupMemNum := getGroupMemNum(p2pType)

	if setgroup == 0 {
		return
	}
	groupList.Lock()
	defer groupList.Unlock()
	if *groupChanged == 2 {
		if replace == "add" {
			count := 0
			enode := ""
			for i := 0; i < groupList.count; i++ {
				count++
				node := groupList.Nodes[i]
				if enode != "" {
					enode += Dcrmdelimiter
				}
				e := fmt.Sprintf("enode://%v@%v:%v", node.ID, node.IP, node.UDP)
				enode += e
				if bytes.Equal(n.IP, node.IP) == true && n.UDP == node.UDP {
					ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
					go SendToPeer(NodeID{}, node.ID, ipa, "", p2pType)
				}
			}
			enodes := fmt.Sprintf("%v,%v", count, enode)
			if p2pType == Dcrmprotocol_type {
				go callPrivKeyEvent(enodes)
			}
		}
		return
	}

	if replace == "add" {
		if groupList.count >= groupMemNum {
			groupList.count = groupMemNum
			return
		}
		groupList.Nodes = append(groupList.Nodes, RpcNode(nodeToRPC(n)))
		groupList.count++
		if *groupChanged == 0 {
			*groupChanged = 1
		}
	} else if replace == "remove" {
		if groupList.count <= 0 {
			groupList.count = 0
			return
		}
		for i := 0; i < groupList.count; i++ {
			if groupList.Nodes[i].ID == n.ID {
				groupList.Nodes = append(groupList.Nodes[:i], groupList.Nodes[i+1:]...)
				groupList.count--
				if *groupChanged == 0 {
					*groupChanged = 1
				}
				break
			}
		}
	}
	if groupList.count == groupMemNum && *groupChanged == 1 {
		count := 0
		enode := ""
		for i := 0; i < groupList.count; i++ {
			count++
			node := groupList.Nodes[i]
			if enode != "" {
				enode += Dcrmdelimiter
			}
			e := fmt.Sprintf("enode://%v@%v:%v", node.ID, node.IP, node.UDP)
			enode += e
			ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
			go SendToPeer(NodeID{}, node.ID, ipa, "", p2pType)
		}
		enodes := fmt.Sprintf("%v,%v", count, enode)
		if p2pType == Dcrmprotocol_type {
			go callPrivKeyEvent(enodes)
		}
		*groupChanged = 2
	}
}

//send group info
func SendMsgToNode(toid NodeID, toaddr *net.UDPAddr, msg string) error {
	if msg == "" {
		return nil
	}
	return Table4group.net.sendMsgToPeer(toid, toaddr, msg)
}

func SendToPeer(gid, toid NodeID, toaddr *net.UDPAddr, msg string, p2pType int) error {
	fmt.Printf("==== SendToPeer() ====, toaddr: %v, msg: %v\n", toaddr, msg)
	return Table4group.net.sendToPeer(gid, toid, toaddr, msg, p2pType)
}
func (t *udp) sendToPeer(gid, toid NodeID, toaddr *net.UDPAddr, msg string, p2pType int) error {
	req := getGroupInfo(gid, p2pType)
	fmt.Printf("%v ====  (t *udp) sendToPeer()  ====, toaddr: %v, groupInfo: %v\n", common.CurrentTime(), toaddr, req)
	if req == nil {
		return nil
	}
	errc := t.pending(toid, byte(Dcrm_groupInfoPacket), func(r interface{}) bool {
		return true
	})
	_, errt := t.send(toaddr, byte(Dcrm_groupInfoPacket), req)
	if errt != nil {
		fmt.Printf("%v ====  (t *udp) sendToPeer()  ====, t.send, toaddr: %v, err: %v\n", common.CurrentTime(), toaddr, errt)
	} else {
		fmt.Printf("%v ====  (t *udp) sendToPeer()  ====, t.send, toaddr: %v, groupInfo: %v SUCCESS\n", common.CurrentTime(), toaddr, req)
	}
	err := <-errc
	return err
}
func (req *Group) name() string { return "GROUPMSG/v4" }
func (req *Group) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	nodes := make([]*Node, 0)
	for _, rn := range req.Nodes {
		fmt.Printf("%v ==== (req *Group) handle() ====, Node: %v\n", common.CurrentTime(), rn)
		n, err := t.nodeFromRPC(from, rpcNode(rn))
		if err != nil {
			fmt.Printf("%v ==== (req *Group) handle() ====, gid: %v, Node: %v Group p2perror: %v\n", common.CurrentTime(), req.ID, rn, err)
			return err
		}
		fmt.Printf("%v ==== (req *Group) handle() ====, append Node: %v\n", common.CurrentTime(), rn)
		nodes = append(nodes, n)
	}

	fmt.Printf("%v ==== (req *Group) handle() ====, callGroupEvent, from: %v, gid: %v, req.Nodes: %v\n", common.CurrentTime(), from, req.ID, nodes)
	go callGroupEvent(req.ID, req.Mode, nodes, int(req.P2pType), req.Type)
	return nil
}

//send msg
func (t *udp) sendMsgToPeer(toid NodeID, toaddr *net.UDPAddr, msg string) error {
	errc := t.pending(toid, PeerMsgPacket, func(r interface{}) bool {
		return true
	})
	_, errs := t.send(toaddr, PeerMsgPacket, &message{
		Msg:        msg,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	if errs != nil {
		fmt.Printf("==== (t *udp) sendMsgToPeer ====, errs: %v\n", errs)
	}
	err := <-errc
	return err
}
func (req *message) name() string { return "MESSAGE/v4" }

func (req *message) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	fmt.Printf("====  (req *message) handle()  ====\n")
	if expired(req.Expiration) {
		return errExpired
	}
	go callPriKeyEvent(req.Msg)
	return nil
}

var groupcallback func(NodeID, string, interface{}, int, string)

func RegisterGroupCallback(callbackfunc func(NodeID, string, interface{}, int, string)) {
	groupcallback = callbackfunc
}

func callGroupEvent(gid NodeID, mode string, n []*Node, p2pType int, Type string) {
	if groupcallback != nil {
		fmt.Printf("==== callGroupEvent() ====, gid: %v, mode: %v, n: %v, p2pType: %v, Type: %v\n", gid, mode, n, p2pType, Type)
		groupcallback(gid, mode, n, p2pType, Type)
	}
}

var prikeycallback func(interface{})

func RegisterPriKeyCallback(callbackfunc func(interface{})) {
	prikeycallback = callbackfunc
}

func callPriKeyEvent(msg string) {
	if prikeycallback != nil {
		prikeycallback(msg)
	}
}

func callMsgEvent(e interface{}, p2pType int, fromID string) <-chan string {
	switch p2pType {
	case Sdkprotocol_type:
		if sdkcallback != nil {
			return sdkcallback(e, fromID)
		} else {
			fmt.Printf("==== callMsgEvent() ====, error: callback func is nil, RegisterSdkMsgCallback not called\n")
			ch := make(chan string)
			ch <- "RegisterSdkMsgCallback not called"
			return ch
		}
	case Dcrmprotocol_type:
		return dcrmcallback(e)
	case Xprotocol_type:
		return xpcallback(e)
	}
	ch := make(chan string)
	ch <- "p2pType invalid"
	return ch
}

var sdkcallback func(interface{}, string) <-chan string

func RegisterSdkMsgCallback(sdkbackfunc func(interface{}, string) <-chan string) {
	sdkcallback = sdkbackfunc
}
func callsdkEvent(e interface{}, fromID string) <-chan string {
	return sdkcallback(e, fromID)
}

//peer(of DCRM group) receive other peer msg to run dcrm
var dcrmcallback func(interface{}) <-chan string

func RegisterDcrmMsgCallback(callbackfunc func(interface{}) <-chan string) {
	dcrmcallback = callbackfunc
}
func calldcrmEvent(e interface{}) <-chan string {
	return dcrmcallback(e)
}

var sdkretcallback func(interface{}, string)

func RegisterSdkMsgRetCallback(sdkbackfunc func(interface{}, string)) {
	sdkretcallback = sdkbackfunc
}
func callsdkReturn(e interface{}, fromID string) {
	if sdkretcallback != nil {
		sdkretcallback(e, fromID)
	}
}

//return
var dcrmretcallback func(interface{})

func RegisterDcrmMsgRetCallback(callbackfunc func(interface{})) {
	dcrmretcallback = callbackfunc
}
func calldcrmReturn(e interface{}) {
	dcrmretcallback(e)
}

//peer(of Xp group) receive other peer msg to run dccp
var xpcallback func(interface{}) <-chan string

func RegisterXpMsgCallback(callbackfunc func(interface{}) <-chan string) {
	xpcallback = callbackfunc
}
func callxpEvent(e interface{}) <-chan string {
	return xpcallback(e)
}

//return
var xpretcallback func(interface{})

func RegisterXpMsgRetCallback(callbackfunc func(interface{})) {
	xpretcallback = callbackfunc
}
func callxpReturn(e interface{}) {
	xpretcallback(e)
}

func callCCReturn(e interface{}, p2pType int, fromID string) {
	switch p2pType {
	case Sdkprotocol_type:
		callsdkReturn(e, fromID)
	case Dcrmprotocol_type:
		calldcrmReturn(e)
	case Xprotocol_type:
		callxpReturn(e)
	}
}

//get private Key
var privatecallback func(interface{})

func RegisterSendCallback(callbackfunc func(interface{})) {
	privatecallback = callbackfunc
}

func callPrivKeyEvent(e string) {
	if privatecallback != nil {
		privatecallback(e)
	}
}

func ParseNodes(n []*Node) (int, string) {
	i := 0
	enode := ""
	for _, e := range n {
		if enode != "" {
			enode += Dcrmdelimiter
		}
		i++
		enode += e.String()
	}
	return i, enode
}

func GetLocalIP() string {
	return LocalIP
}

func GetRemoteIP() net.IP {
	return RemoteIP
}

func GetRemotePort() uint16 {
	if RemotePort == 0 {
		RemotePort = Table4group.self.UDP
	}
	return RemotePort
}

func GetLocalID() NodeID {
	return SelfNodeID
}

func GetEnode() string {
	return SelfEnode
}

func updateRemoteIP(ip net.IP, port uint16) {
	if setgroup == 0 && RemoteUpdate == false {
		RemoteUpdate = true
		enode := fmt.Sprintf("enode://%v@%v:%v", GetLocalID(), RemoteIP, RemotePort)
		n, _ := ParseNode(enode)
		setGroup(n, "add")
		updateIPPort(ip, port)
	}
}

func updateIPPort(ip net.IP, port uint16) {
	fmt.Printf("updateRemoteIP, IP:port = %v:%v\n\n", ip, port)
	RemoteIP = ip
	RemotePort = port
	SelfEnode = fmt.Sprintf("enode://%v@%v:%v", GetLocalID(), RemoteIP, RemotePort)
	SelfIPPort = fmt.Sprintf("%v:%v", RemoteIP, RemotePort)
}

func SendToMyselfAndReturn(selfID, msg string, p2pType int) {
	msgc := callMsgEvent(msg, p2pType, selfID)
	msgr := <-msgc
	callCCReturn(msgr, p2pType, selfID)
}

func UpdateGroupNodesNumber(number, p2pType int) {
	switch p2pType {
	case Sdkprotocol_type:
		if SDK_groupNum == 0 {
			SDK_groupNum = number
		}
		break
	case Dcrmprotocol_type:
		if Dcrm_groupMemNum == 0 {
			Dcrm_groupMemNum = number
		}
		break
	case Xprotocol_type:
		if Xp_groupMemNum == 0 {
			Xp_groupMemNum = number
		}
		break
	}
}

func GetEnodeStatus(enode string) (string, error) {
	n, err := ParseNode(enode)
	if err != nil || n.validateComplete() != nil {
		fmt.Printf("GetEnodeStatus ParseNode err: %v\n", enode)
		return "", errors.New("enode wrong format")
	}
	selfid := fmt.Sprintf("%v", GetLocalID())
	fmt.Printf("GetEnodeStatus selfid: %v, node.ID: %v\n", selfid, n.ID)
	if n.ID.String() == selfid {
		return "OnLine", nil
	} else {
		return getOnLine(n.ID), nil
	}
	return "OffLine", nil
}

func StoreGroupToDb(groupInfo *Group) error { //nooo
	groupDbLock.Lock()
	defer groupDbLock.Unlock()

	dir := getGroupDir()
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		return err
	}

	key := crypto.Keccak256Hash([]byte(strings.ToLower(fmt.Sprintf("%v", groupInfo.ID)))).Hex()
	ac := new(Group)
	ac.ID = groupInfo.ID
	ac.Mode = groupInfo.Mode
	ac.P2pType = groupInfo.P2pType
	ac.Type = groupInfo.Type
	ac.Nodes = make([]RpcNode, 0)
	for _, n := range groupInfo.Nodes {
		ac.Nodes = append(ac.Nodes, n)
	}
	alos, err := Encode2(ac)
	if err != nil {
		db.Close()
		return err
	}
	ss, err := Compress([]byte(alos))
	if err != nil {
		db.Close()
		return err
	}

	fmt.Printf("==== StoreGroupInfo() ==== new, ac: %v\n", ac)
	db.Put([]byte(key), []byte(ss), nil)
	db.Close()
	return nil
}

func RecoverGroupByGID(gid NodeID) (*Group, error) {
	groupDbLock.Lock()
	defer groupDbLock.Unlock()

	dir := getGroupDir()
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		return nil, err
	}

	key := crypto.Keccak256Hash([]byte(strings.ToLower(fmt.Sprintf("%v", gid)))).Hex()
	da, err := db.Get([]byte(key), nil)
	if err == nil {
		ds, err := UnCompress(string(da))
		if err != nil {
			db.Close()
			return nil, err
		}

		dss, err := Decode2(ds, "Group")
		if err != nil {
			fmt.Printf("==== GetGroupInfo() ====, error:decode group data fail\n")
			db.Close()
			return nil, err
		}

		ac := dss.(*Group)
		fmt.Printf("==== GetGroupInfo() ====, ac: %v\n", ac)
		db.Close()
		return ac, nil
	}
	db.Close()
	return nil, err
}

func StoreGroupSDKListToDb() error { //nooo
	groupDbLock.Lock()
	defer groupDbLock.Unlock()

	dir := getGroupSDKListDir()
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		return err
	}

	key := crypto.Keccak256Hash([]byte("groupsdklist")).Hex()
	ac := new(GroupSDKList)
	ac.Nodes = make([]*Node, 0)
	for _, n := range groupSDKList {
		ac.Nodes = append(ac.Nodes, n)
	}
	alos, err := Encode2(ac)
	if err != nil {
		db.Close()
		return err
	}
	ss, err := Compress([]byte(alos))
	if err != nil {
		db.Close()
		return err
	}

	fmt.Printf("==== StoreGroupSDKListToDb() ==== new, groupSDKList: %v\n", ac)
	db.Put([]byte(key), []byte(ss), nil)
	db.Close()
	return nil
}

func RecoverGroupSDKList() error { //nooo
	groupDbLock.Lock()
	defer groupDbLock.Unlock()

	dir := getGroupSDKListDir()
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		return err
	}
	defer db.Close()

	key := crypto.Keccak256Hash([]byte("groupsdklist")).Hex()
	da, err := db.Get([]byte(key), nil)
	if err == nil {
		ds, err := UnCompress(string(da))
		if err != nil {
			return err
		}

		dss, err := Decode2(ds, "GroupSDKList")
		if err != nil {
			fmt.Printf("==== RecoverGroupSDKList() ====, error:decode group data fail\n")
			return err
		}

		ac := dss.(*GroupSDKList)
		fmt.Printf("==== RecoverGroupSDKList() ====, groupSDKList: %v\n", ac)
		for _, n := range ac.Nodes {
			groupSDKList = append(groupSDKList, n)
		}
		return nil
	}
	return err
}

func GetGroupDir() string {
	return getGroupDir()
}

func getGroupDir() string {
	dir := p2pDir
	if setgroup != 0 {
		dir = filepath.Join(dir, p2pSuffix, "bootnode-"+SelfID)
	} else {
		dir = filepath.Join(dir, p2pSuffix, SelfID)
	}
	fmt.Printf("==== getGroupDir() ====, dir: %v\n", dir)
	return dir
}

func getGroupSDKListDir() string {
	if setgroup == 0 {
		return ""
	}
	dir := filepath.Join(p2pDir, p2pSuffix, "SDKList-"+SelfID)
	fmt.Printf("==== getGroupSDKListDir() ====, dir: %v\n", dir)
	return dir
}

func Encode2(obj interface{}) (string, error) {
	switch obj.(type) {
	case *Group:
		ch := obj.(*Group)
		ret, err := json.Marshal(ch)
		if err != nil {
			return "", err
		}
		return string(ret), nil
	case *GroupSDKList:
		ch := obj.(*GroupSDKList)
		ret, err := json.Marshal(ch)
		if err != nil {
			return "", err
		}
		return string(ret), nil
	default:
		return "", fmt.Errorf("encode obj fail.")
	}
}

func Decode2(s string, datatype string) (interface{}, error) {
	if datatype == "GroupSDKList" {
		var m GroupSDKList
		err := json.Unmarshal([]byte(s), &m)
		if err != nil {
			return nil, err
		}
		return &m, nil
	}
	if datatype == "Group" {
		var m Group
		err := json.Unmarshal([]byte(s), &m)
		if err != nil {
			return nil, err
		}
		return &m, nil
	}
	return nil, fmt.Errorf("decode obj fail.")
}

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

func RecoverGroupAll(SdkGroup map[NodeID]*Group) error { //nooo
	groupDbLock.Lock()
	defer groupDbLock.Unlock()

	dir := getGroupDir()
	fmt.Printf("==== getGroupFromDb() ====, dir = %v\n", dir)
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		fmt.Printf("==== getGroupFromDb() ====, db open err %v\n", err)
		return err
	}

	iter := db.NewIterator(nil, nil)
	for iter.Next() {
		value := string(iter.Value())
		ss, err := UnCompress(value)
		if err != nil {
			fmt.Printf("==== getGroupFromDb() ====, UnCompress err %v\n", err)
			continue
		}

		g, err := Decode2(ss, "Group")
		if err != nil {
			fmt.Printf("==== getGroupFromDb() ====, Decode2 err %v\n", err)
			continue
		}

		gm := g.(*Group)
		groupTmp := NewGroup()
		groupTmp.Mode = gm.Mode
		groupTmp.P2pType = gm.P2pType
		groupTmp.Type = gm.Type
		groupTmp.ID = gm.ID
		SdkGroup[gm.ID] = groupTmp
		groupTmp.Nodes = make([]RpcNode, 0)
		for _, node := range gm.Nodes {
			groupTmp.Nodes = append(groupTmp.Nodes, node)
		}
		fmt.Printf("==== getGroupFromDb() ====, nodes: %v\n", groupTmp.Nodes)
		fmt.Printf("==== getGroupFromDb() ====, SdkGroup: %v\n", SdkGroup[gm.ID])
	}
	db.Close()
	return nil
}

func NewGroup() *Group {
	return &Group{}
}

func UpdateOnLine(nodeID NodeID, online bool) {
	if nodeOnline[nodeID] == nil {
		nodeOnline[nodeID] = new(OnLineStatus)
	}
	nodeOnline[nodeID].Lock.Lock()
	nodeOnline[nodeID].Status = online
	nodeOnline[nodeID].Lock.Unlock()
	fmt.Printf("%v ==== UpdateOnLine() ====, nodeid: %v, status: %v\n", common.CurrentTime(), nodeID, online)
}

func getOnLine(nodeID NodeID) string {
	if nodeOnline[nodeID] != nil {
		nodeOnline[nodeID].Lock.Lock()
		online := nodeOnline[nodeID].Status
		nodeOnline[nodeID].Lock.Unlock()
		if online == true {
			return "OnLine"
		}
	}
	return "OffLine"
}

func PrintBucketNodeInfo(id NodeID) {
	Table4group.mutex.Lock()
	defer Table4group.mutex.Unlock()

	findNode := false
	for i := range Table4group.buckets {
		if findNode == true {
			break
		}
		findReplacements := true
		b := Table4group.buckets[i]
		for j, n := range b.entries { // live entries, sorted by time of last contact
			if id == n.ID {
				fmt.Printf("==== PrintBucketNodeInfo() ====, buckets: %v, entries: %v, %v:%v\n", i, j, n.IP, n.UDP)
				findNode = true
				findReplacements = false
				break
			}
		}
		if findReplacements == true {
			for j, n := range b.replacements { // live entries, sorted by time of last contact
				if id == n.ID {
					fmt.Printf("==== PrintBucketNodeInfo() ====, replacements: %v, %v:%v\n", j, n.IP, n.UDP)
					findNode = true
					break
				}
			}
		}
	}
	if findNode != true {
		fmt.Printf("==== PrintfBucketNodeInfo() ====, %v, not exist int bucket fail\n", id)
	}
}


func Remove(n *Node) {
	fmt.Printf("==== remove() ====, n: %v\n", n)
	Table4group.delete(n)
}

func checkUpdateNode(n *Node) {
	if setgroup == 1 {
		return
	}
	if updateGroupsNode == true {
		return
	}
	updateGroupsNode = true
	if setgroup == 0 && n.ID != SelfNodeID && checkAddNodes(n.ID) == true {
		if ok := checkSeeds(n.ID); ok == false {
			setGroup(n, "add")
		}
	}
	updateGroupsNode = false
}

func loadedSeed(seeds []*Node) {
	if loadedDone == false {
		loadedDone = true
		for i := range seeds {
			loadedSeeds[seeds[i].ID] = 1
		}
	}
}

func AddNodes(nid NodeID) {
	addNodesLock.Lock()
	defer addNodesLock.Unlock()
	addNodes[nid] = 1
}

func checkAddNodes(nid NodeID) bool {
	addNodesLock.Lock()
	defer addNodesLock.Unlock()
	if addNodes[nid] == 1 {
		delete(addNodes, nid)
		return true
	}
	return false
}

func checkSeeds(nid NodeID) bool {
	if loadedSeeds[nid] == 1 {
		return true
	}
	return false
}

func InitIP(ip string, port uint16) {
	LocalIP = ip
	RemoteIP = parseIP(ip)
	RemotePort = port
	SelfEnode = fmt.Sprintf("enode://%v@%v:%v", GetLocalID(), RemoteIP, RemotePort)
	fmt.Printf("==== InitIP() ====, IP: %v\n", RemoteIP)
	go func(enode string) {
		n, _ := ParseNode(enode)
		<-SDK_groupListChan
		setGroup(n, "add")
		RemoteUpdate = false
	}(SelfEnode)
}

func parseIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		fmt.Printf("parseIP invalid %v\n", s)
		return net.IP{}
	}
	return ip
}

