// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package discover implements the Node Discovery Protocol.
//
// The Node Discovery protocol provides a way to find RLPx nodes that
// can be connected to. It uses a Kademlia-like protocol to maintain a
// distributed database of the IDs and endpoints of all listening
// nodes.

//modify by huangweijun@fusion.org
package discover

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/fsn-dev/dcrm-sdk/p2p/rlp"
)

var (
	setgroupNumber = 0
	setgroup       = 0
	Dcrmdelimiter  = "dcrmmsg"
	Dcrm_groupList *group
	Xp_groupList   *group
	tmpdcrmmsg     = &getdcrmmessage{Number: [3]byte{0, 0, 0}, Msg: ""}
	setlocaliptrue = false
	localIP        = "0.0.0.0"
	changed        = 0
	Xp_changed     = 0

	SDK_groupList map[NodeID]*group = make(map[NodeID]*group)
	groupSDK sync.Mutex
	groupSDKList []*Node
)

const (
	Dcrm_groupMemNum = 3
	Xp_groupMemNum   = 3
	SDK_groupNum = 3
)

const (
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
	PeerMsgPacket
	getDcrmPacket
	getSdkPacket
	Xp_getCCPacket
	getXpPacket
	gotDcrmPacket
	gotSdkPacket
	gotXpPacket
)

type (
	findgroup struct {
		ID NodeID
		P2pType    byte
		Target     NodeID // doesn't need to be an actual public key
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	group struct {
		sync.Mutex
		ID      NodeID
		//gname      NodeID
		msg        string
		count      int
		P2pType    byte
		Nodes      []rpcNode
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	groupmessage struct {
		sync.Mutex
		ID      NodeID
		//gname      []string
		msg        string
		count      int
		P2pType    byte
		Nodes      []rpcNode
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
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
		Expiration uint64
	}

	dcrmmessage struct {
		//sync.Mutex
		Target     NodeID // doesn't need to be an actual public key
		P2pType    byte
		Msg        string
		Expiration uint64
	}
)

func (req *findgroup) name() string { return "FINDGROUP/v4" }
func (req *group) name() string     { return "GROUP/v4" }

func getGroupList(gid NodeID, p2pType int) *group {
	switch p2pType {
	case Sdkprotocol_type:
		fmt.Printf("getGroupList, gid: %v, SDK_groupList[gid]: %v\n", gid, SDK_groupList[gid])
		return getGroupSDK(gid)
	case Dcrmprotocol_type:
		return Dcrm_groupList
	case Xprotocol_type:
		return Xp_groupList
	}
	return nil
}

func getGroupSDK(gid NodeID) *group{
	for id, g := range SDK_groupList {
		index := id.String()
		gf := gid.String()
		fmt.Printf("getGroupSDK, id: %v, gid: %v\n", id, gid)
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
func (t *udp) findgroup(gid, toid NodeID, toaddr *net.UDPAddr, target NodeID, p2pType int) ([]*Node, error) {
	//log.Debug("====  (t *udp) findgroup()  ====", "gid", gid, "p2pType", p2pType)
	nodes := make([]*Node, 0, bucketSize)
	nreceived := 0
	groupPacket := getGroupPacket(p2pType)
	findgroupPacket := getFindGroupPacket(p2pType)
	groupMemNum := getGroupMemNum(p2pType)
	errc := t.pending(toid, byte(groupPacket), func(r interface{}) bool {
		reply := r.(*group)
		//log.Debug("findgroup", "reply", reply, "r", r)
		for _, rn := range reply.Nodes {
			nreceived++
			n, err := t.nodeFromRPC(toaddr, rn)
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
	t.send(toaddr, byte(findgroupPacket), &findgroup{
		ID: gid,
		P2pType:    byte(p2pType),
		Target:     target,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
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
		t.send(from, byte(groupPacket), p)
       }
       return nil
}

func (req *group) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
       //log.Debug("====  (req *group) handle()  ====")
       //log.Debug("group handle", "group handle: ", req)
       if expired(req.Expiration) {
               return errExpired
       }
       groupPacket := getGroupPacket(int(req.P2pType))
       if !t.handleReply(fromID, byte(groupPacket), req) {
		//log.Debug("====  (req *group) handle()  ====", "errUnsolicitedReply", errUnsolicitedReply)
		return errUnsolicitedReply
       }
       return nil
}

func (req *getdcrmmessage) name() string { return "GETDCRMMSG/v4" }
func (req *dcrmmessage) name() string    { return "DCRMMSG/v4" }

var number [3]byte

func SendToGroupCC(toid NodeID, toaddr *net.UDPAddr, msg string, p2pType int) (string, error) {
	return Table4group.net.sendToGroupCC(toid, toaddr, msg, p2pType)
}

// sendgroup sends to group dcrm and waits until
// the node has reply.
func (t *udp) sendToGroupCC(toid NodeID, toaddr *net.UDPAddr, msg string, p2pType int) (string, error) {
       //log.Debug("====  (t *udp) sendToGroupCC()  ====", "p2pType", p2pType)
       err := errors.New("")
       retmsg := ""
       getCCPacket := getCCPacket(p2pType)
       number[0]++
       //log.Debug("sendToGroupCC", "send toaddr: ", toaddr)
       if len(msg) <= 800 {
               number[1] = 1
               number[2] = 1
		//log.Debug("sendToGroupCC", "getCCPacket", getCCPacket, "byte(getCCPacket)", byte(getCCPacket))
               _, err = t.send(toaddr, byte(getCCPacket), &getdcrmmessage{
                       Number:     number,
                       P2pType:    byte(p2pType),
                       Msg:        msg,
                       Expiration: uint64(time.Now().Add(expiration).Unix()),
               })
               //log.Debug("dcrm", "number = ", number, "msg(<800) = ", msg)
       } else if len(msg) > 800 && len(msg) < 1600 {
               number[1] = 1
               number[2] = 2
               t.send(toaddr, byte(getCCPacket), &getdcrmmessage{
                       Number:     number,
                       P2pType:    byte(p2pType),
                       Msg:        msg[0:800],
                       Expiration: uint64(time.Now().Add(expiration).Unix()),
               })
               //log.Debug("send", "msg(> 800):", msg)
               number[1] = 2
               number[2] = 2
               _, err = t.send(toaddr, byte(getCCPacket), &getdcrmmessage{
                       Number:     number,
                       P2pType:    byte(p2pType),
                       Msg:        msg[800:],
                       Expiration: uint64(time.Now().Add(expiration).Unix()),
               })
       } else {
               //log.Error("send, msg size > 1600, sent failed.\n")
               return "send fail, msg size > 1600.", nil
       }
       //errc := t.pending(toid, gotDcrmPacket, func(r interface{}) bool {
       //      fmt.Printf("dcrm, gotDcrmPacket: %+v\n", r)
       //      retmsg = r.(*dcrmmessage).Msg
       //      return true
       //})
       //err := <-errc
       //fmt.Printf("dcrm, retmsg: %+v\n", retmsg)
       return retmsg, err
}

func (req *getdcrmmessage) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
       //log.Debug("====  (req *getdcrmmessage) handle()  ====")
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
       msgp := req.Msg
       num := req.Number
       //log.Debug("dcrm handle", "req.Number", num)
       if num[2] > 1 {
               if tmpdcrmmsg.Number[0] == 0 || num[0] != tmpdcrmmsg.Number[0] {
                       tmpdcrmmsg = &(*req)
                       //log.Debug("dcrm handle", "tmpdcrmmsg = ", tmpdcrmmsg)
                       return nil
               }
               //log.Debug("dcrm handle", "tmpdcrmmsg.Number = ", tmpdcrmmsg.Number)
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
               //log.Debug("getmessage", "callEvent msg: ", msgp)
               msgc := callMsgEvent(msgp, int(req.P2pType), fromID.String())
               //callUpdateOrderCacheEvent(msgp)//for mongo
               //log.Debug("getmessage", "callEvent retmsg: ", msgc)
               msg := <-msgc
               //tmpdcrmmsg.Number = [3]byte{}
               //t.send(from, gotDcrmPacket, &getdcrmmessage{
               //log.Debug("getmessage", "send(from", from, "msg", msg)
               gotpacket := getGotPacket(int(req.P2pType))
               t.send(from, byte(gotpacket), &dcrmmessage{
                       Target:     fromID,
                       P2pType:    req.P2pType,
                       Msg:        msg,
                       Expiration: uint64(time.Now().Add(expiration).Unix()),
               })
               //log.Debug("dcrm handle", "send to from: ", from, ", message: ", msg)
       }()
       return nil
}

func (req *dcrmmessage) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
       //log.Debug("====  (req *dcrmmessage) handle()  ====\n")
       //log.Debug("dcrmmessage", "handle, req: ", req)
       //if expired(req.Expiration) {
       //        return errExpired
       //}
       //if !t.handleReply(fromID, gotDcrmPacket, req) {
       //      return errUnsolicitedReply
       //}
       //log.Debug("dcrmmessage", "handle, callReturn req.Msg", req.Msg)
       go callCCReturn(req.Msg, int(req.P2pType), fromID.String())
       return nil
}

func getGroupInfo(gid NodeID, p2pType int) *group {
//	log.Debug("getGroupInfo", "p2pType", p2pType)
	groupMemNum := getGroupMemNum(p2pType)
	groupList := getGroupList(gid, p2pType)
	fmt.Printf("getGroupInfo, gid: %v, groupList: %v, setgroup: %v, p2pType: %v\n", gid, groupList, setgroup, p2pType)
	if setgroup == 1 && groupList != nil && groupList.count == groupMemNum {
		groupList.Lock()
		defer groupList.Unlock()
		p := groupList
		p.P2pType = byte(p2pType)
		p.Expiration = uint64(time.Now().Add(expiration).Unix())
		return p
	}
//	log.Warn("getGroupInfo nil")
	return nil
}

func InitGroup(Number int) error {
//	log.Debug("==== InitGroup() ====")
	setgroup = 1
	setgroupNumber = Number
	Dcrm_groupList = &group{msg: "dcrm", count: 0, Expiration: ^uint64(0)}
	Xp_groupList = &group{msg: "dcrm", count: 0, Expiration: ^uint64(0)}
	return nil
}

func SendToGroup(gid NodeID, msg string, allNodes bool, p2pType int) string {
//	log.Debug("==== SendToGroup() ====", "p2pType", p2pType)
	bn := Table4group.nursery[0]
	if bn == nil {
//		log.Warn("SendToGroup(), bootnode is nil\n")
		return ""
	}
	ipa := &net.UDPAddr{IP: bn.IP, Port: int(bn.UDP)}
	g := GetGroup(gid, bn.ID, ipa, bn.ID, p2pType)
	groupMemNum := getGroupMemNum(p2pType)
//	log.Debug("==== SendToGroup() ====", "GetGroup", g, "groupMemNum", groupMemNum)
	if g == nil || len(g) != groupMemNum {
//		log.Warn("SendToGroup(), group is nil\n")
		return ""
	}
	sent := make([]int, groupMemNum+1)
	retMsg := ""
	ret := ""
	count := 0
	pingErrorCount := 0
	for i := 1; i <= groupMemNum; {
		if pingErrorCount > groupMemNum * 5 {
			fmt.Printf("ping timeout\n")
			break
		}
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
//		log.Debug("sendToDcrmGroup", "group[", r, "]", g[r])
		n := g[r]
		if n.ID.String() == GetLocalID().String() {
			go SendToMyselfAndReturn(n.ID.String(), msg, p2pType)
		} else {
			ipa = &net.UDPAddr{IP: n.IP, Port: int(n.UDP)}
			err := Table4group.net.ping(n.ID, ipa)
			pingErrorCount += 1
			if err != nil {
//				log.Debug("sendToDcrmGroup, err", "group[", r, "]", g[r])
				continue
			}
			ret, err = Table4group.net.sendToGroupCC(n.ID, ipa, msg, p2pType)
		}
		retMsg = fmt.Sprintf("%v, %s ", n.IP, ret)
		count += 1
		if allNodes == false {
			break
		}
	}
	if (allNodes == false && count == 1) || (allNodes == true && count == groupMemNum) {
		return retMsg
	}
	return "send fail."
}

func GetGroup(gid, id NodeID, addr *net.UDPAddr, target NodeID, p2pType int) []*Node {
//	log.Debug("GetGroup", "gid", gid, "id", id, "addr", addr, "target", target, "p2pType", p2pType)
	g, _ := Table4group.net.findgroup(gid, id, addr, target, p2pType)
//	log.Debug("tab.net.findgroup", "g", g, "err", e)
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

func sendGroupInfo(groupList *group, p2pType int) {
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
		//if bytes.Equal(n.IP, node.IP) == true && n.UDP == node.UDP {
			ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
			go SendToPeer(groupList.ID, node.ID, ipa, "", p2pType)
		//}
	}
	//enodes := fmt.Sprintf("%v,%v,%v", groupList.ID, count, enode)
//	log.Debug("send group to nodes", "group: ", enodes)
//	log.Warn("send group to nodes", "group: ", enodes)
	if p2pType == Dcrmprotocol_type || p2pType == Sdkprotocol_type {
		//go callPrivKeyEvent(enodes)
		var tmp int = 0
		for i := 0; i < groupList.count; i++ {
			node := groupList.Nodes[i]
			cDPrivKey := fmt.Sprintf("%v", groupList.ID) + "|" + "1dcrmslash1:" + strconv.Itoa(tmp) + "#" + "Init"
			tmp++
			//go SendToPeer(enode, cDPrivKey)
			go func (node rpcNode, msg string) {
				ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
				SendMsgToNode(node.ID, ipa, msg)
			}(node, cDPrivKey)
		}
	}
}

func addGroupSDK(n *Node) {
	groupTmp := new(group)
	groupTmp.Nodes = []rpcNode{{},{},{}}
	for i, node := range groupSDKList {
		groupTmp.Nodes[i] = nodeToRPC(node)
		groupTmp.count++
	}
	groupTmp.Nodes[2] = nodeToRPC(n)
	groupTmp.count++
	groupTmp.ID = n.ID
	//fmt.Printf("addGroupSDK, gid: %v\n", groupTmp.ID)
	SDK_groupList[groupTmp.ID] = groupTmp
}

func updateGroupSDK(n *Node) {
	groupTmp := SDK_groupList[n.ID]
	for i, node := range groupTmp.Nodes {
		if node.ID == n.ID {
			groupTmp.Nodes = append(groupTmp.Nodes[:i], groupTmp.Nodes[i+1:]...)
			groupTmp.Nodes = append(groupTmp.Nodes, nodeToRPC(n))
			return
		}
	}
}

func checkNodeIDExist(n *Node) bool {
	groupTmp := SDK_groupList[n.ID]
	for _, node := range groupTmp.Nodes {
		if node.ID == n.ID {
			ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
			err := Table4group.net.ping(node.ID, ipa)
			if err == nil {
				return true
			}
			break
		}
	}
	return false
}

func checkSDKNodeExist(n *Node) bool {
	for i, node := range groupSDKList {
		nrpc := nodeToRPC(node)
		if nrpc.ID == n.ID {
			fmt.Printf("checkSDKNodeExist, update groupSDKList[%v] (%v -> %v)\n", i, groupSDKList[i], n)
			groupSDKList[i] = n
			return true
		}
	}
	return false
}

func setGroupSDK(n *Node, replace string, p2pType int) {
	if setgroup == 0 {
		return
	}
//	log.Debug("==== setGroupSDK() ====", "node", n, "add/replace", replace)
	fmt.Printf("==== setGroupSDK() ====, node: %v, add/replace: %v\n", n, replace)
	groupSDK.Lock()
	defer groupSDK.Unlock()
	if replace == "add" {
		if checkSDKNodeExist(n) {
			return
		}
		//if n.ID.String() == "ead5708649f3fb10343a61249ea8509b3d700f1f51270f13ecf889cdf8dafce5e7eb649df3ee872fb027b5a136e17de73965ec34c46ea8a5553b3e3150a0bf8d" ||
		//	n.ID.String() == "bd6e097bb40944bce309f6348fe4d56ee46edbdf128cc75517df3cc586755737733c722d3279a3f37d000e26b5348c9ec9af7f5b83122d4cfd8c9ad836a0e1ee" ||
		//	n.ID.String() == "1520992e0053bbb92179e7683b3637ea0d43bb2cd3694a94a1e90e909108421c2ce22e0abdb0a335efdd8e6391eb08ba967f641b42e4ebde39997c8ad000e8c8" {
		//grouplist.gname = append(groupList.gname, "dddddddddd")
		fmt.Printf("==== setGroupSDK() ====, len(groupSDKList) = %v, SDK_groupNum = %v\n", len(groupSDKList), SDK_groupNum)
		if len(groupSDKList) == (SDK_groupNum - 1) {
			if SDK_groupList[n.ID] == nil { // exist group
				addGroupSDK(n)
			} else {
				if checkNodeIDExist(n) {
					return
				} else {
					delete(SDK_groupList, n.ID)
					addGroupSDK(n)
				}
			}
			fmt.Printf("==== setGroupSDK() ====, nodeID: %v, group: %v\n", n.ID, SDK_groupList[n.ID])
			sendGroupInfo(SDK_groupList[n.ID], p2pType)
		} else { // add self node
			if len(groupSDKList) < SDK_groupNum {
				//e := fmt.Sprintf("enode://%v@%v:%v", node.ID, node.IP, node.UDP)
				groupSDKList = append(groupSDKList, n)
				fmt.Printf("==== setGroupSDK() ====, len(groupSDKList) = %v\n", len(groupSDKList))
			}
		}
	} else {
		if SDK_groupList[n.ID] != nil { // exist group
			delete(SDK_groupList, n.ID)
		}
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
//	log.Debug("==== setGroupCC() ====", "node", n, "add/replace", replace)
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
//			log.Debug("send group to nodes", "group: ", enodes)
			if p2pType == Dcrmprotocol_type {
				go callPrivKeyEvent(enodes)
			}
		}
		return
	}

	//fmt.Printf("node: %+v, tabal.self: %+v\n", n, Table4group.self)
	//if n.ID == Table4group.self.ID {
	//	return
	//}
	if replace == "add" {
//		log.Debug("group add", "groupList.count", groupList.count, "groupMemNum", groupMemNum)
		if groupList.count >= groupMemNum {
			groupList.count = groupMemNum
			return
		}
//		log.Debug("connect", "NodeID", n.ID.String())
		//if n.ID.String() == "ead5708649f3fb10343a61249ea8509b3d700f1f51270f13ecf889cdf8dafce5e7eb649df3ee872fb027b5a136e17de73965ec34c46ea8a5553b3e3150a0bf8d" ||
		//	n.ID.String() == "bd6e097bb40944bce309f6348fe4d56ee46edbdf128cc75517df3cc586755737733c722d3279a3f37d000e26b5348c9ec9af7f5b83122d4cfd8c9ad836a0e1ee" ||
		//	n.ID.String() == "1520992e0053bbb92179e7683b3637ea0d43bb2cd3694a94a1e90e909108421c2ce22e0abdb0a335efdd8e6391eb08ba967f641b42e4ebde39997c8ad000e8c8" {
		//grouplist.gname = append(groupList.gname, "dddddddddd")
		groupList.Nodes = append(groupList.Nodes, nodeToRPC(n))
		groupList.count++
		if *groupChanged == 0 {
			*groupChanged = 1
		}
//		log.Debug("group(add)", "node", n)
//		log.Debug("group", "groupList", groupList)
		//}
	} else if replace == "remove" {
//		log.Debug("group remove")
		if groupList.count <= 0 {
			groupList.count = 0
			return
		}
//		log.Debug("connect", "NodeID", n.ID.String())
		for i := 0; i < groupList.count; i++ {
			if groupList.Nodes[i].ID == n.ID {
				groupList.Nodes = append(groupList.Nodes[:i], groupList.Nodes[i+1:]...)
				groupList.count--
				if *groupChanged == 0 {
					*groupChanged = 1
				}
//				log.Debug("group(remove)", "node", n)
//				log.Debug("group", "groupList", groupList)
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
//			log.Debug("send group to node", "group", p2pType, "enode", e)
			go SendToPeer(NodeID{}, node.ID, ipa, "", p2pType)
			//TODO get and send privatekey slice
			//go SendMsgToNode(node.ID, ipa, "0xff00ff")
		}
		enodes := fmt.Sprintf("%v,%v", count, enode)
//		log.Debug("send group to nodes", "group", p2pType, "enodes", enodes)
		if p2pType == Dcrmprotocol_type {
			go callPrivKeyEvent(enodes)
		}
		*groupChanged = 2
	}
}

//send group info
func SendMsgToNode(toid NodeID, toaddr *net.UDPAddr, msg string) error {
//	log.Debug("==== discover.SendMsgToNode() ====", "toid", toid, "toaddr", toaddr, "msg", msg)
	if msg == "" {
		return nil
	}
	return Table4group.net.sendMsgToPeer(toid, toaddr, msg)
}

func SendToPeer(gid, toid NodeID, toaddr *net.UDPAddr, msg string, p2pType int) error {
//	log.Debug("==== SendToPeer() ====", "msg", msg)
	return Table4group.net.sendToPeer(gid, toid, toaddr, msg, p2pType)
}
func (t *udp) sendToPeer(gid, toid NodeID, toaddr *net.UDPAddr, msg string, p2pType int) error {
//	log.Debug("====  (t *udp) sendToPeer()  ====")
//	log.Warn("====  (t *udp) sendToPeer()  ====", "gid", gid)
	req := getGroupInfo(gid, p2pType)
//	log.Warn("====  (t *udp) sendToPeer()  ====", "req", req)
	if req == nil {
		return nil
	}
	errc := t.pending(toid, byte(Dcrm_groupInfoPacket), func(r interface{}) bool {
		return true
	})
//	log.Warn("====  (t *udp) sendToPeer()  ====", "sendtoAddress", toaddr)
	t.send(toaddr, byte(Dcrm_groupInfoPacket), req)
	err := <-errc
	return err
}
func (req *groupmessage) name() string { return "GROUPMSG/v4" }
func (req *groupmessage) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
//	log.Debug("====  (req *groupmessage) handle()  ====")
	fmt.Printf("====  (req *groupmessage) handle()  ====\n")
	if expired(req.Expiration) {
		return errExpired
	}
//	log.Debug("groupmessage", "req", req)
	nodes := make([]*Node, 0, bucketSize)
	for _, rn := range req.Nodes {
		n, err := t.nodeFromRPC(from, rn)
		if err != nil {
//			log.Trace("Invalid neighbor node received", "ip", rn.IP, "addr", from, "err", err)
			continue
		}
		nodes = append(nodes, n)
	}

//	log.Debug("group msg handle", "req.Nodes: ", nodes)
//	log.Warn("group msg handle", "req.Nodes: ", nodes)
	go callGroupEvent(req.ID, nodes, int(req.P2pType))
	return nil
}

//send msg
func (t *udp) sendMsgToPeer(toid NodeID, toaddr *net.UDPAddr, msg string) error {
//	log.Debug("====  (t *udp) sendMsgToPeer()  ====")
	errc := t.pending(toid, PeerMsgPacket, func(r interface{}) bool {
		return true
	})
	t.send(toaddr, PeerMsgPacket, &message{
		Msg:        msg,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	err := <-errc
	return err
}
func (req *message) name() string { return "MESSAGE/v4" }

func (req *message) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	fmt.Printf("====  (req *message) handle()  ====\n")
//	log.Debug("\n\n====  (req *message) handle()  ====")
//	log.Debug("req: %#v\n", req)
	if expired(req.Expiration) {
		return errExpired
	}
	go callPriKeyEvent(req.Msg)
	return nil
}

var groupcallback func(NodeID, interface{}, int)

func RegisterGroupCallback(callbackfunc func(NodeID, interface{}, int)) {
	groupcallback = callbackfunc
}

func callGroupEvent(gid NodeID, n []*Node, p2pType int) {
	fmt.Printf("callGroupEvent\n")
	groupcallback(gid, n, p2pType)
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
		return sdkcallback(e, fromID)
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

//for mongo
var updateOrderCachecallback func(interface{})

func RegisterUpdateOrderCacheCallback(callbackfunc func(interface{})) {
	updateOrderCachecallback = callbackfunc
}
func callUpdateOrderCacheEvent(e interface{}) {
	updateOrderCachecallback(e)
}

var sdkretcallback func(interface{}, string)

func RegisterSdkMsgRetCallback(sdkbackfunc func(interface{}, string)) {
	sdkretcallback = sdkbackfunc
}
func callsdkReturn(e interface{}, fromID string) {
	sdkretcallback(e, fromID)
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
        switch (p2pType) {
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

func setLocalIP(data interface{}) {
	if setlocaliptrue == true {
		return
	}
	localIP = data.(*pong).To.IP.String()
	setlocaliptrue = true
}

func GetLocalIP() string {
	return localIP
}

func GetLocalID() NodeID {
	//return Table4group.Self().ID
	return Table4group.self.ID
}

func SendToMyselfAndReturn(selfID, msg string, p2pType int) {
	msgc := callMsgEvent(msg, p2pType, selfID)
	//log.Debug("getmessage", "callEvent retmsg: ", msgc)
	msgr := <-msgc
	callCCReturn(msgr, p2pType, selfID)
}

