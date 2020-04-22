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

package layer2

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/fsn-dev/cryptoCoins/crypto"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	"github.com/fsn-dev/dcrm-walletService/p2p"
	"github.com/fsn-dev/dcrm-walletService/p2p/discover"
	"github.com/fsn-dev/dcrm-walletService/p2p/rlp"
)

func BroadcastToGroup(gid discover.NodeID, msg string, p2pType int, myself bool) (string, error) {
	cdLen := getCDLen(msg)
	fmt.Printf("%v ==== BroadcastToGroup() ====, gid: %v, msg: %v\n", common.CurrentTime(), gid, msg[:cdLen])
	group, msgCode := getGroupAndCode(gid, p2pType)
	if group == nil {
		e := fmt.Sprintf("BroadcastToGroup p2pType=%v is not exist", p2pType)
		fmt.Printf("==== BroadcastToGroup ====, p2pType: %v, is not exist\n", p2pType)
		return "", errors.New(e)
	}
	groupTmp := *group
	go p2pBroatcast(&groupTmp, msg, msgCode, myself)
	return "BroadcastToGroup send end", nil
}


func p2pBroatcast(group *discover.Group, msg string, msgCode int, myself bool) int {
	cdLen := getCDLen(msg)
	fmt.Printf("%v ==== p2pBroatcast() ====, group: %v, msg: %v\n", common.CurrentTime(), group, msg[:cdLen])
	if group == nil {
		fmt.Printf("==== p2pBroatcast() ====, group nil, msg: %v\n", msg[:cdLen])
		return 0
	}
	//pi := p2pServer.PeersInfo()
	//for _, pinfo := range pi {
	//	fmt.Printf("==== p2pBroatcast() ====, peers.Info: %v\n", pinfo)
	//}
	var ret int = 0
	//wg := &sync.WaitGroup{}
	//wg.Add(len(group.Nodes))
	for _, node := range group.Nodes {
		fmt.Printf("%v ==== p2pBroatcast() ====, nodeID: %v, len: %v, group: %v, msg: %v\n", common.CurrentTime(), node.ID, len(msg), group, msg[:cdLen])
		if selfid == node.ID {
			if myself == true {
				fmt.Printf("%v ==== p2pBroatcast() ====, myself, group: %v, msg: %v\n", common.CurrentTime(), group, msg[:cdLen])
				go callEvent(msg, node.ID.String())
			}
			//wg.Done()
			continue
		}
		//go func(node discover.RpcNode) {
		//	defer wg.Done()
			fmt.Printf("%v ==== p2pBroatcast() ====, call p2pSendMsg, group: %v, msg: %v\n", common.CurrentTime(), group, msg[:cdLen])
			//TODO, print node info from tab
			//discover.PrintBucketNodeInfo(node.ID)
			err := p2pSendMsg(node, uint64(msgCode), msg)
			if err != nil {
			}
		//}(node)
		time.Sleep(time.Duration(100) * time.Millisecond)
	}
	//wg.Wait()
	return ret
}

func p2pSendMsg(node discover.RpcNode, msgCode uint64, msg string) error {
	cdLen := getCDLen(msg)
	if msg == "" {
		fmt.Printf("==== p2pSendMsg() ==== p2pBroatcast, nodeID: %v, msg nil p2perror\n", node.ID)
		return errors.New("p2pSendMsg msg is nil")
	}
	fmt.Printf("%v ==== p2pSendMsg() ==== p2pBroatcast, node %v:%v %v, msg: %v\n", common.CurrentTime(), node.IP, node.UDP, node.ID, msg[:cdLen])
	err := errors.New("p2pSendMsg err")
	for {
		emitter.Lock()
		p := emitter.peers[node.ID]
		if p != nil {
			if err = p2p.Send(p.ws, msgCode, msg); err != nil {
				err = p2p.Send(p.ws, msgCode, msg)
			}
			if err == nil {
				emitter.Unlock()
				fmt.Printf("%v ==== p2pSendMsg() ==== p2pBroatcast, node %v:%v %v, msg: %v, send success\n", common.CurrentTime(), node.IP, node.UDP, node.ID, msg[:cdLen])
				return nil
			} else {
				fmt.Printf("%v ==== p2pSendMsg() ==== p2pBroatcast, node %v:%v %v, msg: %v, send fail p2perror\n", common.CurrentTime(), node.IP, node.UDP, node.ID, msg[:cdLen])
			}
		} else {
			fmt.Printf("%v ==== p2pSendMsg() ==== p2pBroatcast, nodeID: %v, peer not exist p2perror continue\n", common.CurrentTime(), node.ID)
		}
		emitter.Unlock()
	}
	return err
}

func getGroupAndCode(gid discover.NodeID, p2pType int) (*discover.Group, int) {
	msgCode := peerMsgCode
	var group *discover.Group = nil
	switch p2pType {
	case Sdkprotocol_type:
		discover.GroupSDK.Lock()
		defer discover.GroupSDK.Unlock()
		if SdkGroup != nil {
			_, group = getGroupSDK(gid)
			msgCode = Sdk_msgCode
		}
		break
	default:
		return nil, msgCode
	}
	return group, msgCode
}

func GetGroupSDKAll() []*discover.Group { //nooo
	var groupTmp []*discover.Group
	for _, g := range SdkGroup {
		if g.Type != "1+1+1" && g.Type != "1+2" {
			continue
		}
		groupTmp = append(groupTmp, g)
	}
	return groupTmp
}

func getGroupSDK(gid discover.NodeID) (discover.NodeID, *discover.Group) { //nooo
	for id, g := range SdkGroup {
		if g.Type != "1+1+1" && g.Type != "1+2" {
			continue
		}
		index := id.String()
		gf := gid.String()
		if index[:8] == gf[:8] {
			return id, g
		}
	}
	return discover.NodeID{}, nil
}

func init() {
	emitter = NewEmitter()
	discover.RegisterGroupCallback(recvGroupInfo)
}
func NewEmitter() *Emitter {
	return &Emitter{peers: make(map[discover.NodeID]*peer)}
}

// update p2p
func (e *Emitter) addPeer(p *p2p.Peer, ws p2p.MsgReadWriter) {
	e.Lock()
	defer e.Unlock()
	fmt.Printf("%v ==== addPeer() ====, id: %v\n", common.CurrentTime(), p.ID().String()[:8])
	discover.RemoveSequenceDoneRecv(p.ID().String())
	e.peers[p.ID()] = &peer{ws: ws, peer: p, peerInfo: &peerInfo{int(ProtocolVersion)}}
	//enode := fmt.Sprintf("enode://%v@%v", p.ID().String(), p.RemoteAddr())
	//node, _ := discover.ParseNode(enode)
	//p2pServer.AddTrustedPeer(node)
	discover.UpdateOnLine(p.ID(), true)
	discover.AddNodes(p.ID())
}

func (e *Emitter) removePeer(p *p2p.Peer) {
	e.Lock()
	defer e.Unlock()
	discover.UpdateOnLine(p.ID(), false)
	fmt.Printf("%v ==== removePeer() ====, id: %v\n", common.CurrentTime(), p.ID().String()[:8])
}

func HandlePeer(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	emitter.addPeer(peer, rw)
	for {
		msg, err := rw.ReadMsg()
		if err != nil {
			fmt.Printf("%v ==== handle() ====, %v, rw.ReadMsg err: %v\n", common.CurrentTime(), peer.ID(), err)
			emitter.removePeer(peer)
			return err
		}
		switch msg.Code {
		case peerMsgCode:
			var recv []byte
			err := rlp.Decode(msg.Payload, &recv)
			if err != nil {
				fmt.Printf("%v ==== handle() ==== p2pBroatcast, Err: decode msg err: %v, p2perror\n", common.CurrentTime(), err)
			} else {
				fmt.Printf("%v ==== handle() ==== p2pBroatcast, Recv callEvent(), peerMsgCode fromID: %v, msg: %v\n", common.CurrentTime(), peer.ID().String(), string(recv))
				go callEvent(string(recv), peer.ID().String())
			}
			break
		case Sdk_msgCode:
			var recv []byte
			err := rlp.Decode(msg.Payload, &recv)
			if err != nil {
				fmt.Printf("%v ==== handle() ==== p2pBroatcast, Err: decode sdk msg err: %v, p2perror\n", common.CurrentTime(), err)
			} else {
				cdLen := getCDLen(string(recv))
				fmt.Printf("%v ==== handle() ==== p2pBroatcast, Recv Sdk_callEvent(), Sdk_msgCode fromID: %v, msg: %v\n", common.CurrentTime(), peer.ID().String(), string(recv)[:cdLen])
				go Sdk_callEvent(string(recv), peer.ID().String())
			}
			break
		default:
			fmt.Println("unkown msg code")
			break
		}
	}
	return nil
}

// receive message form peers
func RegisterCallback(recvFunc func(interface{}, string)) {
	discover.RegisterCallback(recvFunc)
	callback = recvFunc
}
func callEvent(msg, fromID string) {
	fmt.Printf("%v ==== callEvent() ====, fromID: %v, msg: %v\n", common.CurrentTime(), fromID, msg)
	callback(msg, fromID)
}

func GetSelfID() string {
	return discover.GetLocalID().String()
}

func GetEnode() string {
	return discover.GetEnode()
}

func getGroup(gid discover.NodeID, p2pType int) (int, string) {
	var group *discover.Group
	switch p2pType {
	case Sdkprotocol_type:
		discover.GroupSDK.Lock()
		defer discover.GroupSDK.Unlock()
		if SdkGroup != nil {
			_, group = getGroupSDK(gid)
		}
		break
	default:
		return 0, ""
	}
	enode := ""
	count := 0
	if group == nil {
		return count, enode
	}
	for _, e := range group.Nodes {
		if enode != "" {
			enode += discover.Dcrmdelimiter
		}
		enode += fmt.Sprintf("enode://%v@%v:%v", e.ID, e.IP, e.UDP)
		count++
	}
	return count, enode
}

func recvGroupInfo(gid discover.NodeID, mode string, req interface{}, p2pType int, Type string) {
	fmt.Printf("%v ==== recvGroupInfo() ====, gid: %v, req: %v\n", common.CurrentTime(), gid, req)
	discover.GroupSDK.Lock()
	defer discover.GroupSDK.Unlock()
	var group *discover.Group
	switch p2pType {
	case Sdkprotocol_type:
		if SdkGroup[gid] != nil {
			//TODO: check IP,UDP
			_, groupTmp := getGroupSDK(gid)
			idcount := 0
			for _, enode := range req.([]*discover.Node) {
				node, _ := discover.ParseNode(enode.String())
				for _, n := range groupTmp.Nodes {
					if node.ID == n.ID {
						ipp1 := fmt.Sprintf("%v:%v", node.IP, node.UDP)
						ipp2 := fmt.Sprintf("%v:%v", n.IP, n.UDP)
						if ipp1 == ipp2 {
							idcount += 1
							break
						}
						break
					}
				}
			}
			if idcount == len(req.([]*discover.Node)) {
				fmt.Printf("==== recvGroupInfo() ====, gid: %v exist\n", gid)
				return
			}
		}
		groupTmp := discover.NewGroup()
		groupTmp.ID = gid
		groupTmp.Mode = mode
		groupTmp.P2pType = byte(p2pType)
		groupTmp.Type = Type
		SdkGroup[gid] = groupTmp
		group = groupTmp
		break
	}
	group.Nodes = make([]discover.RpcNode, 0)
	for _, enode := range req.([]*discover.Node) {
		node, _ := discover.ParseNode(enode.String())
		group.Nodes = append(group.Nodes, discover.RpcNode{ID: node.ID, IP: node.IP, UDP: node.UDP, TCP: node.UDP})
		if node.ID != selfid {
			go p2pServer.AddPeer(node)
			go p2pServer.AddTrustedPeer(node)
		}
	}
	fmt.Printf("%v ==== recvGroupInfo() ====, Store Group: %v\n", common.CurrentTime(), group)
	discover.StoreGroupToDb(group)
	discover.RecoverGroupAll(SdkGroup)
	discover.RecoverGroupAll(discover.SDK_groupList) // Group
}

func Broadcast(msg string) {
	if msg == "" || emitter == nil {
		return
	}
	emitter.Lock()
	defer emitter.Unlock()
	func() {
		for _, p := range emitter.peers {
			if err := p2p.Send(p.ws, peerMsgCode, msg); err != nil {
				continue
			}
		}
	}()
}

func SendMsgToPeer(enode string, msg string) error {
	return discover.SendMsgToPeer(enode,msg)
}

func SendToMyself(enode, msg string, p2pType int) error {
	node, _ := discover.ParseNode(enode)
	ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
	if _, err := discover.SendToGroupCC(node.ID, ipa, msg, p2pType); err == nil {
		return err
	}
	return nil
}

func SendToPeer(enode string, msg string) {
	node, _ := discover.ParseNode(enode)
	ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
	discover.SendMsgToNode(node.ID, ipa, msg)
}

func InitSelfNodeID(nodeid string) {
	sid, _ := HexID(nodeid)
	discover.SelfNodeID = sid
	fmt.Printf("==== InitSelfNodeID() ====, SelfNodeID: %v\n", sid)
}

func InitServer(nodeserv interface{}) {
	discover.GroupSDK.Lock()
	defer discover.GroupSDK.Unlock()
	selfid = discover.GetLocalID()
	p2pServer = nodeserv.(p2p.Server)
	discover.RecoverGroupAll(SdkGroup)
	for i, g := range SdkGroup {
		fmt.Printf("==== InitServer() ====, GetGroupFromDb, g: %v\n", g)
		for _, node := range g.Nodes {
			fmt.Printf("==== InitServer() ====, gid: %v, node: %v\n", i, node)
			if node.ID != selfid {
				discover.PingNode(node.ID, node.IP, int(node.UDP))
				en := discover.NewNode(node.ID, node.IP, node.UDP, node.TCP)
				go p2pServer.AddPeer(en)
				go p2pServer.AddTrustedPeer(en)
			}
		}
	}
	discover.RecoverGroupAll(discover.SDK_groupList) // Group
	discover.SDK_groupListChan<-1
}

func getCDLen(msg string) int {
	if len(msg) > 214 {
		return 214
	}
	return len(msg)
}

//-------- for broadcast --------
func broadWithMsg(msg string) bool {
	hash := msgHash(msg)
	ret := broadWithHash(hash)
	broadAddHash(hash)
	return ret
}

func broadAddMsg(msg string) {
	hash := msgHash(msg)
	broadAddHash(hash)
}

func broadWithHash(hash common.Hash) bool {
	knownHashMutex.Lock()
	defer knownHashMutex.Unlock()
	if !knownHash.Contains(hash) {
		return false
	}
	return true
}

func broadAddHash(hash common.Hash) {
	knownHashMutex.Lock()
	defer knownHashMutex.Unlock()
	if knownHash.Cardinality() >= maxKnownTxs {
		knownHash.Pop()
	}
	knownHash.Add(hash)
}

func msgHash(msg string) common.Hash {
	hashHex := crypto.Keccak256Hash([]byte(strings.ToLower(msg))).Hex()
	hash := common.HexToHash(hashHex)
	return hash
}
//-------- for broadcast end --------
