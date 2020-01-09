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
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	"github.com/fsn-dev/dcrm-walletService/crypto/sha3"
	"github.com/fsn-dev/dcrm-walletService/p2p"
	"github.com/fsn-dev/dcrm-walletService/p2p/discover"
	"github.com/fsn-dev/dcrm-walletService/p2p/rlp"
)

func BroadcastToGroup(gid discover.NodeID, msg string, p2pType int, myself bool) (string, error) {
	emitter.Lock()
	defer emitter.Unlock()

	xvcGroup, msgCode := getGroupAndCode(gid, p2pType)
	if xvcGroup == nil {
		e := fmt.Sprintf("BroadcastToGroup p2pType=%v is not exist", p2pType)
		return "", errors.New(e)
	}
	failret := p2pBroatcast(xvcGroup, msg, msgCode, myself)
	if failret != 0 {
		e := fmt.Sprintf("BroadcastToGroup send failed nodecount=%v", failret)
		return "", errors.New(e)
	}
	return "BroadcastToGroup send Success", nil
}

func p2pBroatcast(dccpGroup *discover.Group, msg string, msgCode int, myself bool) int {
	fmt.Printf("==== p2pBroatcast() ====, group : %v\n", dccpGroup)
	if dccpGroup == nil {
		return 0
	}
	var ret int = 0
	for _, node := range dccpGroup.Nodes {
		fmt.Printf("==== p2pBroatcast() ====, send to node : %v\n", node)
		if selfid == node.ID {
			if myself == true {
				go callEvent(msg, node.ID.String())
			}
			continue
		}
		go p2pSendMsg(node, uint64(msgCode), msg)
	}
	return ret
}

func p2pSendMsg(node discover.RpcNode, msgCode uint64, msg string) error {
	if msg == "" {
		return errors.New("p2pSendMsg msg is nil")
	}
	fmt.Printf("==== p2pSendMsg() ====, send to node: %v\n", node)
	err := errors.New("p2pSendMsg err")
	p := emitter.peers[node.ID]
	if p == nil {
		fmt.Printf("==== p2pSendMsg() ====, send to node: %v, peer not exist\n", node)
		return errors.New("peer not exist")
	}
	countSendFail := 0
	for {
		errp := discover.PingNode(node.ID, node.IP, int(node.UDP))
		if errp == nil {
			if err = p2p.Send(p.ws, msgCode, msg); err != nil {
			} else {
				//tx := Transaction{Payload: []byte(msg)}
				//p.knownTxs.Add(tx.hash())
				fmt.Printf("==== p2pSendMsg() ====, send to node: %v SUCCESS, countSend : %v\n", node.ID, countSendFail)
				return nil
			}
		}
		countSendFail += 1
		if countSendFail > 100 {
			break
		}
		if countSendFail % 10 == 0 {
			fmt.Printf("==== p2pSendMsg() ====, send to node: %v fail, countSend : %v, continue\n", node.ID, countSendFail)
		}
		time.Sleep(time.Duration(300) * time.Millisecond)
	}
	fmt.Printf("==== p2pSendMsg() ====, send to node: %v fail, countSendFail : %v timeout\n", node.ID, countSendFail)
	return err
}

func getGroupAndCode(gid discover.NodeID, p2pType int) (*discover.Group, int) {
	msgCode := peerMsgCode
	var xvcGroup *discover.Group = nil
	switch p2pType {
	case Sdkprotocol_type:
		if SdkGroup != nil {
			_, xvcGroup = getGroupSDK(gid)
			msgCode = Sdk_msgCode
		}
		break
	case DcrmProtocol_type:
		if dccpGroup != nil {
			xvcGroup = dccpGroup
			msgCode = Dcrm_msgCode
		}
		break
	case Xprotocol_type:
		if xpGroup != nil {
			xvcGroup = xpGroup
			msgCode = Xp_msgCode
		}
		break
	default:
		return nil, msgCode
	}
	return xvcGroup, msgCode
}

func getGroupSDK(gid discover.NodeID) (discover.NodeID, *discover.Group) {
	sdkGroupLock.Lock()
	sdkGroupLock.Unlock()
	for id, g := range SdkGroup {
		if g.Type != "1+1+1" && g.Type != "1+2" {
			continue
		}
		index := id.String()
		gf := gid.String()
	//	log.Debug("getGroupSDK", "id", id, "gid", gid)
		if index[:8] == gf[:8] {
			return id, g
		}
	}
	return discover.NodeID{}, nil
}

func init() {

	emitter = NewEmitter()
	discover.RegisterGroupCallback(recvGroupInfo)
	//TODO callback
	//RegisterRecvCallback(recvPrivkeyInfo)
}
func NewEmitter() *Emitter {
	//fmt.Println("========  NewEmitter()  ========")
	return &Emitter{peers: make(map[discover.NodeID]*peer)}
}

// update p2p
func (e *Emitter) addPeer(p *p2p.Peer, ws p2p.MsgReadWriter) {
	fmt.Printf("==== addPeer() ====\nid: %+v ...\n", p.ID().String()[:8])
	//log.Debug("addPeer", "p: ", p, "ws: ", ws)
	e.Lock()
	defer e.Unlock()
	e.peers[p.ID()] = &peer{ws: ws, peer: p, peerInfo: &peerInfo{int(ProtocolVersion)}, knownTxs: mapset.NewSet()}
}

func HandlePeer(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	//log.Debug("==== HandlePeer() ====\n")
	emitter.addPeer(peer, rw)
	//log.Debug("emitter", "emitter.peers: ", emitter.peers)
	for {
		msg, err := rw.ReadMsg()
		//log.Debug("HandlePeer", "ReadMsg", msg)
		if err != nil {
			return err
		}
		//log.Debug("HandlePeer", "receive Msgs msg.Payload", msg.Payload)
		switch msg.Code {
		case peerMsgCode:
			var recv []byte
			err := rlp.Decode(msg.Payload, &recv)
			//log.Debug("Decode", "rlp.Decode", recv)
			if err != nil {
				fmt.Printf("Err: decode msg err %+v\n", err)
			} else {
			//	log.Debug("HandlePeer", "callback(msg): ", recv)
				go callEvent(string(recv), peer.ID().String())
			}
			break
		case Sdk_msgCode:
			var recv []byte
			err := rlp.Decode(msg.Payload, &recv)
			//log.Debug("Decode", "rlp.Decode", recv)
			if err != nil {
				fmt.Printf("Err: decode msg err %+v\n", err)
			} else {
			//	log.Debug("HandlePeer", "callback(msg): ", recv)
				go Sdk_callEvent(string(recv), peer.ID().String())
			}
			break
		case Dcrm_msgCode:
			var recv []byte
			err := rlp.Decode(msg.Payload, &recv)
			//log.Debug("Decode", "rlp.Decode", recv)
			if err != nil {
				fmt.Printf("Err: decode msg err %+v\n", err)
			} else {
			//	log.Debug("HandlePeer", "callback(msg): ", recv)
				go Dcrm_callEvent(string(recv))
			}
			break
		case Xp_msgCode:
			var recv []byte
			err := rlp.Decode(msg.Payload, &recv)
		//	log.Debug("Decode", "rlp.Decode", recv)
			if err != nil {
				fmt.Printf("Err: decode msg err %+v\n", err)
			} else {
		//		log.Debug("HandlePeer", "callback(msg): ", recv)
				go Xp_callEvent(string(recv))
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
	callback = recvFunc
}
func callEvent(msg, fromID string) {
	fmt.Printf("callEvent\n")
	callback(msg, fromID)
}

func GetSelfID() string {
	return discover.GetLocalID().String()
}

func GetEnode() string {
	return discover.GetEnode()
}

func getGroup(gid discover.NodeID, p2pType int) (int, string) {
	var xvcGroup *discover.Group
	switch p2pType {
	case Sdkprotocol_type:
		if SdkGroup != nil {
			_, xvcGroup = getGroupSDK(gid)
		//	log.Debug("BroadcastToGroup", "gid", gid, "xvcGroup", gid, xvcGroup)
		}
		break
	case DcrmProtocol_type:
		if dccpGroup == nil {
			return 0, ""
		}
		xvcGroup = dccpGroup
		break
	case Xprotocol_type:
		if xpGroup == nil {
			return 0, ""
		}
		xvcGroup = xpGroup
		break
	default:
		return 0, ""
	}
	enode := ""
	count := 0
	if xvcGroup == nil {
		return count, enode
	}
	for _, e := range xvcGroup.Nodes {
		//log.Debug("GetGroup", "i", i, "e", e)
		if enode != "" {
			enode += discover.Dcrmdelimiter
		}
		enode += fmt.Sprintf("enode://%v@%v:%v", e.ID, e.IP, e.UDP)
		count++
	}
	//log.Debug("group", "count = ", count, "enode = ", enode)
	//TODO
	return count, enode
}

func recvGroupInfo(gid discover.NodeID, mode string, req interface{}, p2pType int, Type string) {
	sdkGroupLock.Lock()
	sdkGroupLock.Unlock()
	//log.Debug("==== recvGroupInfo() ====", "gid", gid, "req", req)
	//fmt.Printf("==== recvGroupInfo() ====, gid: %v, req: %v\n", gid, req)
	//log.Debug("recvGroupInfo", "local ID: ", selfid)
	var xvcGroup *discover.Group
	switch (p2pType) {
	case Sdkprotocol_type:
		//_, groupTmp := getGroupSDK(gid)
		//if groupTmp != nil {
		//	return
		//	//delete(SdkGroup, id)
		//}
		groupTmp := discover.NewGroup()
		groupTmp.ID = gid
		//groupTmp.Gname = gname
		groupTmp.Mode = mode
		groupTmp.P2pType = byte(p2pType)
		groupTmp.Type = Type
		SdkGroup[gid] = groupTmp
		xvcGroup = groupTmp
		break
	case DcrmProtocol_type:
		dccpGroup = discover.NewGroup()
		xvcGroup = dccpGroup
		break
	case Xprotocol_type:
		xpGroup = discover.NewGroup()
		xvcGroup = xpGroup
		break
	default:
		return
	}
	updateGroupNodesNumber(len(req.([]*discover.Node)), p2pType)
	xvcGroup.Nodes = make([]discover.RpcNode, 0)
	for _, enode := range req.([]*discover.Node) {
	//	log.Debug("recvGroupInfo", "i: ", i, "e: ", enode)
		node, _ := discover.ParseNode(enode.String())
		xvcGroup.Nodes = append(xvcGroup.Nodes, discover.RpcNode{ID: node.ID, IP: node.IP, UDP: node.UDP, TCP: node.UDP})
		if node.ID != selfid {
			go p2pServer.AddPeer(node)
		}
	//	log.Debug("recvGroupInfo", "xvcGroup.group", xvcGroup.group[node.ID.String()])
	}
	fmt.Printf("==== recvGroupInfo() ====, Group: %v\n", xvcGroup)
	discover.StoreGroupToDb(xvcGroup)
	discover.RecoverGroupAll(SdkGroup)
	for i, g := range SdkGroup {
		fmt.Printf("SdkGroup, i: %v, g: %v\n", i, g)
	}
	discover.RecoverGroupAll(discover.SDK_groupList)// Group
	//fmt.Printf("==== recvGroupInfo() ====, getGroupInfo g = %v\n", g)

//	log.Debug("recvGroupInfo", "xvcGroup", xvcGroup)
//	log.Debug("recvGroupInfo", "Group", p2pType, "enodes", xvcGroup)
}

func Broadcast(msg string) {
//	log.Debug("==== Broadcast() ====\n")
	if msg == "" || emitter == nil {
		return
	}
//	log.Debug("Broadcast", "sendMsg", msg)
	emitter.Lock()
	defer emitter.Unlock()
	func() {
//		log.Debug("peer", "emitter", emitter)
		for _, p := range emitter.peers {
//			log.Debug("Broadcast", "to , p", p, "msg", p, msg)
//			log.Debug("Broadcast", "p.ws", p.ws)
			if err := p2p.Send(p.ws, peerMsgCode, msg); err != nil {
//				log.Error("Broadcast", "p2p.Send err", err, "peer id", p.peer.ID())
				continue
			}
		}
	}()
}

func SendMsgToPeer(enode string, msg string) error {
//	log.Debug("==== SendMsgToPeer() ====\n")
	node, _ := discover.ParseNode(enode)
	p := emitter.peers[node.ID]
	if p == nil {
//		log.Debug("Failed: SendToPeer peers mismatch peerID", "peerID", node.ID)
		return errors.New("peerID mismatch!")
	}
	if err := p2p.Send(p.ws, peerMsgCode, msg); err != nil {
//		log.Debug("Failed: SendToPeer", "peerID", node.ID, "msg", msg)
		return err
	}
//	log.Debug("Success: SendToPeer", "peerID", node.ID, "msg", msg)
	return nil
}

//func SendMsg(msg string) {
//	Dcrmrotocol_broadcastToGroup(msg)
//}

func SendToMyself(enode, msg string, p2pType int) error {
//	log.Debug("==== SendMsgToPeer() ====\n")
	node, _ := discover.ParseNode(enode)
	ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
	if _, err := discover.SendToGroupCC(node.ID, ipa, msg, p2pType); err == nil {
//		log.Debug("Success: SendToMyself", "peerID", node.ID, "msg", msg, "ret", ret)
		return err
	}
//	log.Debug("Failed: SendToMyself", "peerID", node.ID, "msg", msg)
	return nil
}

func SendToPeer(enode string, msg string) {
//	log.Debug("==== DCCP SendToPeer ====\n")
//	log.Debug("SendToPeer", "enode: ", enode, "msg: ", msg)
	node, _ := discover.ParseNode(enode)
	//log.Debug("node.id: %+v, node.IP: %+v, node.UDP: %+v\n", node.ID, node.IP, node.UDP)
	ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
	discover.SendMsgToNode(node.ID, ipa, msg)
}

// broadcastInGroup will propagate a batch of message to all peers which are not known to
// already have the given message.
func (e *Emitter) broadcastInGroup(tx Transaction) {
	e.Lock()
	defer e.Unlock()

	var txset = make(map[*peer][]Transaction)

	// Broadcast message to a batch of peers not knowing about it
	peers := e.peersWithoutTx(tx.hash(), true)
//	log.Debug("broadcastInGroup", "peers", peers)
	for _, peer := range peers {
		txset[peer] = append(txset[peer], tx)
	}
//	log.Trace("Broadcast transaction", "hash", tx.hash(), "recipients", len(peers))

	for peer, txs := range txset {
		peer.sendTx(txs)
	}
}

// group: true, in group
//        false, peers
func (e *Emitter) peersWithoutTx(hash common.Hash, group bool) []*peer {
	list := make([]*peer, 0, len(e.peers))
	if group == true {
		if dccpGroup == nil || len(dccpGroup.Nodes) == 0 {
			return list
		}
		for _, n := range dccpGroup.Nodes {
			if n.ID == selfid {
				continue
			}
//			log.Debug("peersWithoutTx", "emitter", e)
//			log.Debug("peersWithoutTx", "g.id", g.id)
			p := e.peers[n.ID]
			if p != nil && !p.knownTxs.Contains(hash) {
				list = append(list, p)
			}
		}
	} else {
		for _, p := range e.peers {
			if !p.knownTxs.Contains(hash) {
				list = append(list, p)
			}
		}
	}
	return list
}

// SendTransactions sends transactions to the peer and includes the hashes
// in its transaction hash set for future reference.
func (p *peer) sendTx(txs []Transaction) {
	for _, tx := range txs {
		if err := p2p.Send(p.ws, Dcrm_msgCode, string(tx.Payload)); err != nil {
			if len(p.queuedTxs) >= maxKnownTxs {
				p.knownTxs.Pop()
			}
			p.knownTxs.Add(tx.hash())
		}
	}
}

// Hash hashes the RLP encoding of tx.
// It uniquely identifies the transaction.
func (tx *Transaction) hash() common.Hash {
	if hash := tx.Hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	v := rlpHash(tx.Payload)
	tx.Hash.Store(v)
	return v
}

func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}

func updateGroupNodesNumber(number, p2pType int) {
	discover.UpdateGroupNodesNumber(number, p2pType)
}

func InitServer(nodeserv interface{}) {
	selfid = discover.GetLocalID()
	p2pServer = nodeserv.(p2p.Server)
	sdkGroupLock.Lock()
	sdkGroupLock.Unlock()
	discover.RecoverGroupAll(SdkGroup)
	for i, g := range SdkGroup {
		for _, node := range g.Nodes {
			if node.ID != selfid {
				discover.PingNode(node.ID, node.IP, int(node.UDP))
				en := discover.NewNode(node.ID, node.IP, node.UDP, node.TCP)
				go p2pServer.AddPeer(en)
			}
		}
		fmt.Printf("discover.GetGroupFromDb, gid: %v, g: %v\n", i, g)
	}
	discover.RecoverGroupAll(discover.SDK_groupList)// Group
}

