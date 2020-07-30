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
	"github.com/fsn-dev/dcrm-walletService/crypto/sha3"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	"github.com/fsn-dev/dcrm-walletService/p2p"
	"github.com/fsn-dev/dcrm-walletService/p2p/discover"
	"github.com/fsn-dev/dcrm-walletService/p2p/rlp"
)

func BroadcastToGroup(gid discover.NodeID, msg string, p2pType int, myself bool) (string, error) {
	cdLen := getCDLen(msg)
	common.Info("==== BroadcastToGroup() ====", "gid", gid, "msg", msg[:cdLen])
	xvcGroup, msgCode := getGroupAndCode(gid, p2pType)
	if xvcGroup == nil {
		e := fmt.Sprintf("BroadcastToGroup p2pType=%v is not exist", p2pType)
		common.Debug("==== BroadcastToGroup ====", "p2pType", p2pType, "is not exist", "")
		return "", errors.New(e)
	}
	groupTmp := *xvcGroup
	go p2pBroatcast(&groupTmp, msg, msgCode, myself)
	return "BroadcastToGroup send end", nil
}


func p2pBroatcast(dccpGroup *discover.Group, msg string, msgCode int, myself bool) int {
	cdLen := getCDLen(msg)
	common.Debug("==== p2pBroatcast() ====", "group", dccpGroup, "msg", msg[:cdLen])
	if dccpGroup == nil {
		common.Debug("==== p2pBroatcast() ====", "group", "nil", "msg", msg[:cdLen])
		return 0
	}
	pi := p2pServer.PeersInfo()
	for _, pinfo := range pi {
		common.Debug("==== p2pBroatcast() ====", "peers.Info", pinfo)
	}
	var ret int = 0
	//wg := &sync.WaitGroup{}
	//wg.Add(len(dccpGroup.Nodes))
	for _, node := range dccpGroup.Nodes {
		common.Info("==== p2pBroatcast() ====", "nodeID", node.ID, "len", len(msg), "group", dccpGroup, "msg", msg[:cdLen])
		if selfid == node.ID {
			if myself == true {
				common.Debug("==== p2pBroatcast() ====", "myself, group", dccpGroup, "msg", msg[:cdLen])
				go callEvent(msg, node.ID.String())
			}
			//wg.Done()
			continue
		}
		//go func(node discover.RpcNode) {
		//	defer wg.Done()
			common.Debug("==== p2pBroatcast() ====", "call p2pSendMsg, group", dccpGroup, "msg", msg[:cdLen])
			//TODO, print node info from tab
			discover.PrintBucketNodeInfo(node.ID)
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
		common.Debug("==== p2pSendMsg() ==== p2pBroatcast", "nodeID", node.ID, "msg", "nil p2perror")
		return errors.New("p2pSendMsg msg is nil")
	}
	common.Info("==== p2pSendMsg() ==== p2pBroatcast", "node.IP", node.IP, "node.UDP", node.UDP, "node.ID", node.ID, "msg", msg[:cdLen])
	err := errors.New("p2pSendMsg err")
	countSendFail := 0
	for {
		emitter.Lock()
		p := emitter.peers[node.ID]
		if p != nil {
			if err = p2p.Send(p.ws, msgCode, msg); err != nil {
				common.Info("==== p2pSendMsg() ==== p2pBroatcast", "node.IP", node.IP, "node.UDP", node.UDP, "node.ID", node.ID, "msg", msg[:cdLen], "send", "fail p2perror")
			} else {
				emitter.Unlock()
				common.Debug("==== p2pSendMsg() ==== p2pBroatcast", "node.IP", node.IP, "node.UDP", node.UDP, "node.ID", node.ID, "countSend", countSendFail, "msg", msg[:cdLen], "send", "success")
				return nil
			}
		} else {
			common.Debug("==== p2pSendMsg() ==== p2pBroatcast", "nodeID", node.ID, "peer", "not exist p2perror continue")
		}
		emitter.Unlock()

		countSendFail += 1
		if countSendFail >= 30 {
			common.Debug("==== p2pBroatcast p2pSendMsg() ====", "send to node.IP", node.IP, "node.UDP", node.UDP, "node.ID", node.ID, "msg", msg[:cdLen], "timeout p2perror", "")
			break
		}
		if countSendFail == 1 || countSendFail%5 == 0 {
			common.Debug("==== p2pBroatcast p2pSendMsg() ====", "send to node", node.ID, "countSend", "countSendFail")
		}
		time.Sleep(time.Duration(1) * time.Second)
	}
	return err
}

func getGroupAndCode(gid discover.NodeID, p2pType int) (*discover.Group, int) {
	msgCode := peerMsgCode
	var xvcGroup *discover.Group = nil
	switch p2pType {
	case Sdkprotocol_type:
		discover.GroupSDK.Lock()
		defer discover.GroupSDK.Unlock()
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
	common.Info("==== addPeer() ====", "id", p.ID().String()[:8])
	discover.RemoveSequenceDoneRecv(p.ID().String())
	e.peers[p.ID()] = &peer{ws: ws, peer: p, peerInfo: &peerInfo{int(ProtocolVersion)}, knownTxs: mapset.NewSet()}
	enode := fmt.Sprintf("enode://%v@%v", p.ID().String(), p.RemoteAddr())
	node, _ := discover.ParseNode(enode)
	p2pServer.AddTrustedPeer(node)
	discover.UpdateOnLine(p.ID(), true)
	discover.AddNodes(p.ID())
}

func (e *Emitter) removePeer(p *p2p.Peer) {
	e.Lock()
	defer e.Unlock()
	discover.UpdateOnLine(p.ID(), false)
	common.Info("==== removePeer() ====", "id", p.ID().String()[:8])
	return
	enode := fmt.Sprintf("enode://%v@%v", p.ID().String(), p.RemoteAddr())
	node, _ := discover.ParseNode(enode)
	p2pServer.RemoveTrustedPeer(node)
	discover.Remove(node)
	delete(e.peers, p.ID())
}

func HandlePeer(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	emitter.addPeer(peer, rw)
	//go discover.UpdateGroupSDKNode(peer.ID(), peer.RemoteAddr())
	for {
		msg, err := rw.ReadMsg()
		if err != nil {
			common.Debug("==== handle() ====", "peerID", peer.ID(), "w.ReadMsg err", err)
			rw = emitter.peers[peer.ID()].ws
			time.Sleep(time.Duration(1) * time.Second)
			continue
			//emitter.removePeer(peer)
			//return err
		}
		switch msg.Code {
		case peerMsgCode:
			var recv []byte
			err := rlp.Decode(msg.Payload, &recv)
			if err != nil {
				common.Info("==== handle() ==== p2pBroatcast", "Err: decode msg err", err)
			} else {
				common.Info("==== handle() ==== p2pBroatcast", "Recv callEvent(), peerMsgCode fromID", peer.ID().String(), "msg", string(recv))
				go callEvent(string(recv), peer.ID().String())
			}
			break
		case Sdk_msgCode:
			var recv []byte
			err := rlp.Decode(msg.Payload, &recv)
			if err != nil {
				common.Info("==== handle() ==== p2pBroatcast", "Err: decode sdk msg err", err)
			} else {
				cdLen := getCDLen(string(recv))
				common.Info("==== handle() ==== p2pBroatcast", "Recv Sdk_callEvent(), Sdk_msgCode fromID", peer.ID().String(), "msg", string(recv)[:cdLen])
				go Sdk_callEvent(string(recv), peer.ID().String())
			}
			break
		case Dcrm_msgCode:
			var recv []byte
			err := rlp.Decode(msg.Payload, &recv)
			if err != nil {
				common.Info("Err: decode msg", "err", err)
			} else {
				go Dcrm_callEvent(string(recv))
			}
			break
		case Xp_msgCode:
			var recv []byte
			err := rlp.Decode(msg.Payload, &recv)
			if err != nil {
				common.Debug("Err: decode msg", "err", err)
			} else {
				go Xp_callEvent(string(recv))
			}
			break
		default:
			common.Debug("unkown msg code", "", "")
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
	common.Debug("==== callEvent() ====", "fromID", fromID, "msg", msg)
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
		discover.GroupSDK.Lock()
		defer discover.GroupSDK.Unlock()
		if SdkGroup != nil {
			_, xvcGroup = getGroupSDK(gid)
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
		if enode != "" {
			enode += discover.Dcrmdelimiter
		}
		enode += fmt.Sprintf("enode://%v@%v:%v", e.ID, e.IP, e.UDP)
		count++
	}
	return count, enode
}

func recvGroupInfo(gid discover.NodeID, mode string, req interface{}, p2pType int, Type string) {
	common.Info("==== recvGroupInfo() ====", "gid", gid, "req", req)
	discover.GroupSDK.Lock()
	defer discover.GroupSDK.Unlock()
	var xvcGroup *discover.Group
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
				common.Debug("==== recvGroupInfo() ====", "exist gid", gid)
				return
			}
		}
		groupTmp := discover.NewGroup()
		groupTmp.ID = gid
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
		node, _ := discover.ParseNode(enode.String())
		xvcGroup.Nodes = append(xvcGroup.Nodes, discover.RpcNode{ID: node.ID, IP: node.IP, UDP: node.UDP, TCP: node.UDP})
		if node.ID != selfid {
			go p2pServer.AddPeer(node)
			go p2pServer.AddTrustedPeer(node)
		}
	}
	common.Debug("==== recvGroupInfo() ====", "Store Group", xvcGroup)
	discover.StoreGroupToDb(xvcGroup)
	discover.RecoverGroupAll(SdkGroup)
	if false {
		var testGroup  map[discover.NodeID]*discover.Group = make(map[discover.NodeID]*discover.Group)//TODO delete
		discover.RecoverGroupAll(testGroup)
		common.Debug("==== recvGroupInfo() ====", "Recov test Group", testGroup)
		for i, g := range testGroup {
			common.Debug("testGroup", "i", i, "g", g)
		}
	}
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
	node, _ := discover.ParseNode(enode)
	countSendFail := 0
	for {
		emitter.Lock()
		p := emitter.peers[node.ID]
		if p != nil {
			if err := p2p.Send(p.ws, peerMsgCode, msg); err != nil {
				common.Debug("==== SendMsgToPeer() ====", "send to node", node.ID, "msg", msg, "p2perror", err, "countSend", countSendFail)
			} else {
				common.Debug("==== SendMsgToPeer() ====", "send to node", node.ID, "msg", msg, "SUCCESS, countSend", countSendFail)
				emitter.Unlock()
				return nil
			}
		}
		emitter.Unlock()

		countSendFail += 1
		if countSendFail > 3000 {
			common.Debug("==== SendMsgToPeer() ====", "send to node", node.ID, "msg", msg, "timeout fail", "")
			break
		}
		if countSendFail <= 1 || countSendFail%100 == 0 {
			common.Debug("==== SendMsgToPeer() ====", "send to node", node.ID, "fail, countSend", countSendFail)
		}
		time.Sleep(time.Duration(100) * time.Millisecond)
	}
	retMsg := fmt.Sprintf("==== SendMsgToPeer() ====, send msg: %v to node: %v timeout err", msg, node.ID)
	return errors.New(retMsg)
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

// broadcastInGroup will propagate a batch of message to all peers which are not known to
// already have the given message.
func (e *Emitter) broadcastInGroup(tx Transaction) {
	e.Lock()
	defer e.Unlock()

	var txset = make(map[*peer][]Transaction)

	// Broadcast message to a batch of peers not knowing about it
	peers := e.peersWithoutTx(tx.hash(), true)
	for _, peer := range peers {
		txset[peer] = append(txset[peer], tx)
	}

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

func InitSelfNodeID(nodeid string) {
	sid, _ := HexID(nodeid)
	discover.SelfNodeID = sid
	common.Info("==== InitSelfNodeID() ====", "SelfNodeID", sid)
}

func InitP2pDir() {
	discover.InitP2pDir()
}

func InitServer(nodeserv interface{}) {
	discover.GroupSDK.Lock()
	defer discover.GroupSDK.Unlock()
	selfid = discover.GetLocalID()
	p2pServer = nodeserv.(p2p.Server)
	discover.RecoverGroupAll(SdkGroup)
	for i, g := range SdkGroup {
		common.Debug("==== InitServer() ====", "GetGroupFromDb, g", g)
		for _, node := range g.Nodes {
			common.Debug("==== InitServer() ====", "gid", i, "node", node)
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
