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
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	"github.com/fsn-dev/dcrm-walletService/crypto/sha3"
	"github.com/fsn-dev/dcrm-walletService/p2p"
	"github.com/fsn-dev/dcrm-walletService/p2p/discover"
	"github.com/fsn-dev/dcrm-walletService/p2p/rlp"
	"github.com/fsn-dev/dcrm-walletService/crypto"
)

func BroadcastToGroup(gid discover.NodeID, msg string, p2pType int, myself bool) (string, error) {
	emitter.Lock()

	xvcGroup, msgCode := getGroupAndCode(gid, p2pType)
	if xvcGroup == nil {
		e := fmt.Sprintf("BroadcastToGroup p2pType=%v is not exist", p2pType)
		return "", errors.New(e)
	}
	groupTmp := *xvcGroup
	emitter.Unlock()
	go p2pBroatcast(&groupTmp, msg, msgCode, myself)
	return "BroadcastToGroup send end", nil
}

func p2pBroatcast(dccpGroup *discover.Group, msg string, msgCode int, myself bool) int {
	fmt.Printf("==== p2pBroatcast() ====, group : %v, msg: %v\n", dccpGroup, msg)
	if dccpGroup == nil {
		fmt.Printf("==== p2pBroatcast() ====, group : nil, msg: %v error\n", dccpGroup, msg)
		return 0
	}
	var ret int = 0
	wg := &sync.WaitGroup{}
	wg.Add(len(dccpGroup.Nodes))
	for _, node := range dccpGroup.Nodes {
		fmt.Printf("  ==== p2pBroatcast() ====, group : %v, msg: %v, nodeID: %v\n", dccpGroup, msg, node.ID)
		if selfid == node.ID {
			if myself == true {
				fmt.Printf("    ==== p2pBroatcast() ====, group : %v, msg: %v, myself\n", dccpGroup, msg)
				go callEvent(msg, node.ID.String())
			}
			wg.Done()
			continue
		}
		go func(node discover.RpcNode) {
			defer wg.Done()
			fmt.Printf("    ==== p2pBroatcast() ====, group : %v, msg: %v, call p2pSendMsg\n", dccpGroup, msg)
			err := p2pSendMsg(node, uint64(msgCode), msg)
			if err != nil {
			}
		}(node)
	}
	wg.Wait()
	return ret
}

func p2pSendMsg(node discover.RpcNode, msgCode uint64, msg string) error {
	if msg == "" {
		fmt.Printf("==== p2pSendMsg() ====, send to node: %v, msg: nil error\n", node.ID)
		return errors.New("p2pSendMsg msg is nil")
	}
	fmt.Printf("==== p2pSendMsg() ====, send to node: %v, msg\n", node.ID, msg)
	err := errors.New("p2pSendMsg err")
	emitter.Lock()
	p := emitter.peers[node.ID]
	if p == nil {
		fmt.Printf("==== p2pSendMsg() ====, send to node: %v, peer not exist\n", node.ID)
		return errors.New("peer not exist")
	}
	emitter.Unlock()
	countSendFail := 0
	for {
		emitter.Lock()
		p = emitter.peers[node.ID]
		if p != nil {
			if err = p2p.Send(p.ws, msgCode, msg); err != nil {
			} else {
				emitter.Unlock()
				fmt.Printf("==== p2pBroatcast p2pSendMsg() ====, send to node: %v, msg: %v, SUCCESS, countSend : %v\n", node.ID, msg, countSendFail)
				return nil
			}
		}
		emitter.Unlock()

		countSendFail += 1
		if countSendFail > 3000 {
			fmt.Printf("==== p2pSendMsg() ====, send to node: %v fail\n", node.ID)
			fmt.Printf("==== p2pBroatcast p2pSendMsg() ====, send to node: %v, msg: %v timeout fail\n", node.ID, msg)
			break
		}
		if countSendFail <= 1 || countSendFail % 100 == 0 {
			fmt.Printf("==== p2pSendMsg() ====, send to node: %v fail, countSend : %v, continue\n", node.ID, countSendFail)
			fmt.Printf("==== p2pBroatcast p2pSendMsg() ====, send to node: %v fail, countSend : %v, continue\n", node.ID, countSendFail)
		}
		time.Sleep(time.Duration(100) * time.Millisecond)
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

func GetGroupSDKAll() ([]*discover.Group) {//nooo
	var groupTmp []*discover.Group
	for _, g := range SdkGroup {
		if g.Type != "1+1+1" && g.Type != "1+2" {
			continue
		}
		groupTmp = append(groupTmp, g)
	}
	return groupTmp
}

func getGroupSDK(gid discover.NodeID) (discover.NodeID, *discover.Group) {//nooo
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
	fmt.Printf("==== addPeer() ====\nid: %+v ...\n", p.ID().String()[:8])
	e.Lock()
	defer e.Unlock()
	discover.RemoveSequenceDoneRecv(p.ID().String())
	e.peers[p.ID()] = &peer{ws: ws, peer: p, peerInfo: &peerInfo{int(ProtocolVersion)}, knownTxs: mapset.NewSet()}
}

func HandlePeer(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	emitter.addPeer(peer, rw)
	for {
		msg, err := rw.ReadMsg()
		if err != nil {
			return err
		}
		switch msg.Code {
		case peerMsgCode:
			var recv []byte
			err := rlp.Decode(msg.Payload, &recv)
			if err != nil {
				fmt.Printf("Err: decode msg err %+v\n", err)
			} else {
				fmt.Printf("==== p2pBroatcast Recv callEvent() ====, peerMsgCode fromID: %v, msg: %v\n", peer.ID().String(), string(recv))
				go callEvent(string(recv), peer.ID().String())
			}
			break
		case Sdk_msgCode:
			var recv []byte
			err := rlp.Decode(msg.Payload, &recv)
			if err != nil {
				fmt.Printf("Err: decode msg err %+v\n", err)
			} else {
				fmt.Printf("==== p2pBroatcast Recv Sdk_callEvent() ====, Sdk_msgCode fromID: %v, msg: %v\n", peer.ID().String(), string(recv))
				go Sdk_callEvent(string(recv), peer.ID().String())
			}
			break
		case Dcrm_msgCode:
			var recv []byte
			err := rlp.Decode(msg.Payload, &recv)
			if err != nil {
				fmt.Printf("Err: decode msg err %+v\n", err)
			} else {
				go Dcrm_callEvent(string(recv))
			}
			break
		case Xp_msgCode:
			var recv []byte
			err := rlp.Decode(msg.Payload, &recv)
			if err != nil {
				fmt.Printf("Err: decode msg err %+v\n", err)
			} else {
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
	discover.GroupSDK.Lock()
	defer discover.GroupSDK.Unlock()
	var xvcGroup *discover.Group
	switch (p2pType) {
	case Sdkprotocol_type:
		if SdkGroup[gid] != nil {
			////TODO: check IP,UDP
			//_, groupTmp := getGroupSDK(gid)
			//flag := false
			//for _, enode := range req.([]*discover.Node) {
			//	node, _ := discover.ParseNode(enode.String())
			//	flag = false
			//	for _, n := range groupTmp.Nodes {
			//		if node.ID == n.ID {
			//			ip1 := fmt.Sprintf("%v", node.IP)
			//			ip2 := fmt.Sprintf("%v", n.IP)
			//			if ip1 == ip2 && node.UDP == node.UDP {
			//				flag = true
			//				break
			//			}
			//		}
			//	}
			//	if flag == false {
			//		break
			//	}
			//}
			//if flag != false {
				fmt.Printf("==== recvGroupInfo() ====, gid: %v exist\n", gid)
				return
			//}
		}
		keyString := ""
		for _, enode := range req.([]*discover.Node) {
			keyString = fmt.Sprintf("%v%v%v%v", keyString, enode.ID, enode.IP, enode.UDP)
		}
		key := crypto.Keccak256Hash([]byte(keyString)).Hex()
		if mode == "1+1+1" {
			if recvKey1 == key {
				return
			}
			recvKey1 = key
		} else {
			if recvKey2 == key {
				return
			}
			recvKey2 = key
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
		if node.ID != selfid && emitter.peers[node.ID] == nil {
			go p2pServer.AddPeer(node)
		}
	}
	fmt.Printf("==== recvGroupInfo() ====, Group: %v\n", xvcGroup)
	discover.StoreGroupToDb(xvcGroup)
	discover.RecoverGroupAll(SdkGroup)
	for i, g := range SdkGroup {
		fmt.Printf("SdkGroup, i: %v, g: %v\n", i, g)
	}
	discover.RecoverGroupAll(discover.SDK_groupList)// Group
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
			} else {
				fmt.Printf("==== SendMsgToPeer() ====, send to node: %v, msg: %v, SUCCESS, countSend : %v\n", node.ID, msg, countSendFail)
				emitter.Unlock()
				return nil
			}
		}
		emitter.Unlock()

		countSendFail += 1
		if countSendFail > 3000 {
			fmt.Printf("==== SendMsgToPeer() ====, send to node: %v fail\n", node.ID)
			fmt.Printf("==== SendMsgToPeer() ====, send to node: %v, msg: %v timeout fail\n", node.ID, msg)
			break
		}
		if countSendFail <= 1 || countSendFail % 100 == 0 {
			fmt.Printf("==== SendMsgToPeer() ====, send to node: %v fail, countSend : %v, continue\n", node.ID, countSendFail)
			fmt.Printf("==== SendMsgToPeer() ====, send to node: %v fail, countSend : %v, continue\n", node.ID, countSendFail)
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

func InitServer(nodeserv interface{}) {
	discover.GroupSDK.Lock()
	defer discover.GroupSDK.Unlock()
	selfid = discover.GetLocalID()
	p2pServer = nodeserv.(p2p.Server)
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

