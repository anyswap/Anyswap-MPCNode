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
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/fsn-dev/cryptoCoins/crypto"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	"github.com/fsn-dev/dcrm-walletService/p2p"
	"github.com/fsn-dev/dcrm-walletService/p2p/discover"
	"github.com/fsn-dev/dcrm-walletService/p2p/rlp"
	"github.com/fsn-dev/dcrm-walletService/rpc"
)

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

func recvGroupInfo(gid discover.NodeID, req interface{}, p2pType int, Type string) {
	fmt.Printf("%v ==== recvGroupInfo() ====, gid: %v, req: %v\n", common.CurrentTime(), gid, req)
	discover.GroupSDK.Lock()
	defer discover.GroupSDK.Unlock()
	var group *discover.Group
	switch p2pType {
	case Sdkprotocol_type:
		if discover.SDK_groupList[gid] != nil {
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
		groupTmp.P2pType = byte(p2pType)
		groupTmp.Type = Type
		discover.SDK_groupList[gid] = groupTmp
		group = groupTmp
		break
	default:
		fmt.Printf("%v ==== recvGroupInfo() ====, p2pType: %v not support\n", common.CurrentTime(), p2pType)
		return
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
	discover.RecoverGroupAll(discover.SDK_groupList) // Group
}

func InitIPPort(port int) {
	discover.InitIP(getLocalIP(), uint16(port))
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
	discover.RecoverGroupAll(discover.SDK_groupList) // Group
	for i, g := range discover.SDK_groupList {
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
	discover.SDK_groupListChan<-1
}

func (dcrm *DcrmAPI) Version(ctx context.Context) (v string) {
	return ProtocolVersionStr
}
func (dcrm *DcrmAPI) Peers(ctx context.Context) []*p2p.PeerInfo {
	var ps []*p2p.PeerInfo
	for _, p := range dcrm.dcrm.peers {
		ps = append(ps, p.peer.Info())
	}

	return ps
}

// Protocols returns the whisper sub-protocols ran by this particular client.
func (dcrm *Dcrm) Protocols() []p2p.Protocol {
	return []p2p.Protocol{dcrm.protocol}
}

// p2p layer 2
// New creates a Whisper client ready to communicate through the Ethereum P2P network.
func DcrmNew(cfg *Config) *Dcrm {
	dcrm := &Dcrm{
		peers: make(map[discover.NodeID]*peer),
		quit:  make(chan struct{}),
		cfg:   cfg,
	}

	// p2p dcrm sub protocol handler
	dcrm.protocol = p2p.Protocol{
		Name:    ProtocolName,
		Version: ProtocolVersion,
		Length:  NumberOfMessageCodes,
		Run:     HandlePeer,
		NodeInfo: func() interface{} {
			return map[string]interface{}{
				"version": ProtocolVersionStr,
			}
		},
		PeerInfo: func(id discover.NodeID) interface{} {
			if p := emitter.peers[id]; p != nil {
				return p.peerInfo
			}
			return nil
		},
	}

	return dcrm
}

// other
// Start implements node.Service, starting the background data propagation thread
// of the Whisper protocol.
func (dcrm *Dcrm) Start(server *p2p.Server) error {
	return nil
}

// Stop implements node.Service, stopping the background data propagation thread
// of the Whisper protocol.
func (dcrm *Dcrm) Stop() error {
	return nil
}

// APIs returns the RPC descriptors the Whisper implementation offers
func (dcrm *Dcrm) APIs() []rpc.API {
	return []rpc.API{
		{
			Namespace: ProtocolName,
			Version:   ProtocolVersionStr,
			Service:   &DcrmAPI{dcrm: dcrm},
			Public:    true,
		},
	}
}

// 1 + 1 + 1
func CreateSDKGroup(enodes []string) (string, int, string) {
	count := len(enodes)
	sort.Sort(sort.StringSlice(enodes))
	enode := []*discover.Node{}
	id := []byte("")
	for _, un := range enodes {
		fmt.Printf("for enode: %v\n", un)
		node, err := discover.ParseNode(un)
		if err != nil {
			fmt.Printf("CreateSDKGroup, parse err: %v\n", un)
			return "", 0, "enode wrong format"
		}
		fmt.Printf("for selfid: %v, node.ID: %v\n", selfid, node.ID)
		n := fmt.Sprintf("%v", node.ID)
		fmt.Printf("CreateSDKGroup, n: %v\n", n)
		if len(id) == 0 {
			id = crypto.Keccak512([]byte(node.ID.String()))
		} else {
			id = crypto.Keccak512(id, []byte(node.ID.String()))
		}
		enode = append(enode, node)
	}
	gid, err := discover.BytesID(id)
	fmt.Printf("CreateSDKGroup, gid <- id: %v, err: %v\n", gid, err)
	discover.GroupSDK.Lock()
	exist := false
	for i := range discover.SDK_groupList {
		if i == gid {
			exist = true
			break
		}
	}
	discover.GroupSDK.Unlock()
	retErr := discover.StartCreateSDKGroup(gid, enode, "1+1+1", exist)
	return gid.String(), count, retErr
}

func GetGroupList() map[discover.NodeID]*discover.Group {
	discover.GroupSDK.Lock()
	defer discover.GroupSDK.Unlock()
	return discover.SDK_groupList
}

