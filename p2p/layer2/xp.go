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
	"fmt"
	"net"

	"github.com/anyswap/Anyswap-MPCNode/p2p"
	"github.com/anyswap/Anyswap-MPCNode/p2p/discover"
	"github.com/anyswap/Anyswap-MPCNode/rpc"
)

// txs start
func Xprotocol_sendToGroupOneNode(msg string) (string, error) {
	return discover.SendToGroup(discover.NodeID{}, msg, false, Xprotocol_type, nil)
}

// broadcast
// to group's nodes
func Xprotocol_broadcastInGroupOthers(msg string) {
	BroadcastToGroup(discover.NodeID{}, msg, Xprotocol_type, false)
}

func Xprotocol_broadcastInGroupAll(msg string) {
	BroadcastToGroup(discover.NodeID{}, msg, Xprotocol_type, true)
}

// unicast
// to anyone
func Xprotocol_sendMsgToNode(toid discover.NodeID, toaddr *net.UDPAddr, msg string) error {
	fmt.Printf("==== SendMsgToNode() ====\n")
	return discover.SendMsgToNode(toid, toaddr, msg)
}

// to peers
func Xprotocol_sendMsgToPeer(enode string, msg string) error {
	return SendMsgToPeer(enode, msg)
}

// receive message form peers
func Xprotocol_registerRecvCallback(recvXpFunc func(interface{})) {
	Xp_callback = recvXpFunc
}
func Xp_callEvent(msg string) {
	Xp_callback(msg)
}

// receive message from xp
func Xprotocol_registerMsgRecvCallback(xpcallback func(interface{}) <-chan string) {
	discover.RegisterXpMsgCallback(xpcallback)
}

// receive message from dccp result
func Xprotocol_registerMsgRetCallback(xpcallback func(interface{})) {
	discover.RegisterXpMsgRetCallback(xpcallback)
}

func Xprotocol_getGroup() (int, string) {
	return getGroup(discover.NodeID{}, Xprotocol_type)
}

// p2p layer 2
// New creates a Whisper client ready to communicate through the Ethereum P2P network.
func XpNew(cfg *Config) *Xp {
	fmt.Printf("====  xp New  ====\n")
	xp := &Xp{
		peers: make(map[discover.NodeID]*peer),
		quit:  make(chan struct{}),
		cfg:   cfg,
	}

	// p2p dccp sub protocol handler
	xp.protocol = p2p.Protocol{
		Name:    Xp_ProtocolName,
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

	return xp
}

func Xprotocol_getEnodes() (int, string) {
	return Xprotocol_getGroup()
}

// Protocols returns the whisper sub-protocols ran by this particular client.
func (xp *Xp) Protocols() []p2p.Protocol {
	return []p2p.Protocol{xp.protocol}
}

// other
// Start implements node.Service, starting the background data propagation thread
// of the Whisper protocol.
func (xp *Xp) Start(server *p2p.Server) error {
	return nil
}

// Stop implements node.Service, stopping the background data propagation thread
// of the Whisper protocol.
func (xp *Xp) Stop() error {
	return nil
}

// APIs returns the RPC descriptors the Whisper implementation offers
func (xp *Xp) APIs() []rpc.API {
	return []rpc.API{
		{
			Namespace: Xp_ProtocolName,
			Version:   ProtocolVersionStr,
			Service:   &XpAPI{xp: xp},
			Public:    true,
		},
	}
}

func (xp *XpAPI) Version(ctx context.Context) (v string) {
	return ProtocolVersionStr
}
func (xp *XpAPI) Peers(ctx context.Context) []*p2p.PeerInfo {
	var ps []*p2p.PeerInfo
	for _, p := range xp.xp.peers {
		ps = append(ps, p.peer.Info())
	}

	return ps
}
