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
	"net"
	"time"
	"fmt"

	"github.com/fsn-dev/dcrm-sdk/p2p"
	"github.com/fsn-dev/dcrm-sdk/p2p/discover"
	"github.com/fsn-dev/dcrm-sdk/rpc"
)

// txs start
func DcrmProtocol_sendToGroupOneNode(msg string) string {
	return discover.SendToGroup(discover.NodeID{}, msg, false, DcrmProtocol_type)
}

// broadcast
// to group's nodes
func DcrmProtocol_broadcastInGroupAll(msg string) { // within self
	BroadcastToGroup(discover.NodeID{}, msg, DcrmProtocol_type, true)
}

func DcrmProtocol_broadcastInGroupOthers(msg string) { // without self
	BroadcastToGroup(discover.NodeID{}, msg, DcrmProtocol_type, false)
}

// unicast
// to anyone
func DcrmProtocol_sendMsgToNode(toid discover.NodeID, toaddr *net.UDPAddr, msg string) error {
	fmt.Printf("==== SendMsgToNode() ====\n")
	return discover.SendMsgToNode(toid, toaddr, msg)
}

// to peers
func DcrmProtocol_sendMsgToPeer(enode string, msg string) error {
	return SendMsgToPeer(enode, msg)
}

// callback
// receive private key
func DcrmProtocol_registerPriKeyCallback(recvPrivkeyFunc func(interface{})) {
	discover.RegisterPriKeyCallback(recvPrivkeyFunc)
}

func Sdk_callEvent(msg string, fromID string) {
	Sdk_callback(msg, fromID)
}

// receive message form peers
func DcrmProtocol_registerRecvCallback(recvDcrmFunc func(interface{}) <-chan string) {
	Dcrm_callback = recvDcrmFunc
}
func Dcrm_callEvent(msg string) {
	Dcrm_callback(msg)
}

// receive message from dccp
func DcrmProtocol_registerMsgRecvCallback(dcrmcallback func(interface{}) <-chan string) {
	discover.RegisterDcrmMsgCallback(dcrmcallback)
}

// receive message from dccp result
func DcrmProtocol_registerMsgRetCallback(dcrmcallback func(interface{})) {
	discover.RegisterDcrmMsgRetCallback(dcrmcallback)
}

// get info
func DcrmProtocol_getGroup() (int, string) {
	return getGroup(discover.NodeID{}, DcrmProtocol_type)
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
	fmt.Printf("====  dcrm New  ====\n")
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

//TODO callback
func recvPrivkeyInfo(msg interface{}) {
	fmt.Printf("==== recvPrivkeyInfo() ====\n")
	fmt.Println("recvprikey,msg = ", msg)
	//TODO
	//store privatekey slice
	time.Sleep(time.Duration(10) * time.Second)
	DcrmProtocol_broadcastInGroupOthers("aaaa")
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

func DcrmProtocol_getEnodes() (int, string) {
	return getGroup(discover.NodeID{}, DcrmProtocol_type)
}

func RegisterUpdateOrderCacheCallback(recvDcrmFunc func(interface{})) {
	discover.RegisterUpdateOrderCacheCallback(recvDcrmFunc)
}



//=============================== DCRM =================================
func SendMsg(msg string) {
	//BroadcastToGroup(discover.NodeID{}, msg, DcrmProtocol_type)
	DcrmProtocol_broadcastInGroupOthers(msg)
}

func SendToDcrmGroupAllNodes(msg string) string {
	return discover.SendToGroup(discover.NodeID{}, msg, true, DcrmProtocol_type)
}

func RegisterRecvCallback(recvPrivkeyFunc func(interface{})) {
	discover.RegisterPriKeyCallback(recvPrivkeyFunc)
}

func RegisterDcrmCallback(dcrmcallback func(interface{}) <-chan string) {
	discover.RegisterDcrmMsgCallback(dcrmcallback)
	DcrmProtocol_registerRecvCallback(dcrmcallback)
}

func RegisterDcrmRetCallback(dcrmcallback func(interface{})) {
	discover.RegisterDcrmMsgRetCallback(dcrmcallback)
}

func GetGroup() (int, string) {
	return DcrmProtocol_getGroup()
}

func GetEnodes() (int, string) {
	return GetGroup()
}

func RegisterSendCallback(callbackfunc func(interface{})) {
	discover.RegisterSendCallback(callbackfunc)
}

func ParseNodeID(enode string) string {
	node, _ := discover.ParseNode(enode)
	return node.ID.String()
}

//================   API   SDK    =====================
func SdkProtocol_sendToGroupOneNode(gID, msg string) string {
	gid, _ := discover.HexID(gID)
	return discover.SendToGroup(gid, msg, false, Sdkprotocol_type)
}

func SdkProtocol_SendToGroupAllNodes(gID, msg string) string {
	gid, _ := discover.HexID(gID)
	return discover.SendToGroup(gid, msg, true, Sdkprotocol_type)
}

func SdkProtocol_broadcastInGroupOthers(gID, msg string) { // without self
	gid, _ := discover.HexID(gID)
	BroadcastToGroup(gid, msg, Sdkprotocol_type, false)
}

func SdkProtocol_broadcastInGroupAll(gID, msg string) { // within self
	gid, _ := discover.HexID(gID)
	BroadcastToGroup(gid, msg, Sdkprotocol_type, true)
}

func SdkProtocol_getGroup(gID string) (int, string) {
	gid, _ := discover.HexID(gID)
	return getGroup(gid, Sdkprotocol_type)
}


//  ---------------------   API  callback   ----------------------
// recv from broadcastInGroup...
func SdkProtocol_registerBroadcastInGroupCallback(recvSdkFunc func(interface{}, string)) {
	Sdk_callback = recvSdkFunc
}
// recv from sendToGroup...
func SdkProtocol_registerSendToGroupCallback(sdkcallback func(interface{}, string) <-chan string) {
	discover.RegisterSdkMsgCallback(sdkcallback)
}
// recv return from sendToGroup...
func SdkProtocol_registerSendToGroupReturnCallback(sdkcallback func(interface{}, string)) {
	discover.RegisterSdkMsgRetCallback(sdkcallback)
}

