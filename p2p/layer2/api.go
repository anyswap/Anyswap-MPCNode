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

	"github.com/fsn-dev/dcrm-walletService/p2p"
	"github.com/fsn-dev/dcrm-walletService/p2p/discover"
)

//================   API   SDK    =====================
func SdkProtocol_sendToGroupOneNode(gID, msg string) (string, error) {
	gid, _ := discover.HexID(gID)
	if checkExistGroup(gid) == false {
		fmt.Printf("sendToGroupOneNode, group gid: %v not exist\n", gid)
		return "", errors.New("sendToGroupOneNode, gid not exist")
	}
	g := getSDKGroupNodes(gid)
	return discover.SendToGroup(gid, msg, false, Sdkprotocol_type, g)
}

func SdkProtocol_SendToGroupAllNodes(gID, msg string) (string, error) {
	gid, _ := discover.HexID(gID)
	if checkExistGroup(gid) == false {
		e := fmt.Sprintf("SendGroupAllNodes, group gid: %v not exist", gid)
		fmt.Println(e)
		return "", errors.New(e)
	}
	g := getSDKGroupNodes(gid)
	return discover.SendToGroup(gid, msg, true, Sdkprotocol_type, g)
}

func SdkProtocol_broadcastInGroupOthers(gID, msg string) (string, error) { // without self
	gid, _ := discover.HexID(gID)
	if checkExistGroup(gid) == false {
		e := fmt.Sprintf("broadcastInGroupOthers, group gid: %v not exist", gid)
		fmt.Println(e)
		return "", errors.New(e)
	}
	return BroadcastToGroup(gid, msg, Sdkprotocol_type, false)
}

func SdkProtocol_broadcastInGroupAll(gID, msg string) (string, error) { // within self
	gid, _ := discover.HexID(gID)
	if checkExistGroup(gid) == false {
		e := fmt.Sprintf("broadcastInGroupAll, group gid: %v not exist", gid)
		fmt.Println(e)
		return "", errors.New(e)
	}
	return BroadcastToGroup(gid, msg, Sdkprotocol_type, true)
}

func SdkProtocol_getGroup(gID string) (int, string) {
	gid, err := discover.HexID(gID)
	if err != nil || checkExistGroup(gid) == false {
		fmt.Printf("broadcastInGroupAll, group gID: %v, hexid-gid: %v not exist\n", gID, gid)
		return 0, ""
	}
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

// receive message form peers
func RegisterCallback(recvFunc func(interface{}, string)) {
	discover.RegisterCallback(recvFunc)
	callback = recvFunc
}

func RegisterRecvCallback(recvPrivkeyFunc func(interface{})) {
	discover.RegisterPriKeyCallback(recvPrivkeyFunc)
}

func RegisterSendCallback(callbackfunc func(interface{})) {
	discover.RegisterSendCallback(callbackfunc)
}

func GetGroupSDKAll() []*discover.Group { //nooo
	var groupTmp []*discover.Group
	for _, g := range discover.SDK_groupList {
		if g.Type != "1+1+1" {
			continue
		}
		groupTmp = append(groupTmp, g)
	}
	return groupTmp
}

func GetSelfID() string {
	return discover.GetLocalID().String()
}

func GetEnode() string {
	return discover.GetEnode()
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

func ParseNodeID(enode string) string {
	node, err := discover.ParseNode(enode)
	if err != nil {
		fmt.Printf("==== ParseNodeID() ====, enode: %v, error: %v\n", enode, err.Error())
		return ""
	}
	return node.ID.String()
}

func GetEnodeStatus(enode string) (string, error) {
	return discover.GetEnodeStatus(enode)
}

func HexID(gID string) (discover.NodeID, error) {
	return discover.HexID(gID)
}

