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

package dcrm

import (
	"encoding/json"
	"fmt"
	"github.com/fsn-dev/dcrm-walletService/p2p/layer2"
)

var RPCTEST bool = false

const (
	SUCCESS string = "Success"
	FAIL    string = "Error"
	NULLRET string = "Null"
	REPEAT  string = "Repeat"
	PENDING string = "Pending"
)

type Result struct {
	Status string // Success, Error, Null, Repeat, Pending
	Tip    string
	Error  string
	Data   interface{}
}

type Enode struct {
	Enode string
}

type EnodeStatus struct {
	Enode  string
	Status string
}

func packageResult(status, tip, errors string, msg interface{}) string {
	ret := &Result{Status: status, Tip: tip, Error: errors, Data: msg}
	retnid, _ := json.Marshal(ret)
	return string(retnid)
}

func (this *Service) GetEnode() string {
	fmt.Printf("==== GetEnode() ====\n")
	en := layer2.GetEnode()
	reten := &Enode{Enode: en}
	fmt.Printf("==== GetEnode() ====, en: %v, ret: %v\n", en, reten)
	return packageResult(SUCCESS, "", "", reten)
}

type GroupInfo struct {
	Gid    string
	Mode   string
	Count int
	Enodes []string
}

func (this *Service) CreateGroup(mode string, enodes []string) string {
	return this.CreateSDKGroup(mode, enodes)
}

func (this *Service) CreateSDKGroup(mode string, enodes []string) string {
	fmt.Printf("==== CreateSDKGroup() ====\n")
	err := layer2.CheckAddPeer(mode, enodes)
	if err != nil {
		ret := &GroupInfo{Mode: mode}
		fmt.Printf("==== CreateSDKGroup() ====, CheckAddPeer err: %v\n", err)
		return packageResult(FAIL, "add peer failed", err.Error(), ret)
	}
	gid, count, retErr := layer2.CreateSDKGroup(mode, enodes)
	if retErr != "" {
		status := FAIL
		fmt.Printf("==== CreateSDKGroup() ====, CreateSDKGroup tip: %v, err: %v\n", retErr, retErr)
		ret := &GroupInfo{Gid: gid, Mode: mode, Count: count, Enodes: enodes}
		return packageResult(status, retErr, retErr, ret)
	}
	fmt.Printf("==== CreateSDKGroup() ====, gid: %v, count: %v\n", gid, count)
	ret := &GroupInfo{Gid: gid, Mode: mode, Count: count, Enodes: enodes}
	return packageResult(SUCCESS, "", "", ret)
}

type sdkGroupInfo struct {
	Enode     string
	GroupList []GroupInfo
}

func (this *Service) GetSDKGroup(enode string) string {
	return getSDKGroup(enode, "1+1+1")
}

func (this *Service) GetSDKGroup4Dcrm() string {
	enode := layer2.GetEnode()
	return getSDKGroup(enode, "")
}

func (this *Service) GetSDKGroupPerson(enode string) string {
	return getSDKGroup(enode, "1+2")
}

func getSDKGroup(enode, groupType string) string {
	group := make([]GroupInfo, 0)
	nodeid := layer2.ParseNodeID(enode)
	stat := SUCCESS
	tip := ""
	addGroupChanged := false
	for gid, g := range layer2.SdkGroup {
		addGroup := false
		fmt.Printf("g: %v\n", gid, g)
		enodes := make([]string, 0)
		if g.Type == groupType {
			for id, en := range g.Nodes {
				enodes = append(enodes, fmt.Sprintf("enode://%v@%v:%v", en.ID, en.IP, en.UDP))
				fmt.Printf("getSDKGroup, id: %v, nodeid: %v\n", id, nodeid)
				if en.ID.String() == nodeid {
					addGroup = true
					addGroupChanged = true
				}
			}
		}
		if addGroup {
			ret := &GroupInfo{Gid: gid.String(), Mode: g.Mode, Count: len(g.Nodes), Enodes: enodes}
			group = append(group, *ret)
		}
	}
	if !addGroupChanged {
		stat = NULLRET
		tip = "group is null"
	}
	sgi := &sdkGroupInfo{Enode: enode, GroupList: group}
	return packageResult(stat, tip, tip, sgi)
}

func (this *Service) GetEnodeStatus(enode string) string {
	es := &EnodeStatus{Enode: enode}
	status := SUCCESS
	stat, err := layer2.GetEnodeStatus(enode)
	if stat == "" {
		status = FAIL
	}
	es.Status = stat

	errString := ""
	if err != nil {
		errString = fmt.Sprintf("%v", err.Error())
	}
	return packageResult(status, errString, errString, es)
}

// TEST
func (this *Service) GetSDKGroupAll() string {
if RPCTEST == false { return "" }
	retMsg := layer2.GetGroupSDKAll()
	fmt.Printf("==== GetSDKGroupAll() ====, ret: %v\n", retMsg)
	return packageResult(SUCCESS, "", "", retMsg)
}

func (this *Service) BroadcastInSDKGroupAll(gid, msg string) string {
if RPCTEST == false { return "" }
	retMsg, err := layer2.SdkProtocol_broadcastInGroupAll(gid, msg)
	status := SUCCESS
	if err != nil {
		status = FAIL
	}
	fmt.Printf("==== BroadcastInSDKGroupAll() ====, ret: %v\n", retMsg)
	return packageResult(status, "", retMsg, msg)
}

func (this *Service) SendToGroupAllNodes(gid, msg string) string {
if RPCTEST == false { return "" }
	retMsg, err := layer2.SdkProtocol_SendToGroupAllNodes(gid, msg)
	status := SUCCESS
	if err != nil {
		status = FAIL
	}
	fmt.Printf("==== SendToGroupAllNodes() ====, ret: %v\n", retMsg)
	return packageResult(status, "", retMsg, msg)
}

