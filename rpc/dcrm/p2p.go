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
	"fmt"

	"github.com/anyswap/Anyswap-MPCNode/internal/params"
	"github.com/anyswap/Anyswap-MPCNode/p2p/layer2"
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

type Version struct {
	Version string
	Commit string
	Date string
}

type EnodeStatus struct {
	Enode  string
	Status string
}

func packageResult(status, tip, errors string, msg interface{}) map[string]interface{} {
	return map[string]interface{}{
		"Status": status,
		"Tip":    tip,
		"Error":  errors,
		"Data":   msg,
	}
}

func (this *Service) GetVersion() map[string]interface{} {
	fmt.Printf("==== GetVersion() ====\n")
	v, c, d := params.GetVersion()
	fmt.Printf("==== GetVersion() ====, version: %v, commit: %v, date: %v\n", v, c, d)
	retv := &Version{Version: v, Commit: c, Date: d}
	return packageResult(SUCCESS, "", "", retv)
}

func (this *Service) GetEnode() map[string]interface{} {
	fmt.Printf("==== GetEnode() ====\n")
	en := layer2.GetEnode()
	reten := &Enode{Enode: en}
	fmt.Printf("==== GetEnode() ====, en: %v, ret: %v\n", en, reten)
	return packageResult(SUCCESS, "", "", reten)
}

type GroupID struct {
	Gid    string
	Sgid    string
}

type GroupInfo struct {
	Gid    string
	Count  int
	Enodes []string
}

func (this *Service) ReshareGroup(threshold string, enodes []string) map[string]interface{} {
	fmt.Printf("==== ReshareSDKGroup() ====, threshold: %v, enodes: %v\n", threshold, enodes)
	all, err := layer2.CheckAddPeer(threshold, enodes, true)
	if err != nil {
		ret := &GroupID{}
		fmt.Printf("==== ReshareSDKGroup() ====, CheckAddPeer err: %v\n", err)
		return packageResult(FAIL, err.Error(), err.Error(), ret)
	}
	gid, count, retErr := layer2.CreateSDKGroup(threshold, enodes, false)
	if retErr != "" {
		status := FAIL
		fmt.Printf("==== ReshareSDKGroup() ====, CreateSDKGroup tip: %v, err: %v\n", retErr, retErr)
		ret := &GroupID{Gid: gid}
		return packageResult(status, retErr, retErr, ret)
	}
	sgid := ""
	if all != true {
		sid, _, retErrs := layer2.CreateSDKGroup(threshold, enodes, true)
		if retErrs != "" {
			status := FAIL
			fmt.Printf("==== ReshareSDKGroup() ====, CreateSDKGroup sub tip: %v, err: %v\n", retErrs, retErrs)
			ret := &GroupID{Sgid: sid}
			return packageResult(status, retErr, retErr, ret)
		}
		sgid = sid
		fmt.Printf("==== ReshareSDKGroup() ====, gid: %v, sgid: %v, count: %v\n", gid, sid, count)
	}
	ret := &GroupID{Gid: gid, Sgid: sgid}
	return packageResult(SUCCESS, "", "", ret)
}

func (this *Service) CreateGroup(threshold string, enodes []string) map[string]interface{} {
	return this.CreateSDKGroup(threshold, enodes, false)
}

func (this *Service) CreateSDKGroup(threshold string, enodes []string, subGroup bool) map[string]interface{} {
	fmt.Printf("==== CreateSDKGroup() ====\n")
	_, err := layer2.CheckAddPeer(threshold, enodes, subGroup)
	if err != nil {
		ret := &GroupID{}
		fmt.Printf("==== CreateSDKGroup() ====, CheckAddPeer err: %v\n", err)
		return packageResult(FAIL, err.Error(), err.Error(), ret)
	}
	gid, count, retErr := layer2.CreateSDKGroup(threshold, enodes, subGroup)
	if retErr != "" {
		status := FAIL
		fmt.Printf("==== CreateSDKGroup() ====, CreateSDKGroup tip: %v, err: %v\n", retErr, retErr)
		ret := &GroupID{Gid: gid}
		return packageResult(status, retErr, retErr, ret)
	}
	fmt.Printf("==== CreateSDKGroup() ====, gid: %v, count: %v\n", gid, count)
	ret := &GroupID{Gid: gid}
	return packageResult(SUCCESS, "", "", ret)
}

type sdkGroupInfo struct {
	Enode     string
	GroupList []GroupInfo
}

func (this *Service) GetGroupByID(gid string) map[string]interface{} {
	fmt.Printf("==== GetGroupByID() ====, gid: %v\n", gid)
	return getGroupByID(gid)
}

func (this *Service) GetSDKGroup(enode string) map[string]interface{} {
	return getSDKGroup(enode, "1+1+1")
}

func (this *Service) GetSDKGroup4Dcrm() map[string]interface{} {
	enode := layer2.GetEnode()
	return getSDKGroup(enode, "")
}

func (this *Service) GetSDKGroupPerson(enode string) map[string]interface{} {
	return getSDKGroup(enode, "1+2")
}

func getGroupByID(gID string) map[string]interface{} {
	gid, _ := layer2.HexID(gID)
	stat := SUCCESS
	tip := ""
	addGroupChanged := false
	for id, g := range layer2.GetGroupList() {
		fmt.Printf("==== getGroupByID() ====, range g: %v\n", g)
		enodes := make([]string, 0)
		if id == gid {
			for _, en := range g.Nodes {
				enode := fmt.Sprintf("enode://%v@%v:%v", en.ID, en.IP, en.UDP)
				enodes = append(enodes, enode)
				fmt.Printf("==== getGroupByID() ====, gid: %v, enode: %v\n", gid, enode)
				addGroupChanged = true
			}
			ret := &GroupInfo{Gid: gID, Count: len(g.Nodes), Enodes: enodes}
			fmt.Printf("==== getGroupByID() ====, gid: %v, ret: %v\n", gid, ret)
			return packageResult(stat, tip, tip, ret)
		}
	}
	if !addGroupChanged {
		stat = NULLRET
		tip = "group is null"
	}
	ret := &GroupInfo{Gid: gID}
	return packageResult(stat, tip, tip, ret)
}

func getSDKGroup(enode, groupType string) map[string]interface{} {
	group := make([]GroupInfo, 0)
	fmt.Printf("==== getSDKGroup() ====, call layer2.ParseNodeID() args enode: %v\n", enode)
	nodeid := layer2.ParseNodeID(enode)
	stat := SUCCESS
	tip := ""
	addGroupChanged := false
	for gid, g := range layer2.GetGroupList() {
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
			ret := &GroupInfo{Gid: gid.String(), Count: len(g.Nodes), Enodes: enodes}
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

func (this *Service) GetEnodeStatus(enode string) map[string]interface{} {
	fmt.Printf("==== GetEnodeStatus() ====, enode: %v\n", enode)
	es := &EnodeStatus{Enode: enode}
	status := SUCCESS
	stat, err := layer2.GetEnodeStatus(enode)
	fmt.Printf("==== GetEnodeStatus() ====, enode: %v, stat: %v\n", enode, stat)
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
func (this *Service) GetSDKGroupAll() map[string]interface{} {
	if RPCTEST == false {
		return packageResult(FAIL, "", "RPCTEST == false", "")
	}
	retMsg := layer2.GetGroupSDKAll()
	fmt.Printf("==== GetSDKGroupAll() ====, ret: %v\n", retMsg)
	return packageResult(SUCCESS, "", "", retMsg)
}

func (this *Service) BroadcastInSDKGroupAll(gid, msg string) map[string]interface{} {
	if RPCTEST == false {
		return packageResult(FAIL, "", "RPCTEST == false", "")
	}
	retMsg, err := layer2.SdkProtocol_broadcastInGroupAll(gid, msg)
	status := SUCCESS
	if err != nil {
		status = FAIL
	}
	fmt.Printf("==== BroadcastInSDKGroupAll() ====, ret: %v\n", retMsg)
	return packageResult(status, "", retMsg, msg)
}

func (this *Service) SendToGroupAllNodes(gid, msg string) map[string]interface{} {
	if RPCTEST == false {
		return packageResult(FAIL, "", "RPCTEST == false", "")
	}
	retMsg, err := layer2.SdkProtocol_SendToGroupAllNodes(gid, msg)
	status := SUCCESS
	if err != nil {
		status = FAIL
	}
	fmt.Printf("==== SendToGroupAllNodes() ====, ret: %v\n", retMsg)
	return packageResult(status, "", retMsg, msg)
}
