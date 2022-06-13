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

	"github.com/fsn-dev/dcrm-walletService/internal/common"
	"github.com/fsn-dev/dcrm-walletService/internal/params"
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
	v, c, d := params.GetVersion()
	common.Debug("==== GetVersion() ====", "version", v, "commit", c, "date", d)
	retv := &Version{Version: v, Commit: c, Date: d}
	return packageResult(SUCCESS, "", "", retv)
}

func (this *Service) GetEnode() map[string]interface{} {
	en := layer2.GetEnode()
	reten := &Enode{Enode: en}
	common.Debug("==== GetEnode() ====", "enode", en)
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
	common.Debug("==== ReshareSDKGroup() ====", "threshold", threshold, "len(enodes)", len(enodes))
	all, err := layer2.CheckAddPeer(threshold, enodes, true)
	if err != nil {
		ret := &GroupID{}
		common.Debug("==== ReshareSDKGroup() ====", "CheckAddPeer", "error")
		return packageResult(FAIL, err.Error(), err.Error(), ret)
	}
	gid, count, retErr := layer2.CreateSDKGroup(threshold, enodes, false)
	if retErr != "" {
		status := FAIL
		common.Debug("==== ReshareSDKGroup() ====", "CreateSDKGroup", "error")
		ret := &GroupID{Gid: gid}
		return packageResult(status, retErr, retErr, ret)
	}
	sgid := ""
	if all != true {
		sid, _, retErrs := layer2.CreateSDKGroup(threshold, enodes, true)
		if retErrs != "" {
			status := FAIL
			common.Debug("==== ReshareSDKGroup() ====", "CreateSDKGroup sub", "error")
			ret := &GroupID{Sgid: sid}
			return packageResult(status, retErr, retErr, ret)
		}
		sgid = sid
		common.Debug("==== ReshareSDKGroup() ====", "gid", gid, "sgid", gid, "count", count)
	}
	ret := &GroupID{Gid: gid, Sgid: sgid}
	return packageResult(SUCCESS, "", "", ret)
}

func (this *Service) CreateGroup(threshold string, enodes []string) map[string]interface{} {
	return this.CreateSDKGroup(threshold, enodes, false)
}

func (this *Service) CreateSDKGroup(threshold string, enodes []string, subGroup bool) map[string]interface{} {
	_, err := layer2.CheckAddPeer(threshold, enodes, subGroup)
	if err != nil {
		ret := &GroupID{}
		common.Debug("==== CreateSDKGroup() ====", "CheckAddPeer", "error")
		return packageResult(FAIL, err.Error(), err.Error(), ret)
	}
	gid, count, retErr := layer2.CreateSDKGroup(threshold, enodes, subGroup)
	if retErr != "" {
		status := FAIL
		common.Debug("==== CreateSDKGroup() ====", "CreateSDKGroup", "error")
		ret := &GroupID{Gid: gid}
		return packageResult(status, retErr, retErr, ret)
	}
	common.Debug("==== CreateSDKGroup() ====","gid",gid,"count",count)
	ret := &GroupID{Gid: gid}
	return packageResult(SUCCESS, "", "", ret)
}

type sdkGroupInfo struct {
	Enode     string
	GroupList []GroupInfo
}

func (this *Service) GetGroupByID(gid string) map[string]interface{} {
	common.Debug("==== GetGroupByID() ====", "gid", gid)
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
		enodes := make([]string, 0)
		if id == gid {
			for _, en := range g.Nodes {
				enode := fmt.Sprintf("enode://%v@%v:%v", en.ID, en.IP, en.UDP)
				enodes = append(enodes, enode)
				addGroupChanged = true
			}
			ret := &GroupInfo{Gid: gID, Count: len(g.Nodes), Enodes: enodes}
			common.Debug("==== getGroupByID() ====", "gid", gid, "len(enodes)", len(enodes))
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
	common.Debug("==== getSDKGroup() ====", "enode", enode)
	nodeid := layer2.ParseNodeID(enode)
	stat := SUCCESS
	tip := ""
	addGroupChanged := false
	for gid, g := range layer2.GetGroupList() {
		addGroup := false
		enodes := make([]string, 0)
		if g.Type == groupType {
			for _, en := range g.Nodes {
				enodes = append(enodes, fmt.Sprintf("enode://%v@%v:%v", en.ID, en.IP, en.UDP))
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
	es := &EnodeStatus{Enode: enode}
	status := SUCCESS
	stat, err := layer2.GetEnodeStatus(enode)
	common.Debug("==== GetEnodeStatus() ====", "enode", enode, "stat", stat)
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
//func (this *Service) GetSDKGroupAll() map[string]interface{} {
//	if RPCTEST == false {
//		return packageResult(FAIL, "", "RPCTEST == false", "")
//	}
//	retMsg := layer2.GetGroupSDKAll()
//	fmt.Printf("==== GetSDKGroupAll() ====, ret: %v\n", retMsg)
//	return packageResult(SUCCESS, "", "", retMsg)
//}
//
//func (this *Service) BroadcastInSDKGroupAll(gid, msg string) map[string]interface{} {
//	if RPCTEST == false {
//		return packageResult(FAIL, "", "RPCTEST == false", "")
//	}
//	retMsg, err := layer2.SdkProtocol_broadcastInGroupAll(gid, msg)
//	status := SUCCESS
//	if err != nil {
//		status = FAIL
//	}
//	fmt.Printf("==== BroadcastInSDKGroupAll() ====, ret: %v\n", retMsg)
//	return packageResult(status, "", retMsg, msg)
//}
//
//func (this *Service) SendToGroupAllNodes(gid, msg string) map[string]interface{} {
//	if RPCTEST == false {
//		return packageResult(FAIL, "", "RPCTEST == false", "")
//	}
//	retMsg, err := layer2.SdkProtocol_SendToGroupAllNodes(gid, msg)
//	status := SUCCESS
//	if err != nil {
//		status = FAIL
//	}
//	fmt.Printf("==== SendToGroupAllNodes() ====, ret: %v\n", retMsg)
//	return packageResult(status, "", retMsg, msg)
//}
