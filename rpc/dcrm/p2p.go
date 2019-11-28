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
	//"strings"
	"github.com/fsn-dev/dcrm5-libcoins/p2p/layer2"
)

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
	en := layer2.GetEnode()
	reten := &Enode{Enode: en}
	fmt.Printf("==== GetEnode() ====, en: %v, ret: %v\n", en, reten)
	return packageResult(SUCCESS, "", "", reten)
}

type GroupInfo struct {
	Gname  string
	Gid    string
	Mode   string
	Status string
	Number int
	Enodes []string
}

func (this *Service) CreateSDKGroup(gname, mode string, enodes []string) string {
	fmt.Printf("==== CreateSDKGroup() ====\n")
	if len(enodes) == 0 {
		ret := &GroupInfo{Gname: gname}
		return packageResult(FAIL, "args 3rd is null", "enodes is null", ret)
	}
	err := layer2.CheckAddPeer(enodes)
	if err != nil {
		ret := &GroupInfo{Gname: gname, Mode: mode}
		return packageResult(FAIL, "add peer failed", err.Error(), ret)
	}
	name, gid, count, retErr := layer2.CreateSDKGroup(gname, mode, enodes)
	if retErr != "" {
		status := FAIL
		tip := ""
		if name != "" {
			tip = fmt.Sprintf("group %v exist", name)
			status = REPEAT
		}
		ret := &GroupInfo{Gname: gname, Gid: gid, Mode: mode, Number: count, Enodes: enodes}
		return packageResult(status, tip, retErr, ret)
	}
	fmt.Printf("==== CreateSDKGroup() ====, gid: %v, count: %v\n", gid, count)
	ret := &GroupInfo{Gname: name, Gid: gid, Mode: mode, Number: count, Enodes: enodes}
	return packageResult(PENDING, "waitting create group approval", "create group started, waitting create group approval", ret)
}

type sdkGroupInfo struct {
	Enode     string
	GroupList []GroupInfo
}

func (this *Service) GetSDKGroup(enode string) string {
	return getSDKGroup(enode, "SUCCESS", false, "")
}

func (this *Service) GetSDKGroup4Dcrm() string {
	enode := layer2.GetEnode()
	return getSDKGroup(enode, "SUCCESS", false, "")
}

func (this *Service) GetSDKGroupPerson(enode string) string {
	return getSDKGroup(enode, "", false, "1+2")
}

func getSDKGroup(enode, build string, status bool, groupMode string) string {
	group := make([]GroupInfo, 0)
	nodeid := layer2.ParseNodeID(enode)
	stat := SUCCESS
	tip := ""
	addGroupChanged := false
	for gid, g := range layer2.SdkGroup {
		addGroup := false
		fmt.Printf("gid: %v, g: %v\n", gid, g)
		enodes := make([]string, 0)
		if groupMode == "1+2" {
			if g.Type == groupMode {
				for id, en := range g.Group {
					enodes = append(enodes, en.Enode)
					fmt.Printf("getSDKGroup, id: %v, nodeid: %v\n", id, nodeid)
					if id == nodeid {
						addGroup = true
						addGroupChanged = true
					}
				}
			}
		} else {
			fmt.Printf("g.Status: %v, build: %v\n", g.Status, build)
			if g.Type == "1+2" {
				continue
			}
			if g.Status != build {
				continue
			}
			for id, en := range g.Group {
				enodes = append(enodes, en.Enode)
				fmt.Printf("getSDKGroup, id: %v, nodeid: %v\n", id, nodeid)
				if id == nodeid {
					addGroup = true
					addGroupChanged = true
				}
			}
		}
		if addGroup {
			ret := &GroupInfo{Gname: g.Gname, Gid: gid.String(), Mode: g.Mode, Number: len(g.Group), Enodes: enodes}
			if status {
				st, err := layer2.GetCreateGroupStatus(g.Gname, enode)
				if err != nil {
					stat = FAIL
					tip = err.Error()
					group = append(group, *ret)
					sgi := &sdkGroupInfo{Enode: enode, GroupList: group}
					return packageResult(stat, tip, tip, sgi)
				}
				ret.Status = st
			}
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
	return packageResult(status, err, err, es)
}

type getGroupNodeStatus struct {
	Enode     string
	GroupList []GroupInfo
}

type setGroupNodeStatus struct {
	Gname  string
	Enode  string
	Status string
	//GroupList []GroupInfo
}

func (this *Service) SetGroupNodeStatus(gname, enode, approval string) string {
	fmt.Printf("==== (this *Service) SetGroupNodeStatus() ====, gname: %v, enode: %v, approval: %v\n", gname, enode, approval)
	err := layer2.SetCreateGroupStatus(gname, enode, approval)
	sgi := &setGroupNodeStatus{Gname: gname, Enode: enode, Status: approval}
	status := SUCCESS
	tip := ""
	if err != nil {
		status = FAIL
		tip = err.Error()
	}
	return packageResult(status, tip, tip, sgi)
}

func (this *Service) GetGroupNodeStatus(enode string) string {
	fmt.Printf("==== (this *Service) GetGroupNodeStatus() ====, enode: %v\n", enode)
	return getSDKGroup(enode, "NEW", true, "")
}

func (this *Service) GetSDKGids() []string {
	retGroup := this.GetSDKGroup4Dcrm()
	var msg json.RawMessage
	buf := Result{Data: &msg}
	err := json.Unmarshal([]byte(retGroup), &buf)
	fmt.Printf("GetSDKGids, buf = %v, err = %v\n", buf, err)
	group := sdkGroupInfo{}
	err = json.Unmarshal(msg, &group)
	fmt.Printf("GetSDKGids, grouplist = %v\n", group)

	ret := make([]string, 0)
	for _, g := range group.GroupList {
		ret = append(ret, g.Gid)
	}
	return ret
}
