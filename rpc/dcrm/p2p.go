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

type Enode struct {
	Enode string
}

type EnodeStatus struct {
	Enode string
	Status string
	Error string
}

type NID struct {
	Nid string
}

func (this *Service) GetEnode() string {
	en := layer2.GetEnode()
	ret := &Enode{Enode: en}
	nid, _ := json.Marshal(ret)
	fmt.Printf("==== GetEnode() ====, en: %v, ret: %v, nid: %v\n", en, ret, string(nid))
	return string(nid)
}

func (this *Service) GetNodeID() string {
	id := layer2.GetSelfID()
	ret := &NID{Nid: id}
	nid, _ := json.Marshal(ret)
	fmt.Printf("==== GetNodeID() ====, id: %v, ret: %v, nid: %v\n", id, ret, string(nid))
	return string(nid)
}

type GroupInfo struct {
	Gname string
	Gid string
	Mode string
	Number int
	Enodes []string
	Status string // group status: NEW, SUCCESS, FAILED
	Error string
}

func (this *Service) CreateSDKGroup(gname, mode string, enodes []string) string {
	fmt.Printf("==== CreateSDKGroup() ====\n")
	if len(enodes) == 0 {
		ret := &GroupInfo{Gname: gname, Error: "nodes is nil"}
		gif, _ := json.Marshal(ret)
		return string(gif)
	}
	err := layer2.CheckAddPeer(enodes)
	if err != nil {
		ret := &GroupInfo{Gname: gname, Mode: mode, Error: err.Error()}
		gif, _ := json.Marshal(ret)
		return string(gif)
	}
	name, gid, count, retErr := layer2.CreateSDKGroup(gname, mode, enodes)
	if retErr != "" {
		if name != gname {
			gname = fmt.Sprintf("%v(new) %v(exist)", gname, name)
		}
		ret := &GroupInfo{Gname: gname, Gid: gid, Mode: mode, Number: count, Enodes: enodes, Error: retErr}
		gif, _ := json.Marshal(ret)
		return string(gif)
	}
	fmt.Printf("==== CreateSDKGroup() ====, gid: %v, count: %v\n", gid, count)
	ret := &GroupInfo{Gname: name, Gid: gid, Mode: mode, Number: count, Enodes: enodes, Status: "NEW"}
	gif, _ := json.Marshal(ret)
	return string(gif)
}

type sdkGroupInfo struct {
	Group []GroupInfo
}

func (this *Service) GetSDKGroup(enode string) string {
	return getSDKGroup(enode, "SUCCESS")
}

func getSDKGroup(enode, status string) string {
	group := make([]GroupInfo, 0)
	nodeid := layer2.ParseNodeID(enode)
	addGroup := false
	for gid, g := range layer2.SdkGroup {
		fmt.Printf("gid: %v, g: %v\n", gid, g)
		addGroup = false
		enodes := make([]string, 0)
		fmt.Printf("g.Status: %v, status: %v\n", g.Status, status)
		if g.Status != status {
			continue
		}
		for id, en := range g.Group {
			enodes = append(enodes, en.Enode)
			if id == nodeid {
				addGroup = true
			}
		}
		if addGroup {
			ret := &GroupInfo{Gname: g.Gname, Gid: gid.String(), Mode: g.Mode, Number: len(g.Group), Enodes: enodes, Status: g.Status}
			group = append(group, *ret)
		}
	}
	sgi := &sdkGroupInfo{Group: group}
	gif, _ := json.Marshal(sgi)
	return string(gif)
}

func (this *Service) GetEnodeStatus(enode string) string {
	es := &EnodeStatus{Enode: enode}
	es.Status, es.Error = layer2.GetEnodeStatus(enode)
	res, _ := json.Marshal(es)
	return string(res)
}

type groupNodeStatus struct {
	Gname string
	Enode string
	Status string
	Error string
	GroupList []GroupInfo
}

func (this *Service) SetGroupNodeStatus(gname, enode, approval string) string {
	fmt.Printf("==== (this *Service) SetGroupNodeStatus() ====, gname: %v, enode: %v, approval: %v\n", gname, enode, approval)
	err := layer2.SetCreateGroupStatus(gname, enode, approval)
	sgi := &groupNodeStatus{Gname: gname, Enode: enode, Status: approval}
	if err != nil {
		sgi.Error = err.Error()
	}
	gif, _ := json.Marshal(sgi)
	return string(gif)
}

func (this *Service) GetGroupNodeStatus(enode string) string {
	fmt.Printf("==== (this *Service) GetGroupNodeStatus() ====, enode: %v\n", enode)
	retGroup := getSDKGroup(enode, "NEW")
	fmt.Printf("\nretGroup: %v\n", retGroup)
	sgi := &groupNodeStatus{Enode: enode}
	rg := sdkGroupInfo{}
	errg := json.Unmarshal([]byte(retGroup), &rg)
	if errg != nil {
		sgi.Error = errg.Error()
	} else {
		//TODO rg
		fmt.Printf("\nrg: %v\n", rg)
		if len(rg.Group) == 0 {
			sgi.Error = "group is null"
		} else {
			//for _, g := range rg.Group {
			//	ret, err := layer2.GetCreateGroupStatus(g.Gname, enode)
			//	if err != nil {
			//		sgi.Error = err.Error()
			//		continue
			//	}
			//	sgi.Gname = g.Gname
			//	sgi.Status = ret
			//}
			sgi.GroupList = rg.Group
		}
	}
	gif, _ := json.Marshal(sgi)
	return string(gif)
}

