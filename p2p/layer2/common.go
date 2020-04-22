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
	"strconv"
	"strings"
	"sync"

	"github.com/fsn-dev/cryptoCoins/crypto"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	"github.com/fsn-dev/dcrm-walletService/p2p/discover"
)

func getGroupAndCode(gid discover.NodeID, p2pType int) (*discover.Group, int) {
	msgCode := peerMsgCode
	var group *discover.Group = nil
	switch p2pType {
	case Sdkprotocol_type:
		discover.GroupSDK.Lock()
		defer discover.GroupSDK.Unlock()
		if discover.SDK_groupList != nil {
			_, group = getGroupSDK(gid)
			msgCode = Sdk_msgCode
		}
		break
	default:
		return nil, msgCode
	}
	return group, msgCode
}

func getGroupSDK(gid discover.NodeID) (discover.NodeID, *discover.Group) { //nooo
	for id, g := range discover.SDK_groupList {
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

func getGroup(gid discover.NodeID, p2pType int) (int, string) {
	var group *discover.Group
	switch p2pType {
	case Sdkprotocol_type:
		discover.GroupSDK.Lock()
		defer discover.GroupSDK.Unlock()
		if discover.SDK_groupList != nil {
			_, group = getGroupSDK(gid)
		}
		break
	default:
		return 0, ""
	}
	enode := ""
	count := 0
	if group == nil {
		return count, enode
	}
	for _, e := range group.Nodes {
		if enode != "" {
			enode += discover.Dcrmdelimiter
		}
		enode += fmt.Sprintf("enode://%v@%v:%v", e.ID, e.IP, e.UDP)
		count++
	}
	return count, enode
}

func getCDLen(msg string) int {
	if len(msg) > 214 {
		return 214
	}
	return len(msg)
}

//-------- for broadcast --------
func broadWithMsg(msg string) bool {
	hash := msgHash(msg)
	ret := broadWithHash(hash)
	broadAddHash(hash)
	return ret
}

func broadAddMsg(msg string) {
	hash := msgHash(msg)
	broadAddHash(hash)
}

func broadWithHash(hash common.Hash) bool {
	knownHashMutex.Lock()
	defer knownHashMutex.Unlock()
	if !knownHash.Contains(hash) {
		return false
	}
	return true
}

func broadAddHash(hash common.Hash) {
	knownHashMutex.Lock()
	defer knownHashMutex.Unlock()
	if knownHash.Cardinality() >= maxKnownTxs {
		knownHash.Pop()
	}
	knownHash.Add(hash)
}

func msgHash(msg string) common.Hash {
	hashHex := crypto.Keccak256Hash([]byte(strings.ToLower(msg))).Hex()
	hash := common.HexToHash(hashHex)
	return hash
}
//-------- for broadcast end --------
func getSDKGroupNodes(gid discover.NodeID) []*discover.Node {
	g := make([]*discover.Node, 0)
	_, group := getGroupSDK(gid)
	if group == nil {
		return g
	}
	for _, rn := range group.Nodes {
		n := discover.NewNode(rn.ID, rn.IP, rn.UDP, rn.TCP)
		g = append(g, n)
	}
	return g
}

func checkExistGroup(gid discover.NodeID) bool {
	discover.GroupSDK.Lock()
	defer discover.GroupSDK.Unlock()
	if discover.SDK_groupList[gid] != nil {
		if discover.SDK_groupList[gid].Type == "1+1+1" {
			return true
		}
	}
	return false
}
func CheckAddPeer(threshold string, enodes []string) error {
	es := strings.Split(threshold, "/")
	if len(es) != 2 {
		msg := fmt.Sprintf("args threshold(%v) format is wrong", threshold)
		return errors.New(msg)
	}
	nodeNum0, _ := strconv.Atoi(es[0])
	nodeNum1, _ := strconv.Atoi(es[1])
	if len(enodes) < nodeNum0 || len(enodes) > nodeNum1 {
		msg := fmt.Sprintf("args threshold(%v) and enodes(%v) not match", threshold, enodes)
		return errors.New(msg)
	}
	var nodeid map[discover.NodeID]int = make(map[discover.NodeID]int, len(enodes))
	defer func() {
		for k := range nodeid {
			delete(nodeid, k)
		}
	}()
	selfEnodeExist := false
	wg := &sync.WaitGroup{}
	for _, enode := range enodes {
		node, err := discover.ParseNode(enode)
		if err != nil {
			msg := fmt.Sprintf("CheckAddPeer, parse err enode: %v", enode)
			return errors.New(msg)
		}
		if nodeid[node.ID] == 1 {
			msg := fmt.Sprintf("CheckAddPeer, enode: %v, err: repeated", enode)
			return errors.New(msg)
		}
		nodeid[node.ID] = 1
		if selfid == node.ID {
			selfEnodeExist = true
			continue
		}

		go func(node *discover.Node) {
			wg.Add(1)
			defer wg.Done()
			p2pServer.AddPeer(node)
			p2pServer.AddTrustedPeer(node)
		}(node)
	}
	wg.Wait()
	if selfEnodeExist != true {
		msg := fmt.Sprintf("CheckAddPeer, slefEnode: %v, err: selfEnode not exist", discover.GetEnode())
		return errors.New(msg)
	}
	return nil
}

func getLocalIP() string {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("net.Interfaces failed, err:", err.Error())
		return ""
	}

	internetIP := ""
	wlanIP := ""
	loopIP := ""
	for i := 0; i < len(netInterfaces); i++ {
		//fmt.Printf("i: %v, flags: %v, net.FlagUp: %v\n", i, netInterfaces[i].Flags, net.FlagUp)
		if (netInterfaces[i].Flags & net.FlagUp) != 0 {
			addrs, _ := netInterfaces[i].Addrs()

			for _, address := range addrs {
				if ipnet, ok := address.(*net.IPNet); ok {
					//fmt.Println(ipnet.IP.String())
					if ipnet.IP.To4() != nil {
						if netInterfaces[i].Name == "WLAN" {
							wlanIP = ipnet.IP.String()
						} else if ipnet.IP.IsLoopback() {
							loopIP = ipnet.IP.String()
						}else {
							if internetIP == "" {
								internetIP = ipnet.IP.String()
							}
						}
					}
				}
			}
		}
	}
	//fmt.Printf("internetIP: %v, wlanIP: %v, loopIP: %v\n", internetIP, wlanIP, loopIP)
	if internetIP != "" {
		//fmt.Printf("\nip: %v\n", internetIP)
		return internetIP
	} else if wlanIP != "" {
		//fmt.Printf("\nip: %v\n", wlanIP)
		return wlanIP
	} else if loopIP != "" {
		//fmt.Printf("\nip: %v\n", loopIP)
		return loopIP
	}
	fmt.Printf("ip is nil\n")
	return ""
}

func Sdk_callEvent(msg string, fromID string) {
	fmt.Printf("Sdk_callEvent\n")
	Sdk_callback(msg, fromID)
}

func callEvent(msg, fromID string) {
	fmt.Printf("%v ==== callEvent() ====, fromID: %v, msg: %v\n", common.CurrentTime(), fromID, msg)
	callback(msg, fromID)
}

