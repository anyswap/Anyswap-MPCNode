// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package simulations simulates p2p networks.
// A mocker simulates starting and stopping real nodes in a network.
package simulations

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/anyswap/Anyswap-MPCNode/p2p/discover"
	"github.com/anyswap/Anyswap-MPCNode/p2p/simulations/adapters"
)

//a map of mocker names to its function
var mockerList = map[string]func(net *Network, quit chan struct{}, nodeCount int){
	"startStop":     startStop,
	"probabilistic": probabilistic,
	"boot":          boot,
}

//Lookup a mocker by its name, returns the mockerFn
func LookupMocker(mockerType string) func(net *Network, quit chan struct{}, nodeCount int) {
	return mockerList[mockerType]
}

//Get a list of mockers (keys of the map)
//Useful for frontend to build available mocker selection
func GetMockerList() []string {
	list := make([]string, 0, len(mockerList))
	for k := range mockerList {
		list = append(list, k)
	}
	return list
}

//The boot mockerFn only connects the node in a ring and doesn't do anything else
func boot(net *Network, quit chan struct{}, nodeCount int) {
	_, err := connectNodesInRing(net, nodeCount)
	if err != nil {
		panic("Could not startup node network for mocker")
	}
}

//The startStop mockerFn stops and starts nodes in a defined period (ticker)
func startStop(net *Network, quit chan struct{}, nodeCount int) {
	nodes, err := connectNodesInRing(net, nodeCount)
	if err != nil {
		panic("Could not startup node network for mocker")
	}
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-quit:
			return
		case <-tick.C:
			id := nodes[rand.Intn(len(nodes))]
			if err := net.Stop(id); err != nil {
				return
			}

			select {
			case <-quit:
				return
			case <-time.After(3 * time.Second):
			}

			if err := net.Start(id); err != nil {
				return
			}
		}
	}
}

//The probabilistic mocker func has a more probabilistic pattern
//(the implementation could probably be improved):
//nodes are connected in a ring, then a varying number of random nodes is selected,
//mocker then stops and starts them in random intervals, and continues the loop
func probabilistic(net *Network, quit chan struct{}, nodeCount int) {
	nodes, err := connectNodesInRing(net, nodeCount)
	if err != nil {
		select {
		case <-quit:
			//error may be due to abortion of mocking; so the quit channel is closed
			return
		default:
			panic("Could not startup node network for mocker")
		}
	}
	for {
		select {
		case <-quit:
			return
		default:
		}
		var lowid, highid int
		var wg sync.WaitGroup
		randWait := time.Duration(rand.Intn(5000)+1000) * time.Millisecond
		rand1 := rand.Intn(nodeCount - 1)
		rand2 := rand.Intn(nodeCount - 1)
		if rand1 < rand2 {
			lowid = rand1
			highid = rand2
		} else if rand1 > rand2 {
			highid = rand1
			lowid = rand2
		} else {
			if rand1 == 0 {
				rand2 = 9
			} else if rand1 == 9 {
				rand1 = 0
			}
			lowid = rand1
			highid = rand2
		}
		var steps = highid - lowid
		wg.Add(steps)
		for i := lowid; i < highid; i++ {
			select {
			case <-quit:
				return
			case <-time.After(randWait):
			}
			fmt.Sprintf("node %v shutting down", nodes[i])
			err := net.Stop(nodes[i])
			if err != nil {
				wg.Done()
				continue
			}
			go func(id discover.NodeID) {
				time.Sleep(randWait)
				err := net.Start(id)
				if err != nil {
				}
				wg.Done()
			}(nodes[i])
		}
		wg.Wait()
	}

}

//connect nodeCount number of nodes in a ring
func connectNodesInRing(net *Network, nodeCount int) ([]discover.NodeID, error) {
	ids := make([]discover.NodeID, nodeCount)
	for i := 0; i < nodeCount; i++ {
		conf := adapters.RandomNodeConfig()
		node, err := net.NewNodeWithConfig(conf)
		if err != nil {
			return nil, err
		}
		ids[i] = node.ID()
	}

	for _, id := range ids {
		if err := net.Start(id); err != nil {
			return nil, err
		}
		fmt.Sprintf("node %v starting up", id)
	}
	for i, id := range ids {
		peerID := ids[(i+1)%len(ids)]
		if err := net.Connect(id, peerID); err != nil {
			return nil, err
		}
	}

	return ids, nil
}
