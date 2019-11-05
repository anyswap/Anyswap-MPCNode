// Copyright 2015 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// bootnode runs a bootstrap node for the Ethereum Discovery Protocol.
package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"net"
	"os"

	//"github.com/fusion/go-fusion/cmd/utils"
	"github.com/fsn-dev/dcrm-sdk/crypto"
	"github.com/fsn-dev/dcrm-sdk/p2p/discover"
	"github.com/fsn-dev/dcrm-sdk/p2p/discv5"
	"github.com/fsn-dev/dcrm-sdk/p2p/nat"
	"github.com/fsn-dev/dcrm-sdk/p2p/netutil"
)

func main() {
	var (
		groupNum    = flag.Int("group", int(1), "group Number: default 1")
		listenAddr  = flag.String("addr", ":40401", "listen address")
		genKey      = flag.String("genkey", "", "generate a node key")
		writeAddr   = flag.Bool("writeaddress", false, "write out the node's pubkey hash and quit")
		nodeKeyFile = flag.String("nodekey", "", "private key filename")
		nodeKeyHex  = flag.String("nodekeyhex", "", "private key as hex (for testing)")
		natdesc     = flag.String("nat", "none", "port mapping mechanism (any|none|upnp|pmp|extip:<IP>)")
		netrestrict = flag.String("netrestrict", "", "restrict network communication to the given IP networks (CIDR masks)")
		runv5       = flag.Bool("v5", false, "run a v5 topic discovery bootnode")

		nodeKey *ecdsa.PrivateKey
		err     error
	)
	flag.Parse()

	natm, err := nat.Parse(*natdesc)
	if err != nil {
		fmt.Errorf("-nat: %v", err)
		return
	}
	switch {
	case *genKey != "":
		nodeKey, err = crypto.GenerateKey()
		if err != nil {
			//utils.Fatalf("could not generate key: %v", err)
		}
		if err = crypto.SaveECDSA(*genKey, nodeKey); err != nil {
			//utils.Fatalf("%v", err)
		}
		return
	case *nodeKeyFile == "" && *nodeKeyHex == "":
		fmt.Printf("Use -nodekey or -nodekeyhex to specify a private key\n")
		return
	case *nodeKeyFile != "" && *nodeKeyHex != "":
		fmt.Printf("Options -nodekey and -nodekeyhex are mutually exclusive\n")
		return
	case *nodeKeyFile != "":
		if nodeKey, err = crypto.LoadECDSA(*nodeKeyFile); err != nil {
			fmt.Printf("-nodekey: %v\n", err)
			return
		}
	case *nodeKeyHex != "":
		if nodeKey, err = crypto.HexToECDSA(*nodeKeyHex); err != nil {
			//utils.Fatalf("-nodekeyhex: %v", err)
		}
	}

	if *writeAddr {
		fmt.Printf("%v\n", discover.PubkeyID(&nodeKey.PublicKey))
		os.Exit(0)
	}

	var restrictList *netutil.Netlist
	if *netrestrict != "" {
		restrictList, err = netutil.ParseNetlist(*netrestrict)
		if err != nil {
			//utils.Fatalf("-netrestrict: %v", err)
		}
	}

	addr, err := net.ResolveUDPAddr("udp", *listenAddr)
	if err != nil {
		//utils.Fatalf("-ResolveUDPAddr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		//utils.Fatalf("-ListenUDP: %v", err)
	}

	realaddr := conn.LocalAddr().(*net.UDPAddr)
	if natm != nil {
		if !realaddr.IP.IsLoopback() {
			go nat.Map(natm, nil, "udp", realaddr.Port, realaddr.Port, "ethereum discovery")
		}
		// TODO: react to external IP changes over time.
		if ext, err := natm.ExternalIP(); err == nil {
			realaddr = &net.UDPAddr{IP: ext, Port: realaddr.Port}
		}
	}

	if *runv5 {
		if _, err := discv5.ListenUDP(nodeKey, conn, realaddr, "", restrictList); err != nil {
			//utils.Fatalf("%v", err)
		}
	} else {
		cfg := discover.Config{
			PrivateKey:   nodeKey,
			AnnounceAddr: realaddr,
			NetRestrict:  restrictList,
		}
		if _, err := discover.ListenUDP(conn, cfg); err != nil {
			//utils.Fatalf("%v", err)
		}
	}

	// TODO: group
	fmt.Printf("groupNum: %v\n", *groupNum)
	if err := discover.InitGroup(*groupNum); err != nil {
	}

	select {}
}
