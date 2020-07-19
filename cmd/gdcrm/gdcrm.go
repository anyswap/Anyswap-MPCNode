/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  caihaijun@fusion.org huangweijun@fusion.org
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

package main

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/fsn-dev/dcrm-walletService/crypto"
	"github.com/fsn-dev/dcrm-walletService/dcrm"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	"github.com/fsn-dev/dcrm-walletService/p2p"
	"github.com/fsn-dev/dcrm-walletService/p2p/discover"
	"github.com/fsn-dev/dcrm-walletService/p2p/layer2"
	"github.com/fsn-dev/dcrm-walletService/p2p/nat"
	rpcdcrm "github.com/fsn-dev/dcrm-walletService/rpc/dcrm"
	"gopkg.in/urfave/cli.v1"
)

func main() {

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func StartDcrm(c *cli.Context) {
    	SetLogger()
	startP2pNode()
	time.Sleep(time.Duration(5) * time.Second)
	rpcdcrm.RpcInit(rpcport)
	dcrm.Start(waitmsg)
	select {} // note for server, or for client
}

func SetLogger() {
          common.SetLogger(uint32(verbosity), json, color)
         if log != "" {
                 common.SetLogFile(log, rotate, maxage)
         }
}

//========================= init ========================
var (
	//args
	rpcport   int
	port      int
	bootnodes string
	keyfile   string
	keyfilehex string
	pubkey    string
	genKey    string
	datadir   string
	log   string
	rotate   uint64
	maxage   uint64
	verbosity   uint64
	json   bool
	color   bool
	waitmsg   uint64

	app       = cli.NewApp()
	statDir   = "stat"
	Version   = ""
)

const privateNet bool = false

type conf struct {
	Gdcrm *gdcrmConf
}

type gdcrmConf struct {
	Nodekey   string
	Bootnodes string
	Port      int
	Rpcport   int
}

func init() {
	//app := cli.NewApp()
	app.Usage = "Dcrm Wallet Service"
	app.Version = "5.2.1"
	Version = app.Version
	app.Action = StartDcrm
	app.Flags = []cli.Flag{
		cli.IntFlag{Name: "rpcport", Value: 0, Usage: "listen port", Destination: &rpcport},
		cli.IntFlag{Name: "port", Value: 0, Usage: "listen port", Destination: &port},
		cli.StringFlag{Name: "bootnodes", Value: "", Usage: "boot node", Destination: &bootnodes},
		cli.StringFlag{Name: "nodekey", Value: "", Usage: "private key filename", Destination: &keyfile},
		cli.StringFlag{Name: "nodekeyhex", Value: "", Usage: "private key as hex", Destination: &keyfilehex},
		cli.StringFlag{Name: "pubkey", Value: "", Usage: "public key from web user", Destination: &pubkey},
		cli.StringFlag{Name: "genkey", Value: "", Usage: "generate a node key", Destination: &genKey},
		cli.StringFlag{Name: "datadir", Value: "", Usage: "data dir", Destination: &datadir},
		cli.StringFlag{Name: "log", Value: "", Usage: "Specify log file, support rotate", Destination: &log},
		cli.Uint64Flag{Name: "rotate", Value: 2, Usage: "log rotation time (unit hour)", Destination: &rotate},
		cli.Uint64Flag{Name: "maxage", Value: 72, Usage: "log max age (unit hour)", Destination: &maxage},
		cli.Uint64Flag{Name: "verbosity", Value: 4, Usage: "log verbosity (0:panic, 1:fatal, 2:error, 3:warn, 4:info, 5:debug, 6:trace)", Destination: &verbosity},
		cli.BoolFlag{Name: "json", Usage: "output log in json format",Destination: &json},
		cli.BoolFlag{Name: "color", Usage: "output log in color text format", Destination: &color},
		cli.Uint64Flag{Name: "waitmsg", Value: 700, Usage: "the time to wait p2p msg", Destination: &waitmsg},
	}
}

func getConfig() error {
	var cf conf
	var path string = "./conf.toml"
	if keyfile != "" && keyfilehex != "" {
		fmt.Printf("Options -nodekey and -nodekeyhex are mutually exclusive\n")
		keyfilehex = ""
	}
	if common.FileExist(path) != true {
		fmt.Printf("config file: %v not exist\n", path)
		return errors.New("config file not exist")
	} else {
		if _, err := toml.DecodeFile(path, &cf); err != nil {
			fmt.Printf("DecodeFile %v: %v\n", path, err)
			return err
		}
	}
	nkey := cf.Gdcrm.Nodekey
	bnodes := cf.Gdcrm.Bootnodes
	pt := cf.Gdcrm.Port
	rport := cf.Gdcrm.Rpcport
	if nkey != "" && keyfile == "" {
		keyfile = nkey
	}
	if bnodes != "" && bootnodes == "" {
		bootnodes = bnodes
	}
	if pt != 0 && port == 0 {
		port = pt
	}
	if rport != 0 && rpcport == 0 {
		rpcport = rport
	}
	return nil
}

func startP2pNode() error {
	common.InitDir(datadir)
	common.SetVersion(Version)
	layer2.InitP2pDir()
	getConfig()
	if port == 0 {
		port = 4441
	}
	if rpcport == 0 {
		rpcport = 4449
	}
	if !privateNet && bootnodes == "" {
		bootnodes = "enode://4dbed736b0d918eb607382e4e50cd85683c4592e32f666cac03c822b2762f2209a51b3ed513adfa28c7fa2be4ca003135a5734cfc1e82161873debb0cff732c8@104.210.49.28:36231"
	}
	if genKey != "" {
		nodeKey, err := crypto.GenerateKey()
		if err != nil {
			fmt.Printf("could not generate key: %v\n", err)
		}
		if err = crypto.SaveECDSA(genKey, nodeKey); err != nil {
			fmt.Printf("could not save key: %v\n", err)
		}
		os.Exit(1)
	}
	var nodeKey *ecdsa.PrivateKey
	var errkey error
	pubdir := ""
	if privateNet {
		if bootnodes == "" {
			bootnodes = "enode://4dbed736b0d918eb607382e4e50cd85683c4592e32f666cac03c822b2762f2209a51b3ed513adfa28c7fa2be4ca003135a5734cfc1e82161873debb0cff732c8@127.0.0.1:36231"
		}
		keyfilehex = ""
		fmt.Printf("private network\n")
		if pubkey != "" {
			pubdir = pubkey
			if strings.HasPrefix(pubkey, "0x") {
				pubdir = pubkey[2:]
			}
			fmt.Printf("bootnodes: %v\n", bootnodes)
			keyname := fmt.Sprintf("%v.key", pubdir[:8])
			keyfile = filepath.Join(layer2.GetSelfDir(), keyname)
		}
	}
	if keyfilehex != "" {
		nodeKey, errkey = crypto.HexToECDSA(keyfilehex)
		if errkey != nil {
			fmt.Printf("HexToECDSA nodekeyhex: %v, err: %v\n", keyfilehex, errkey)
			os.Exit(1)
		}
		fmt.Printf("keyfilehex: %v, bootnodes: %v\n", keyfilehex, bootnodes)
	} else {
		if keyfile == "" {
			keyfile = fmt.Sprintf("node.key")
		}
		fmt.Printf("keyfile: %v, bootnodes: %v\n", keyfile, bootnodes)
		dcrm.KeyFile = keyfile
		nodeKey, errkey = crypto.LoadECDSA(keyfile)
		if errkey != nil {
			nodeKey, _ = crypto.GenerateKey()
			crypto.SaveECDSA(keyfile, nodeKey)
			var kfd *os.File
			kfd, _ = os.OpenFile(keyfile, os.O_WRONLY|os.O_APPEND, 0600)
			kfd.WriteString(fmt.Sprintf("\nenode://%v\n", discover.PubkeyID(&nodeKey.PublicKey)))
			kfd.Close()
		}
	}
	nodeidString := discover.PubkeyID(&nodeKey.PublicKey).String()
	if pubdir == "" {
		pubdir = nodeidString
	}
	if privateNet {
		port = getPort(port)
		rp := getRpcPort(pubdir)
		fmt.Printf("getRpcPort, rp: %v\n", rp)
		if rp != 0 {
			rpcport = rp
		}
		rpcport = getPort(rpcport)
		storeRpcPort(pubdir, rpcport)
	}
	fmt.Printf("port: %v, rpcport: %v\n", port, rpcport)
	layer2.InitSelfNodeID(nodeidString)
	layer2.InitIPPort(port)

	dcrm := layer2.DcrmNew(nil)
	nodeserv := p2p.Server{
		Config: p2p.Config{
			MaxPeers:        100,
			MaxPendingPeers: 100,
			NoDiscovery:     false,
			PrivateKey:      nodeKey,
			Name:            "p2p layer2",
			ListenAddr:      fmt.Sprintf(":%d", port),
			Protocols:       dcrm.Protocols(),
			NAT:             nat.Any(),
			//Logger:     logger,
		},
	}

	bootNodes, err := discover.ParseNode(bootnodes)
	if err != nil {
		return err
	}
	fmt.Printf("==== startP2pNode() ====, bootnodes = %v\n", bootNodes)
	nodeserv.Config.BootstrapNodes = []*discover.Node{bootNodes}

	go func() error {
		if err := nodeserv.Start(); err != nil {
			return err
		}

		layer2.InitServer(nodeserv)
		//fmt.Printf("\nNodeInfo: %+v\n", nodeserv.NodeInfo())
		fmt.Println("\n=================== P2P Service Start! ===================\n")
		if privateNet {
			go func() {
				signalChan := make(chan os.Signal, 1)
				signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
				<-signalChan
				deleteRpcPort(pubdir)
				os.Exit(1)
			}()
		}
		select {}
	}()
	return nil
}

func getPort(port int) int {
	if PortInUse(port) {
		portTmp, err := GetFreePort()
		if err == nil {
			fmt.Printf("PortInUse, port: %v, newport: %v\n", port, portTmp)
			port = portTmp
		} else {
			fmt.Printf("GetFreePort, err: %v\n", err)
			os.Exit(1)
		}
	}
	//fmt.Printf("PORT: %v\n", port)
	return port
}

func GetFreePort() (int, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func PortInUse(port int) bool {
	home := common.HomeDir()
	if home != "" {
		checkStatement := ""
		if runtime.GOOS == "darwin" {
			checkStatement = fmt.Sprintf("netstat -an|grep %v", port)
			output, _ := exec.Command("sh", "-c", checkStatement).CombinedOutput()
			if len(output) > 0 {
				return true
			}
		}else if runtime.GOOS == "windows" {
			p := fmt.Sprintf("netstat -ano|findstr %v", port)
			output := exec.Command("cmd", "/C", p)
			_, err := output.CombinedOutput()
			if err == nil {
				return true
			}
		} else {
			checkStatement = fmt.Sprintf("netstat -anutp|grep %v", port)
			output, _ := exec.Command("sh", "-c", checkStatement).CombinedOutput()
			if len(output) > 0 {
				return true
			}
		}
	}
	return false
}

func storeRpcPort(pubdir string, rpcport int) {
	updateRpcPort(pubdir, fmt.Sprintf("%v", rpcport))
}

func deleteRpcPort(pubdir string) {
	updateRpcPort(pubdir, "")
}

func updateRpcPort(pubdir, rpcport string) {
	portDir := common.DefaultDataDir()
	dir := filepath.Join(portDir, statDir, pubdir)
	if common.FileExist(dir) != true {
		os.MkdirAll(dir, os.ModePerm)
	}
	rpcfile := filepath.Join(dir, "rpcport")
	fmt.Printf("==== updateRpcPort() ====, rpcfile: %v, rpcport: %v\n", rpcfile, rpcport)
	f, err := os.Create(rpcfile)
	defer f.Close()
	if err != nil {
		fmt.Println(err.Error())
	} else {
		_, err = f.Write([]byte(rpcport))
	}
}

func getRpcPort(pubdir string) int {
	fmt.Printf("==== getRpcPort() ====, pubdir: %v\n", pubdir)
	portDir := common.DefaultDataDir()
	dir := filepath.Join(portDir, statDir, pubdir)
	if common.FileExist(dir) != true {
		return 0
	}
	rpcfile := filepath.Join(dir, "rpcport")
	if common.FileExist(rpcfile) != true {
		return 0
	}

	port, err := ioutil.ReadFile(rpcfile)
	if err == nil {
		pp := strings.Split(string(port), "\n")
		p, err := strconv.Atoi(pp[0])
		fmt.Printf("==== getRpcPort() ====, p: %v, err: %v\n", p, err)
		if err == nil {
			return p
		}
        }
	return 0
}

