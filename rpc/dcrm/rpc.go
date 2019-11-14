/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  caihaijun@fusion.org
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
	"os"
	"strconv"
	"os/signal"
	"net"
	"strings"
	"github.com/fsn-dev/dcrm5-libcoins/rpc"
	"github.com/fsn-dev/dcrm5-libcoins/crypto/dcrm"
)

func listenSignal(exit chan int) {
	sig := make(chan os.Signal)
	signal.Notify(sig)

	for {
		<-sig
		exit <- 1
	}
}


type Service struct {}

// this will be called by dcrm_reqDcrmAddr
// raw: tx raw data
// model: "0"  self-group; "1" non self-group
//return pubkey and coins addr
func (this *Service) ReqDcrmAddr(raw string,model string) string {   //函数名首字母必须大写
    fmt.Println("==============dcrm_reqDcrmAddr==================")

    if raw == "" || model == "" || (model != "0" && model != "1") {
	return "param error."
    }

    ret,err := dcrm.ReqDcrmAddr(raw,model)
    if err != nil {
	return err.Error()
    }

    return ret
}

func (this *Service) AcceptLockOut(raw string) string {
    ret,err := dcrm.AcceptLockOut(raw)
    if err != nil {
	return err.Error()
    }

    return ret
}

func (this *Service) LockOut(raw string) map[string]interface{} {
    txhash,err := dcrm.LockOut(raw)
    if err != nil {
	return map[string]interface{}{
		"Error": err.Error(),
	}
    }

    return map[string]interface{}{
	    "TxHash": txhash,
    }
}

func (this *Service) GetBalance(account string,cointype string) string {
    if account == "" || cointype == "" {
	return "param error."
    }

    return dcrm.GetBalance(account,cointype)
}

func (this *Service) GetNonce(account string,cointype string) string {
    if account == "" || cointype == "" {
	return "param error."
    }

    return dcrm.GetNonce(account,cointype)
}

var (
	rpcport  int
	endpoint string = "0.0.0.0"
	server *rpc.Server
	err      error
)

func RpcInit(port int) {
	rpcport = port
	go startRpcServer()
}

// splitAndTrim splits input separated by a comma
// and trims excessive white space from the substrings.
func splitAndTrim(input string) []string {
	result := strings.Split(input, ",")
	for i, r := range result {
		result[i] = strings.TrimSpace(r)
	}
	return result
}

func startRpcServer() error {
	go func() error {
	    server = rpc.NewServer()
	    service := new(Service)
	    if err := server.RegisterName("dcrm", service); err != nil {
		    panic(err)
	    }

	    // All APIs registered, start the HTTP listener
	    var (
		    listener net.Listener
		    err      error
	    )

	    endpoint = endpoint + ":" + strconv.Itoa(rpcport)
	    if listener, err = net.Listen("tcp", endpoint); err != nil {
		    panic(err)
	    }

	    /////////
	    /*
	    var (
		    extapiURL = "n/a"
		    ipcapiURL = "n/a"
	    )
	    rpcAPI := []rpc.API{
		    {
			    Namespace: "account",
			    Public:    true,
			    Service:   api,
			    Version:   "1.0"},
	    }
	    if c.Bool(utils.RPCEnabledFlag.Name) {

		    vhosts := splitAndTrim(c.GlobalString(utils.RPCVirtualHostsFlag.Name))
		    cors := splitAndTrim(c.GlobalString(utils.RPCCORSDomainFlag.Name))

		    // start http server
		    httpEndpoint := fmt.Sprintf("%s:%d", c.String(utils.RPCListenAddrFlag.Name), c.Int(rpcPortFlag.Name))
		    listener, _, err := rpc.StartHTTPEndpoint(httpEndpoint, rpcAPI, []string{"account"}, cors, vhosts, rpc.DefaultHTTPTimeouts)
		    if err != nil {
			    utils.Fatalf("Could not start RPC api: %v", err)
		    }
		    extapiURL = fmt.Sprintf("http://%s", httpEndpoint)
		    log.Info("HTTP endpoint opened", "url", extapiURL)

		    defer func() {
			    listener.Close()
			    log.Info("HTTP endpoint closed", "url", httpEndpoint)
		    }()

	    }
	    if !c.Bool(utils.IPCDisabledFlag.Name) {
		    if c.IsSet(utils.IPCPathFlag.Name) {
			    ipcapiURL = c.String(utils.IPCPathFlag.Name)
		    } else {
			    ipcapiURL = filepath.Join(configDir, "clef.ipc")
		    }

		    listener, _, err := rpc.StartIPCEndpoint(ipcapiURL, rpcAPI)
		    if err != nil {
			    utils.Fatalf("Could not start IPC api: %v", err)
		    }
		    log.Info("IPC endpoint opened", "url", ipcapiURL)
		    defer func() {
			    listener.Close()
			    log.Info("IPC endpoint closed", "url", ipcapiURL)
		    }()

	    }
	    */
	    /////////

	    vhosts := make([]string, 0)
	    cors := splitAndTrim("*")
	    go rpc.NewHTTPServer(cors, vhosts, rpc.DefaultHTTPTimeouts,server).Serve(listener)
	    rpcstring := "\n==================== RPC Service Start! url = " + fmt.Sprintf("http://%s", endpoint) + " =====================\n"
	    fmt.Println(rpcstring)

	    exit := make(chan int)
	    <-exit

	    server.Stop()

	    return nil
	}()

	return nil
}

