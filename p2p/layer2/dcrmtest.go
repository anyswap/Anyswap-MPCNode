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
	"fmt"
	"time"
)

//call define
func call(msg interface{}) <-chan string {
	fmt.Printf("\ndcrm call: msg = %v\n", msg)
	ch := make(chan string, 800)
	return ch
}

func dcrmcall(msg interface{}) <-chan string {
	ch := make(chan string, 800)
	fmt.Printf("\ndcrm dcrmcall: msg=%v\n", msg)
	dcrmcallMsg := fmt.Sprintf("%v dcrmcall", msg)
	DcrmProtocol_broadcastInGroupOthers(dcrmcallMsg) // without self
	ch <- msg.(string)
	return ch
}

func dcrmcallret(msg interface{}) {
	fmt.Printf("dcrm dcrmcallret: msg=%v\n", msg)
}

func main() {
	fmt.Printf("\n\nDCRM P2P test ...\n\n")
	DcrmProtocol_registerRecvCallback(call) // <- Dcrmrotocol_broadcastToGroup(dcrmcallMsg)
	DcrmProtocol_registerMsgRecvCallback(dcrmcall)
	DcrmProtocol_registerMsgRetCallback(dcrmcallret)

	time.Sleep(time.Duration(10) * time.Second)

	//select {} // note for server, or for client

	var num int = 0
	for {
		fmt.Printf("\nSendToDcrmGroup ...\n")
		num += 1
		msg := fmt.Sprintf("%+v test SendToDcrmGroup ...", num)
		DcrmProtocol_sendToGroupOneNode(msg) // -> Handle: DcrmProtocol_registerCallback(call)
		// -> *msg Handle: DcrmProtocol_registerMsgRecvCallback(dcrmcall)
		//    DcrmProtocol_registerMsgRetCallback(dcrmcallret) <- DcrmProtocol_registerMsgRecvCallback(dcrmcall)
		time.Sleep(time.Duration(2) * time.Second)
	}
	select {}
}
