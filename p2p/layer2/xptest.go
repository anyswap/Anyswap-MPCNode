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
func pcall(msg interface{}) {
	fmt.Printf("\nxp call: msg = %v\n", msg)
}

func xpcall(msg interface{}) <-chan string {
	ch := make(chan string, 800)
	fmt.Printf("\nxp xpcall: msg=%v\n", msg)
	dcrmcallMsg := fmt.Sprintf("%v xpcall", msg)
	Xprotocol_broadcastInGroupOthers(dcrmcallMsg)
	ch <- msg.(string)
	return ch
}

func xpcallret(msg interface{}) {
	fmt.Printf("xpcallret: msg=%v\n", msg)
}

func Xprotocol_startTest() {
	fmt.Printf("\n\nXP P2P test ...\n\n")
	Xprotocol_registerRecvCallback(pcall)
	Xprotocol_registerMsgRecvCallback(xpcall)
	Xprotocol_registerMsgRetCallback(xpcallret)

	time.Sleep(time.Duration(10) * time.Second)

	//select {} // note for server, or for client

	var num int = 0
	for {
		fmt.Printf("\nSendToXpGroup ...\n")
		num += 1
		msgtest := fmt.Sprintf("%+v test SendToXpGroup ...", num)
		Xprotocol_sendToGroupOneNode(msgtest)
		time.Sleep(time.Duration(5) * time.Second)
	}

	select {}
}
