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
func bcall(msg interface{}, fromID string) {
	fmt.Printf("\nBroadcast call: msg = %v\n", msg)
}

func CC_startTest() {
	fmt.Printf("\n\nBroadcast test ...\n\n")
	RegisterCallback(bcall)

	time.Sleep(time.Duration(10) * time.Second)

	//select {} // note for client, or for server

	var num int = 0
	for {
		fmt.Printf("\nBroadcast ...\n")
		num += 1
		msgtest := fmt.Sprintf("%+v test Broadcast ...", num)
		Broadcast(msgtest)
		time.Sleep(time.Duration(3) * time.Second)
	}

	select {}
}
