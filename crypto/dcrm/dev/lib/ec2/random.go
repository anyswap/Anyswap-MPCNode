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

package ec2 

import (
	"github.com/fsn-dev/dcrm-walletService/internal/common/math/random"
	"math/big"
	"time"
)

var (
    SafePrime = make(chan *big.Int, 1000)
    RndInt = make(chan *big.Int, 1000)
)

func GenRandomSafePrime(length int) {
    for {
	if len(SafePrime) < 4 { /////TODO  tmp:1000-->4
	    rndInt := <-RndInt
	    p := random.GetSafeRandomPrimeInt2(length/2,rndInt)
	    if p != nil {
		SafePrime <-p
		time.Sleep(time.Duration(1000000)) //1000 000 000 == 1s
	    }
	}

	////TODO tmp:1000-->4
	if len(SafePrime) == 4 {
	    break
	}
	//////
    }
}

func GenRandomInt(length int) {

    for {
	if len(RndInt) < 1000 {
	    ////TODO tmp:1000-->4
	    if len(SafePrime) == 4 {
		break
	    }
	    //////
	    p := random.GetSafeRandomInt(length/2)
	    RndInt <-p
	    
	    time.Sleep(time.Duration(1000000)) //1000 000 000 == 1s
	}
    }
}

