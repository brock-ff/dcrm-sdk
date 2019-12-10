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

package lib

import (
	"github.com/fsn-dev/dcrm-sdk/internal/common/math/random"
	"math/big"
)

var (
    SafePrime = make(chan *big.Int, 1000)
)

func GenRandomSafePrime(length int) {
    for {
	if len(SafePrime) < 1000 {
	    p := random.GetSafeRandomPrimeInt(length/2)
	    SafePrime <-p
	}
    }
}


