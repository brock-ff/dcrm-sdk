package lib 

import (
	"github.com/fsn-dev/dcrm-sdk/internal/common/math/random"
	"math/big"
	"fmt"
)

type NtildeH1H2 struct {
	Ntilde *big.Int
	H1     *big.Int
	H2     *big.Int
}

func GenerateNtildeH1H2(length int) *NtildeH1H2 {

	//p := <-SafePrime //random.GetSafeRandomPrimeInt(length / 2)
	//q := <-SafePrime //random.GetSafeRandomPrimeInt(length / 2)
	p := SafePrime[2] //random.GetSafeRandomPrimeInt(length / 2)
	q := SafePrime[3] //random.GetSafeRandomPrimeInt(length / 2)
	fmt.Println("=============GenerateNtildeH1H2,p = %v,q =%v=================",p,q)
	if p == nil || q == nil {
	    return nil
	}

	ntilde := new(big.Int).Mul(p, q)

	h1 := random.GetRandomIntFromZnStar(ntilde)
	h2 := random.GetRandomIntFromZnStar(ntilde)

	ntildeH1H2 := &NtildeH1H2{Ntilde: ntilde, H1: h1, H2: h2}

	return ntildeH1H2
}
