package main

import (
    "fmt"
    "github.com/fsn-dev/dcrm-sdk/internal/common/math/random"
)

var (
    channel string
)

func init() { 
    flag.StringVar(&channel, "channel", "mychannel", "Channel name") 
}

func main() { 
    flag.Parse() 
//    if channel == "" && chaincode== "" && dbpath == "" { 
//	fmt.Printf("ERROR: Neither of channel, chaincode, key nor dbpath could be empty\n") 
//	return 
//    } 
    fmt.Printf("channel=",channel)

    for {
	p := random.GetSafeRandomPrimeInt(1024)
    }

}








