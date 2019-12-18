package main

import (
    "fmt"
    "github.com/fsn-dev/dcrm-sdk/internal/common/math/random"
    "io/ioutil"
    "net"
    "os"
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

    //////
    /*service :="127.0.0.1:22" 
    tcpAddr, err := net.ResolveTCPAddr("tcp4", service)
    if err != nil {
	return
    }

    conn, err := net.DialTCP("tcp", nil, tcpAddr)
    if err != nil {
	return
    }

    _, err = conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
    result, err := ioutil.ReadAll(conn)
    fmt.Println(string(result))*/
    //////

    for {
	p := random.GetSafeRandomPrimeInt(1024)
	fmt.Println("============get safe random prime = %v==============",p)
    }

}








