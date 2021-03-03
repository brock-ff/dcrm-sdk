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
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/fsn-dev/dcrm-sdk/crypto"
	"github.com/fsn-dev/dcrm-sdk/crypto/dcrm"
	"github.com/fsn-dev/dcrm-sdk/p2p"
	"github.com/fsn-dev/dcrm-sdk/p2p/discover"
	"github.com/fsn-dev/dcrm-sdk/p2p/layer2"
	"github.com/fsn-dev/dcrm-sdk/p2p/nat"
	rpcdcrm "github.com/fsn-dev/dcrm-sdk/rpc/dcrm"
	"github.com/urfave/cli"
	//"github.com/fusion/go-fusion/crypto/dcrm/dev"
)

func main() {

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func StartDcrm(c *cli.Context) {
	startP2pNode(nil)
	time.Sleep(time.Duration(20) * time.Second)
	rpcdcrm.RpcInit(rpcport)
	dcrm.Start()
	select {} // note for server, or for client
}

//========================= init ========================
var (
	//args
	rpcport   int
	port      int
	bootnodes string
	keyfile   string
	genKey    string
	app = cli.NewApp()
)

type conf struct {
	Gdcrm *gdcrmConf
}

type gdcrmConf struct {
	Nodekey string
	Bootnodes string
	Port int
	Rpcport int
}

var count int = 0

func init() {
	//app := cli.NewApp()
	app.Usage = "Dcrm Init"
	app.Version = "5.0"
	app.Action = StartDcrm 
	app.Flags = []cli.Flag{
		cli.IntFlag{Name: "rpcport", Value: 0, Usage: "listen port", Destination: &rpcport},
		cli.IntFlag{Name: "port", Value: 0, Usage: "listen port", Destination: &port},
		cli.StringFlag{Name: "bootnodes", Value: "", Usage: "boot node", Destination: &bootnodes},
		cli.StringFlag{Name: "nodekey", Value: "", Usage: "private key filename", Destination: &keyfile},
		cli.StringFlag{Name: "genkey", Value: "", Usage: "generate a node key", Destination: &genKey},
	}
}

func getConfig() error {
	var cf conf
	var path string = "./conf.toml"
	if _, err := toml.DecodeFile(path, &cf); err != nil {
		//fmt.Printf("%v\n", err)
		return err
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

func startP2pNode(c *cli.Context) error {
	go func() error {
		getConfig()
		if port == 0 {
			port = 5551
		}
		if rpcport == 0 {
			rpcport = 5559
		}
		if bootnodes == "" {
			bootnodes = "enode://200cb94957955bfa331ce14b72325c39f3eaa6bcfa962308c967390e5722f6fda0f6080781fde6a025a6280fbf23f38ca454e51a6b75ddbc1f9d57593790545a@47.107.50.83:5550"
		}
		fmt.Printf("keyfile: %v, bootnodes: %v, port: %v, rpcport: %v\n", keyfile, bootnodes, port, rpcport)
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
		if keyfile == "" {
			keyfile = fmt.Sprintf("node.key")
		}
		fmt.Printf("nodekey: %v\n", keyfile)
		dcrm.KeyFile = keyfile
		nodeKey, errkey := crypto.LoadECDSA(keyfile)
		if errkey != nil {
			nodeKey, _ = crypto.GenerateKey()
			crypto.SaveECDSA(keyfile, nodeKey)
			var kfd *os.File
			kfd, _ = os.OpenFile(keyfile, os.O_WRONLY|os.O_APPEND, 0600)
			kfd.WriteString(fmt.Sprintf("\nenode://%v\n", discover.PubkeyID(&nodeKey.PublicKey)))
			kfd.Close()
		}

		///////test only
		/*nid := discover.PubkeyID(&nodeKey.PublicKey)
		s := nid.String()
		b := nid.Bytes()
		enode := fmt.Sprintf("%v",nid)
		nid2,err := discover.HexID(enode)
		enode2 := fmt.Sprintf("%v",nid2)
		pub,err2 := nid2.Pubkey()
		nid3 := discover.PubkeyID(pub)
		s3 := nid3.String()
		enode3 := fmt.Sprintf("%v",nid3)
		fmt.Println("================gdcrm,s = %s,b len = %v,enode = %s,err =%v,enode2 = %s,s3 = %s,enode3 = %s==============",s,len(b),enode,err,enode2,s3,enode3)*/
		////////////////

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

		if err := nodeserv.Start(); err != nil {
			return err
		}

		layer2.InitServer(nodeserv)
		//fmt.Printf("\nNodeInfo: %+v\n", nodeserv.NodeInfo())
		fmt.Println("\n=================== P2P Service Start! ===================\n")
		select {}
	}()
	return nil
}

