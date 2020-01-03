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

package dev

import (
    "fmt"
    "time"
    "math/big"
    "github.com/syndtr/goleveldb/leveldb"
    "github.com/fsn-dev/dcrm-sdk/crypto/secp256k1"
    "github.com/fsn-dev/dcrm-sdk/crypto/dcrm/dev/lib"
    "encoding/hex"
    "strconv"
    "strings"
)

//ec2
//msgprex = hash 
func dcrm_liloreqAddress(msgprex string,keytype string,ch chan interface{}) {

    fmt.Println("========dcrm_liloreqAddress,Nonce =%s============",msgprex)
    GetEnodesInfo()

    if int32(Enode_cnts) != int32(NodeCnt) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGroupNotReady)}
	ch <- res
	return
    }

    wk,err := FindWorker(msgprex)
    if err != nil || wk == nil {
	res := RpcDcrmRes{Ret:"",Err:err}
	ch <- res
	return
    }
    id := wk.id

    ok := KeyGenerate_ECDSA(msgprex,ch,id,keytype)
    if ok == false {
	return
    }

    iter := workers[id].pkx.Front()
    if iter == nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetGenPubkeyFail)}
	ch <- res
	return
    }
    spkx := iter.Value.(string)
    pkx := new(big.Int).SetBytes([]byte(spkx))
    iter = workers[id].pky.Front()
    if iter == nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetGenPubkeyFail)}
	ch <- res
	return
    }
    spky := iter.Value.(string)
    pky := new(big.Int).SetBytes([]byte(spky))
    ys := secp256k1.S256().Marshal(pkx,pky)

    iter = workers[id].save.Front()
    if iter == nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetGenSaveDataFail)}
	ch <- res
	return
    }
    save := iter.Value.(string)

    s := []string{string(ys),save} ////fusionaddr ??
    ss := strings.Join(s,Sep)
    kd := KeyData{Key:ys,Data:ss}
    PubKeyData <-kd
    pubkeyhex := hex.EncodeToString(ys)
    res := RpcDcrmRes{Ret:pubkeyhex,Err:nil}
    ch <- res
}

type KeyData struct {
    Key []byte
    Data string
}

func SavePubKeyDataToDb() {
    for {
	select {
	case kd := <-PubKeyData:
	    dir := GetDbDir()
	    db, err := leveldb.OpenFile(dir, nil) 
	    if err == nil {
		db.Put(kd.Key,[]byte(kd.Data),nil)
		db.Close()
	    } else {
		PubKeyData <-kd
	    }
	    
	    time.Sleep(time.Duration(10000))  //na, 1 s = 10e9 na
	}
    }
}

func ECDSAGenKeyRoundOne(msgprex string,ch chan interface{},w *RpcReqWorker) (*big.Int,*lib.PolyStruct2, *lib.PolyGStruct2,*lib.Commitment,*lib.PublicKey, *lib.PrivateKey,bool) {
    if w == nil || msgprex == "" {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("no find worker.")}
	ch <- res
	return nil,nil,nil,nil,nil,nil,false
    }

    //1. generate their own "partial" private key secretly
    u1 := GetRandomIntFromZn(secp256k1.S256().N)

    //
    u1Poly, u1PolyG, _ := lib.Vss2Init(u1, ThresHold)

    // 2. calculate "partial" public key, make "pritial" public key commiment to get (C,D)
    //also commit vss
    u1Gx, u1Gy := secp256k1.S256().ScalarBaseMult(u1.Bytes())
    u1Secrets := make([]*big.Int, 0)
    u1Secrets = append(u1Secrets, u1Gx)
    u1Secrets = append(u1Secrets, u1Gy)
    for i := 1; i < len(u1PolyG.PolyG); i++ {
	    u1Secrets = append(u1Secrets, u1PolyG.PolyG[i][0])
	    u1Secrets = append(u1Secrets, u1PolyG.PolyG[i][1])
    }
    commitU1G := new(lib.Commitment).Commit(u1Secrets...)

    // 3. generate their own paillier public key and private key
    u1PaillierPk, u1PaillierSk := lib.GenerateKeyPair(PaillierKeyLength)
    if u1PaillierPk == nil || u1PaillierSk == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("gen paillier key pair fail")}
	ch <- res
	return nil,nil,nil,nil,nil,nil,false
    }

    // 4. Broadcast
    // commitU1G.C, commitU2G.C, commitU3G.C, commitU4G.C, commitU5G.C
    // u1PaillierPk, u2PaillierPk, u3PaillierPk, u4PaillierPk, u5PaillierPk
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "C1"
    s1 := string(commitU1G.C.Bytes())
    s2 := u1PaillierPk.Length
    s3 := string(u1PaillierPk.N.Bytes()) 
    s4 := string(u1PaillierPk.G.Bytes()) 
    s5 := string(u1PaillierPk.N2.Bytes()) 
    ss := enode + Sep + s0 + Sep + s1 + Sep + s2 + Sep + s3 + Sep + s4 + Sep + s5
    SendMsgToDcrmGroup(ss,w.groupid)

    // 1. Receive Broadcast
    // commitU1G.C, commitU2G.C, commitU3G.C, commitU4G.C, commitU5G.C
    // u1PaillierPk, u2PaillierPk, u3PaillierPk, u4PaillierPk, u5PaillierPk
     _,cherr := GetChannelValue(ch_t,w.bc1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetC1Timeout)}
	ch <- res
	return nil,nil,nil,nil,nil,nil,false
    }

    return u1,u1Poly,u1PolyG,commitU1G,u1PaillierPk, u1PaillierSk,true
}

func ECDSAGenKeyRoundTwo(msgprex string,cointype string,ch chan interface{},w *RpcReqWorker,u1Poly *lib.PolyStruct2,ids sortableIDSSlice) ([]*lib.ShareStruct2,bool) {
    if w == nil || cointype == "" || msgprex == "" || u1Poly == nil || len(ids) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil,false
    }
    
    // 2. generate their vss to get shares which is a set
    // [notes]
    // all nodes has their own id, in practival, we can take it as double hash of public key of fusion

    u1Shares,err := u1Poly.Vss2(ids)
    if err != nil {
	res := RpcDcrmRes{Ret:"",Err:err}
	ch <- res
	return nil,false 
    }

    // 3. send the the proper share to proper node 
    //example for u1:
    // Send u1Shares[0] to u1
    // Send u1Shares[1] to u2
    // Send u1Shares[2] to u3
    // Send u1Shares[3] to u4
    // Send u1Shares[4] to u5
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,w.groupid)

	if enodes == "" {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetEnodeByUIdFail)}
	    ch <- res
	    return nil,false
	}
	
	if IsCurNode(enodes,cur_enode) {
	    continue
	}

	for _,v := range u1Shares {
	    uid := lib.GetSharesId(v)
	    if uid.Cmp(id) == 0 {
		mp := []string{msgprex,cur_enode}
		enode := strings.Join(mp,"-")
		s0 := "SHARE1"
		s2 := string(v.Id.Bytes()) 
		s3 := string(v.Share.Bytes()) 
		ss := enode + Sep + s0 + Sep + s2 + Sep + s3
		SendMsgToPeer(enodes,ss)
		break
	    }
	}
    }

    return u1Shares,true
}

func ECDSAGenKeyRoundThree(msgprex string,cointype string,ch chan interface{},w *RpcReqWorker,u1PolyG *lib.PolyGStruct2,commitU1G *lib.Commitment,ids sortableIDSSlice) bool {
    if w == nil || cointype == "" || msgprex == "" || u1PolyG == nil || len(ids) == 0 || commitU1G == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return false
    }
    
    // 4. Broadcast
    // commitU1G.D, commitU2G.D, commitU3G.D, commitU4G.D, commitU5G.D
    // u1PolyG, u2PolyG, u3PolyG, u4PolyG, u5PolyG
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "D1"
    dlen := len(commitU1G.D)
    s1 := strconv.Itoa(dlen)

    ss := enode + Sep + s0 + Sep + s1 + Sep
    for _,d := range commitU1G.D {
	ss += string(d.Bytes())
	ss += Sep
    }

    pglen := 2*(len(u1PolyG.PolyG))
    s4 := strconv.Itoa(pglen)

    ss = ss + s4 + Sep

    for _,p := range u1PolyG.PolyG {
	for _,d := range p {
	    ss += string(d.Bytes())
	    ss += Sep
	}
    }
    ss = ss + "NULL"
    SendMsgToDcrmGroup(ss,w.groupid)
    
    // 1. Receive Broadcast
    // commitU1G.D, commitU2G.D, commitU3G.D, commitU4G.D, commitU5G.D
    // u1PolyG, u2PolyG, u3PolyG, u4PolyG, u5PolyG
    _,cherr := GetChannelValue(ch_t,w.bd1_1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetD1Timeout)}
	ch <- res
	return false 
    }

    return true
}

func ECDSAGenKeyVerifyShareData(msgprex string,cointype string,ch chan interface{},w *RpcReqWorker,u1PolyG *lib.PolyGStruct2,u1Shares []*lib.ShareStruct2,ids sortableIDSSlice) (map[string]*lib.ShareStruct2,[]string,bool) {
    if w == nil || cointype == "" || msgprex == "" || u1PolyG == nil || len(ids) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil,nil,false
    }
 
    // 2. Receive Personal Data
    _,cherr := GetChannelValue(ch_t,w.bshare1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetSHARE1Timeout)}
	ch <- res
	return nil,nil,false
    }

    var sstruct = make(map[string]*lib.ShareStruct2)
    shares := make([]string,NodeCnt-1)
    if w.msg_share1.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllSHARE1Fail)}
	ch <- res
	return nil,nil,false
    }

    itmp := 0
    iter := w.msg_share1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	shares[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }
    
    for _,v := range shares {
	mm := strings.Split(v, Sep)
	//bug
	if len(mm) < 4 {
	    fmt.Println("===================!!! KeyGenerate_ECDSA,fill lib.ShareStruct map error. !!!,Nonce =%s ==================",msgprex)
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("fill lib.ShareStruct map error.")}
	    ch <- res
	    return nil,nil,false
	}
	//
	ushare := &lib.ShareStruct2{Id:new(big.Int).SetBytes([]byte(mm[2])),Share:new(big.Int).SetBytes([]byte(mm[3]))}
	prex := mm[0]
	prexs := strings.Split(prex,"-")
	sstruct[prexs[len(prexs)-1]] = ushare
    }

    for _,v := range u1Shares {
	uid := lib.GetSharesId(v)
	enodes := GetEnodesByUid(uid,cointype,w.groupid)
	if IsCurNode(enodes,cur_enode) {
	    sstruct[cur_enode] = v 
	    break
	}
    }

    ds := make([]string,NodeCnt-1)
    if w.msg_d1_1.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllD1Fail)}
	ch <- res
	return nil,nil,false
    }

    itmp = 0
    iter = w.msg_d1_1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	ds[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    var upg = make(map[string]*lib.PolyGStruct2)
    for _,v := range ds {
	mm := strings.Split(v, Sep)
	dlen,_ := strconv.Atoi(mm[2])
	if len(mm) < (4+dlen) {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_d1_1 data error")}
	    ch <- res
	    return nil,nil,false
	}

	pglen,_ := strconv.Atoi(mm[3+dlen])
	pglen = (pglen/2)
	var pgss = make([][]*big.Int, 0)
	l := 0
	for j:=0;j<pglen;j++ {
	    l++
	    var gg = make([]*big.Int,0)
	    if len(mm) < (4+dlen+l) {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_d1_1 data error")}
		ch <- res
		return nil,nil,false
	    }

	    gg = append(gg,new(big.Int).SetBytes([]byte(mm[3+dlen+l])))
	    l++
	    if len(mm) < (4+dlen+l) {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_d1_1 data error")}
		ch <- res
		return nil,nil,false
	    }
	    gg = append(gg,new(big.Int).SetBytes([]byte(mm[3+dlen+l])))
	    pgss = append(pgss,gg)
	}

	ps := &lib.PolyGStruct2{PolyG:pgss}
	prex := mm[0]
	prexs := strings.Split(prex,"-")
	upg[prexs[len(prexs)-1]] = ps
    }
    upg[cur_enode] = u1PolyG

    // 3. verify the share
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	//bug
	if len(en) == 0 || en[0] == "" || sstruct[en[0]] == nil || upg[en[0]] == nil {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifySHARE1Fail)}
	    ch <- res
	    return nil,nil,false
	}
	//
	if sstruct[en[0]].Verify2(upg[en[0]]) == false {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifySHARE1Fail)}
	    ch <- res
	    return nil,nil,false
	}
    }

    return sstruct,ds,true
}

func ECDSAGenKeyCalcPubKey(msgprex string,cointype string,ch chan interface{},w *RpcReqWorker,udecom map[string]*lib.Commitment,ids sortableIDSSlice) (map[string][]*big.Int,bool) {
    if w == nil || cointype == "" || msgprex == "" || len(udecom) == 0 || len(ids) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil,false
    }

    // for all nodes, de-commitment
    var ug = make(map[string][]*big.Int)
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	_, u1G := udecom[en[0]].DeCommit()
	ug[en[0]] = u1G
    }

    // for all nodes, calculate the public key
    var pkx *big.Int
    var pky *big.Int
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	pkx = (ug[en[0]])[0]
	pky = (ug[en[0]])[1]
	break
    }

    for k,id := range ids {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	pkx, pky = secp256k1.S256().Add(pkx, pky, (ug[en[0]])[0],(ug[en[0]])[1])
    }
    w.pkx.PushBack(string(pkx.Bytes()))
    w.pky.PushBack(string(pky.Bytes()))

    return ug,true
}
 
func ECDSAGenKeyCalcPrivKey(msgprex string,cointype string,ch chan interface{},w *RpcReqWorker,sstruct map[string]*lib.ShareStruct2,ids sortableIDSSlice) (*big.Int,bool) {
    if w == nil || cointype == "" || msgprex == "" || len(sstruct) == 0 || len(ids) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil,false
    }
    
    // 5. calculate the share of private key
    var skU1 *big.Int
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	skU1 = sstruct[en[0]].Share
	break
    }

    for k,id := range ids {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	skU1 = new(big.Int).Add(skU1,sstruct[en[0]].Share)
    }
    skU1 = new(big.Int).Mod(skU1, secp256k1.S256().N)

    return skU1,true
}

func ECDSAGenKeyVerifyCommitment(msgprex string,cointype string,ch chan interface{},w *RpcReqWorker,ds []string,commitU1G *lib.Commitment,ids sortableIDSSlice) ([]string,map[string]*lib.Commitment,bool) {
    if w == nil || cointype == "" || msgprex == "" || len(ds) == 0 || len(ids) == 0 || commitU1G == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil,nil,false
    }
 
    // 4.verify and de-commitment to get uG
    // for all nodes, construct the commitment by the receiving C and D
    cs := make([]string,NodeCnt-1)
    if w.msg_c1.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllC1Fail)}
	ch <- res
	return nil,nil,false
    }

    itmp := 0
    iter := w.msg_c1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	cs[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    var udecom = make(map[string]*lib.Commitment)
    for _,v := range cs {
	mm := strings.Split(v, Sep)
	if len(mm) < 3 {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllC1Fail)}
	    ch <- res
	    return nil,nil,false
	}

	prex := mm[0]
	prexs := strings.Split(prex,"-")
	for _,vv := range ds {
	    mmm := strings.Split(vv, Sep)
	    //bug
	    if len(mmm) < 3 {
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllC1Fail)}
		ch <- res
		return nil,nil,false
	    }

	    prex2 := mmm[0]
	    prexs2 := strings.Split(prex2,"-")
	    if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
		dlen,_ := strconv.Atoi(mmm[2])
		var gg = make([]*big.Int,0)
		l := 0
		for j:=0;j<dlen;j++ {
		    l++
		    //bug
		    if len(mmm) < (3+l) {
			res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllC1Fail)}
			ch <- res
			return nil,nil,false
		    }
		    gg = append(gg,new(big.Int).SetBytes([]byte(mmm[2+l])))
		}
		deCommit := &lib.Commitment{C:new(big.Int).SetBytes([]byte(mm[2])), D:gg}
		udecom[prexs[len(prexs)-1]] = deCommit
		break
	    }
	}
    }
    deCommit_commitU1G := &lib.Commitment{C: commitU1G.C, D: commitU1G.D}
    udecom[cur_enode] = deCommit_commitU1G

    // for all nodes, verify the commitment
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	if len(en) == 0 || en[0] == "" || udecom[en[0]] == nil {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrKeyGenVerifyCommitFail)}
	    ch <- res
	    return nil,nil,false
	}
	if udecom[en[0]].Verify() == false {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrKeyGenVerifyCommitFail)}
	    ch <- res
	    return nil,nil,false
	}
    }

    return cs,udecom,true
}

func ECDSAGenKeyRoundFour(msgprex string,ch chan interface{},w *RpcReqWorker) (*lib.NtildeH1H2,bool) {
    if w == nil || msgprex == "" {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil,false
    }

    // 6. calculate the zk
    
    // zk of paillier key
    NtildeLength := 2048 
    // for u1
    u1NtildeH1H2 := lib.GenerateNtildeH1H2(NtildeLength)
    if u1NtildeH1H2 == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("gen ntilde h1 h2 fail.")}
	ch <- res
	return nil,false 
    }

    // 7. Broadcast ntilde 
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "NTILDEH1H2" //delete zkfactor add ntild h1 h2
    s1 := string(u1NtildeH1H2.Ntilde.Bytes())
    s2 := string(u1NtildeH1H2.H1.Bytes())
    s3 := string(u1NtildeH1H2.H2.Bytes())
    ss := enode + Sep + s0 + Sep + s1 + Sep + s2 + Sep + s3
    SendMsgToDcrmGroup(ss,w.groupid)

    // 1. Receive Broadcast zk
    // u1zkFactProof, u2zkFactProof, u3zkFactProof, u4zkFactProof, u5zkFactProof
    _,cherr := GetChannelValue(ch_t,w.bzkfact)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetZKFACTPROOFTimeout)}
	ch <- res
	return nil,false
    }

    return u1NtildeH1H2,true
}

func ECDSAGenKeyRoundFive(msgprex string,ch chan interface{},w *RpcReqWorker,u1 *big.Int) bool {
    if w == nil || msgprex == "" {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return false
    }

    // zk of u
    u1zkUProof := lib.ZkUProve(u1)

    // 8. Broadcast zk
    // u1zkUProof, u2zkUProof, u3zkUProof, u4zkUProof, u5zkUProof
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "ZKUPROOF"
    s1 := string(u1zkUProof.E.Bytes())
    s2 := string(u1zkUProof.S.Bytes())
    ss := enode + Sep + s0 + Sep + s1 + Sep + s2
    SendMsgToDcrmGroup(ss,w.groupid)

    // 9. Receive Broadcast zk
    // u1zkUProof, u2zkUProof, u3zkUProof, u4zkUProof, u5zkUProof
    _,cherr := GetChannelValue(ch_t,w.bzku)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetZKUPROOFTimeout)}
	ch <- res
	return false 
    }

    return true
}

func ECDSAGenKeyVerifyZKU(msgprex string,cointype string,ch chan interface{},w *RpcReqWorker,ids sortableIDSSlice,ug map[string][]*big.Int) bool {
    if w == nil || msgprex == "" || cointype == "" || len(ids) == 0 || len(ug) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return false
    }

    // for all nodes, verify zk of u
    zku := make([]string,NodeCnt-1)
    if w.msg_zku.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllZKUPROOFFail)}
	ch <- res
	return false
    }
    itmp := 0
    iter := w.msg_zku.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	zku[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	for _,v := range zku {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		e := new(big.Int).SetBytes([]byte(mm[2]))
		s := new(big.Int).SetBytes([]byte(mm[3]))
		zkUProof := &lib.ZkUProof{E: e, S: s}
		if !lib.ZkUVerify(ug[en[0]],zkUProof) {
		    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyZKUPROOFFail)}
		    ch <- res
		    return false 
		}

		break
	    }
	}
    }

    return true
}

func ECDSAGenKeySaveData(cointype string,ids sortableIDSSlice,w *RpcReqWorker,ch chan interface{},skU1 *big.Int,u1PaillierPk *lib.PublicKey, u1PaillierSk *lib.PrivateKey,cs []string,u1NtildeH1H2 *lib.NtildeH1H2) bool {
    if cointype == "" || len(ids) == 0 || w == nil || skU1 == nil || u1PaillierPk == nil || u1PaillierSk == nil || len(cs) == 0 || u1NtildeH1H2 == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return false
    }

    //save skU1/u1PaillierSk/u1PaillierPk/...
    ss := string(skU1.Bytes())
    ss = ss + SepSave
    s1 := u1PaillierSk.Length
    s2 := string(u1PaillierSk.L.Bytes()) 
    s3 := string(u1PaillierSk.U.Bytes())
    ss = ss + s1 + SepSave + s2 + SepSave + s3 + SepSave

    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    s1 = u1PaillierPk.Length
	    s2 = string(u1PaillierPk.N.Bytes()) 
	    s3 = string(u1PaillierPk.G.Bytes()) 
	    s4 := string(u1PaillierPk.N2.Bytes()) 
	    ss = ss + s1 + SepSave + s2 + SepSave + s3 + SepSave + s4 + SepSave
	    continue
	}
	for _,v := range cs {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		s1 = mm[3] 
		s2 = mm[4] 
		s3 = mm[5] 
		s4 := mm[6] 
		ss = ss + s1 + SepSave + s2 + SepSave + s3 + SepSave + s4 + SepSave
		break
	    }
	}
    }

    zkfacts := make([]string,NodeCnt-1)
    if w.msg_zkfact.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllZKFACTPROOFFail)}
	ch <- res
	return false
    }

    itmp := 0
    iter := w.msg_zkfact.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	zkfacts[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    s1 = string(u1NtildeH1H2.Ntilde.Bytes())
	    s2 = string(u1NtildeH1H2.H1.Bytes())
	    s3 = string(u1NtildeH1H2.H2.Bytes())
	    ss = ss + s1 + SepSave + s2 + SepSave + s3 + SepSave
	    continue
	}

	for _,v := range zkfacts {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		ss = ss + mm[2] + SepSave + mm[3] + SepSave + mm[4] + SepSave //for ntilde 
		break
	    }
	}
    }

    ss = ss + "NULL"
    //w.save:  sku1:UiSK:U1PK:U2PK:U3PK:....:UnPK:U1H1:U1H2:U1Y:U1E:U1N:U2H1:U2H2:U2Y:U2E:U2N:U3H1:U3H2:U3Y:U3E:U3N:......:NULL
    //w.save:  sku1:UiSK.Len:UiSK.L:UiSK.U:U1PK.Len:U1PK.N:U1PK.G:U1PK.N2:U2PK.Len:U2PK.N:U2PK.G:U2PK.N2:....:UnPK.Len:UnPK.N:UnPK.G:UnPK.N2:U1Ntilde:U1H1:U1H2:U2Ntilde::U2H1:U2H2:......:UnNtilde:UnH1:UnH2:NULL
    w.save.PushBack(ss)
    return true
}

//ec2
//msgprex = hash 
func KeyGenerate_ECDSA(msgprex string,ch chan interface{},id int,cointype string) bool {
    if id < 0 || id >= RpcMaxWorker || id >= len(workers) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetWorkerIdError)}
	ch <- res
	return false
    }

    w := workers[id]
    if w.groupid == "" {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get group id fail.")}
	ch <- res
	return false
    }
    
    ns,_ := GetGroup(w.groupid)
    if ns != NodeCnt {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGroupNotReady)}
	ch <- res
	return false 
    }

    ids := GetIds(cointype,w.groupid)
    
    //*******************!!!Distributed ECDSA Start!!!**********************************

    u1,u1Poly, u1PolyG,commitU1G,u1PaillierPk, u1PaillierSk,status := ECDSAGenKeyRoundOne(msgprex,ch,w)
    if status != true {
	return status
    }
    fmt.Println("=================generate key,round one finish===================")

    u1Shares,status := ECDSAGenKeyRoundTwo(msgprex,cointype,ch,w,u1Poly,ids)
    if status != true {
	return status
    }
    fmt.Println("=================generate key,round two finish===================")

    if ECDSAGenKeyRoundThree(msgprex,cointype,ch,w,u1PolyG,commitU1G,ids) == false {
	return false
    }
    fmt.Println("=================generate key,round three finish===================")

    sstruct,ds,status := ECDSAGenKeyVerifyShareData(msgprex,cointype,ch,w,u1PolyG,u1Shares,ids)
    if status != true {
	return status
    }
    fmt.Println("=================generate key,verify share data finish===================")

    cs,udecom,status := ECDSAGenKeyVerifyCommitment(msgprex,cointype,ch,w,ds,commitU1G,ids)
    if status != true {
	return false
    }
    fmt.Println("=================generate key,verify commitment finish===================")

    ug,status := ECDSAGenKeyCalcPubKey(msgprex,cointype,ch,w,udecom,ids)
    if status != true {
	return false
    }
    fmt.Println("=================generate key,calc pubkey finish===================")

    skU1,status := ECDSAGenKeyCalcPrivKey(msgprex,cointype,ch,w,sstruct,ids)
    if status != true {
	return false
    }
    fmt.Println("=================generate key,calc privkey finish===================")

    u1NtildeH1H2,status := ECDSAGenKeyRoundFour(msgprex,ch,w)
    if status != true {
	return false
    }
    fmt.Println("=================generate key,round four finish===================")

    if ECDSAGenKeyRoundFive(msgprex,ch,w,u1) != true {
	return false
    }
    fmt.Println("=================generate key,round five finish===================")

    if ECDSAGenKeyVerifyZKU(msgprex,cointype,ch,w,ids,ug) != true {
	return false
    }
    fmt.Println("=================generate key,verify zk of u1 finish===================")

    if ECDSAGenKeySaveData(cointype,ids,w,ch,skU1,u1PaillierPk,u1PaillierSk,cs,u1NtildeH1H2) != true {
	return false
    }
    fmt.Println("=================generate key,save data finish===================")

    //*******************!!!Distributed ECDSA End!!!**********************************
    return true
}

