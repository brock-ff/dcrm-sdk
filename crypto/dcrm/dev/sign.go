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
    "github.com/fsn-dev/dcrm-sdk/crypto/dcrm/dev/lib"
    "math/big"
    "github.com/fsn-dev/dcrm-sdk/crypto/secp256k1"
    "github.com/fsn-dev/dcrm-sdk/crypto/sha3"
    "time"
    "sort"
    "math/rand"
    "strconv"
    "strings"
    "fmt"
    "encoding/hex"
    "github.com/syndtr/goleveldb/leveldb"
    "github.com/fsn-dev/dcrm-sdk/crypto/ecies"
    "github.com/fsn-dev/dcrm-sdk/crypto"
    "bytes"
    crand "crypto/rand"
    "crypto/ecdsa"
)

func validate_lockout(wsid string,pubkey string,keytype string,message string,ch chan interface{}) {
    fmt.Println("========validate_lockout,Nonce =%s============",wsid)
    lock5.Lock()
    pub, err := hex.DecodeString(pubkey)
    if err != nil {
        res := RpcDcrmRes{Ret:"",Err:err}
        ch <- res
        lock5.Unlock()
        return
    }

    //db
    dir := GetDbDir()
    ////////
    db, err := leveldb.OpenFile(dir, nil) 
    if err != nil { 
	fmt.Println("===========validate_lockout,open db fail.Nonce =%s,dir = %s,err = %v,pubkey = %s,cointype = %s=============",wsid,dir,err,pubkey,keytype)
        res := RpcDcrmRes{Ret:"",Err:err}
        ch <- res
        lock5.Unlock()
        return
    } 

    var data string
    var b bytes.Buffer 
    b.WriteString("") 
    b.WriteByte(0) 
    b.WriteString("") 
    iter := db.NewIterator(nil, nil) 
    for iter.Next() { 
	key := string(iter.Key())
	value := string(iter.Value())
	if strings.EqualFold(key,string(pub)) {
	    data = value
	    break
	}
    }
    iter.Release()
    ///////
    if data == "" {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get save data fail.")}
	ch <- res
	db.Close()
	lock5.Unlock()
	return
    }
    
    datas := strings.Split(data,Sep)

    realdcrmpubkey := hex.EncodeToString([]byte(datas[0]))
    if !strings.EqualFold(realdcrmpubkey,pubkey) {
        res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("pubkey check fail")}
        ch <- res
        db.Close()
        lock5.Unlock()
        return
    }

    db.Close()
    lock5.Unlock()

    rch := make(chan interface{}, 1)
    dcrm_sign(wsid,"xxx",message,realdcrmpubkey,keytype,rch)
    ret,cherr := GetChannelValue(ch_t,rch)
    if cherr != nil {
	    res := RpcDcrmRes{Ret:"",Err:cherr}
	    ch <- res
	    return
    }

    res := RpcDcrmRes{Ret:ret,Err:nil}
    ch <- res
    return
}

//ec2
//msgprex = hash 
//return value is the backup for dcrm sig.
func dcrm_sign(msgprex string,sig string,txhash string,pubkey string,cointype string,ch chan interface{}) string {

    GetEnodesInfo() 
    
    if int32(Enode_cnts) != int32(NodeCnt) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("group not ready.")}
	ch <- res
	return ""
    }

    fmt.Println("===================dcrm_sign,Nonce =%s====================",msgprex)

    lock.Lock()
    //db
    dir := GetDbDir()
    db, err := leveldb.OpenFile(dir, nil) 
    if err != nil { 
	fmt.Println("===========dcrm_sign,open db fail.Nonce =%s,dir = %s,err = %v,pubkey = %s,cointype = %s=============",dir,err,pubkey,cointype)
        res := RpcDcrmRes{Ret:"",Err:err}
        ch <- res
        lock.Unlock()
        return ""
    } 

    //
    pub,err := hex.DecodeString(pubkey)
    if err != nil {
	res := RpcDcrmRes{Ret:"",Err:err}
	ch <- res
	db.Close()
	lock.Unlock()
	return ""
    }

    var data string
    var b bytes.Buffer 
    b.WriteString("") 
    b.WriteByte(0) 
    b.WriteString("") 
    iter := db.NewIterator(nil, nil) 
    for iter.Next() { 
	key := string(iter.Key())
	value := string(iter.Value())
	if strings.EqualFold(key,string(pub)) {
	    data = value
	    break
	}
    }
    iter.Release()
    
    if data == "" {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get save data fail.")}
	ch <- res
	db.Close()
	lock.Unlock()
	return ""
    }

    datas := strings.Split(string(data),Sep)
    save := datas[1]
    
    dcrmpub := datas[0]
    dcrmpks := []byte(dcrmpub)
    dcrmpkx,dcrmpky := secp256k1.S256().Unmarshal(dcrmpks[:])

    txhashs := []rune(txhash)
    if string(txhashs[0:2]) == "0x" {
	txhash = string(txhashs[2:])
    }

    db.Close()
    lock.Unlock()

    w,err := FindWorker(msgprex)
    if w == nil || err != nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("no find worker.")}
	ch <- res
	return ""
    }
    id := w.id
    bak_sig := Sign_ec2(msgprex,save,txhash,cointype,dcrmpkx,dcrmpky,ch,id)
    return bak_sig
}

func MapPrivKeyShare(cointype string,w *RpcReqWorker,idSign sortableIDSSlice,privshare string) (*big.Int,*big.Int) {
    if cointype == "" || w == nil || len(idSign) == 0 || privshare == "" {
	return nil,nil
    }

    // 1. map the share of private key to no-threshold share of private key
    var self *big.Int
    lambda1 := big.NewInt(1)
    for _,uid := range idSign {
	enodes := GetEnodesByUid(uid,cointype,w.groupid)
	if IsCurNode(enodes,cur_enode) {
	    self = uid
	    break
	}
    }

    if self == nil {
	return nil,nil
    }

    for i,uid := range idSign {
	enodes := GetEnodesByUid(uid,cointype,w.groupid)
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	
	sub := new(big.Int).Sub(idSign[i], self)
	subInverse := new(big.Int).ModInverse(sub,secp256k1.S256().N)
	times := new(big.Int).Mul(subInverse, idSign[i])
	lambda1 = new(big.Int).Mul(lambda1, times)
	lambda1 = new(big.Int).Mod(lambda1, secp256k1.S256().N)
    }
    
    skU1 := new(big.Int).SetBytes([]byte(privshare))
    w1 := new(big.Int).Mul(lambda1, skU1)
    w1 = new(big.Int).Mod(w1,secp256k1.S256().N)

    return skU1,w1
}

func ECDSASignRoundOne(msgprex string,w *RpcReqWorker,idSign sortableIDSSlice,ch chan interface{}) (*big.Int,*big.Int,*lib.Commitment) {
    if msgprex == "" || w == nil || len(idSign) == 0 {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetC11Timeout)}
	ch <- res
	return nil,nil,nil
    }

    // 2. select k and gamma randomly
    u1K := GetRandomIntFromZn(secp256k1.S256().N)
    u1Gamma := GetRandomIntFromZn(secp256k1.S256().N)
    
    // 3. make gamma*G commitment to get (C, D)
    u1GammaGx,u1GammaGy := secp256k1.S256().ScalarBaseMult(u1Gamma.Bytes())
    commitU1GammaG := new(lib.Commitment).Commit(u1GammaGx, u1GammaGy)

    // 4. Broadcast
    //	commitU1GammaG.C, commitU2GammaG.C, commitU3GammaG.C
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "C11"
    s1 := string(commitU1GammaG.C.Bytes())
    ss := enode + Sep + s0 + Sep + s1
    SendMsgToDcrmGroup(ss,w.groupid)

    // 1. Receive Broadcast
    //	commitU1GammaG.C, commitU2GammaG.C, commitU3GammaG.C
     _,cherr := GetChannelValue(ch_t,w.bc11)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetC11Timeout)}
	ch <- res
	return nil,nil,nil
    }

    return u1K,u1Gamma,commitU1GammaG
}

func ECDSASignPaillierEncrypt(cointype string,save string,w *RpcReqWorker,idSign sortableIDSSlice,u1K *big.Int,ch chan interface{}) (map[string]*big.Int,map[string]*big.Int,map[string]*lib.PublicKey) {
    if cointype == "" || w == nil || len(idSign) == 0 || u1K == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil,nil,nil
    }

    // 2. MtA(k, gamma) and MtA(k, w)
    // 2.1 encrypt c_k = E_paillier(k)
    var ukc = make(map[string]*big.Int)
    var ukc2 = make(map[string]*big.Int)
    var ukc3 = make(map[string]*lib.PublicKey)
    
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1PaillierPk := GetPaillierPk(save,k)
	    if u1PaillierPk == nil {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get save paillier pk fail")}
		ch <- res
		return nil,nil,nil
	    }

	    u1KCipher,u1R,_ := u1PaillierPk.Encrypt(u1K)
	    ukc[en[0]] = u1KCipher
	    ukc2[en[0]] = u1R
	    ukc3[en[0]] = u1PaillierPk
	    break
	}
    }

    return ukc,ukc2,ukc3
}

func ECDSASignRoundTwo(msgprex string,cointype string,save string,w *RpcReqWorker,idSign sortableIDSSlice,ch chan interface{},u1K *big.Int,ukc2 map[string]*big.Int,ukc3 map[string]*lib.PublicKey) (map[string]*lib.MtAZK1Proof_nhh,map[string]*lib.NtildeH1H2) {
    if msgprex == "" || cointype == "" || save == "" || w == nil || len(idSign) == 0 || u1K == nil || len(ukc2) == 0 || len(ukc3) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil,nil
    }

    // 2.2 calculate zk(k)
    var zk1proof = make(map[string]*lib.MtAZK1Proof_nhh)
    var zkfactproof = make(map[string]*lib.NtildeH1H2)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")

	u1zkFactProof := GetZkFactProof(save,k)
	if u1zkFactProof == nil {
	    fmt.Println("=================Sign_ec2,u1zkFactProof is nil. Nonce =%s=====================",msgprex)
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get ntildeh1h2 fail")}
	    ch <- res
	    return nil,nil
	}

	if len(en) == 0 || en[0] == "" {
	    fmt.Println("=================Sign_ec2,get enode error,Nonce =%s,enodes = %s,uid = %v,cointype = %s,groupid = %s =====================",msgprex,enodes,id,cointype,w.groupid)
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get ntildeh1h2 fail")}
	    ch <- res
	    return nil,nil
	}

	zkfactproof[en[0]] = u1zkFactProof
	if IsCurNode(enodes,cur_enode) {
	    u1u1MtAZK1Proof := lib.MtAZK1Prove_nhh(u1K,ukc2[en[0]], ukc3[en[0]], u1zkFactProof)
	    zk1proof[en[0]] = u1u1MtAZK1Proof
	} else {
	    u1u1MtAZK1Proof := lib.MtAZK1Prove_nhh(u1K,ukc2[cur_enode], ukc3[cur_enode], u1zkFactProof)
	    mp := []string{msgprex,cur_enode}
	    enode := strings.Join(mp,"-")
	    s0 := "MTAZK1PROOF"
	    s1 := string(u1u1MtAZK1Proof.Z.Bytes()) 
	    s2 := string(u1u1MtAZK1Proof.U.Bytes()) 
	    s3 := string(u1u1MtAZK1Proof.W.Bytes()) 
	    s4 := string(u1u1MtAZK1Proof.S.Bytes()) 
	    s5 := string(u1u1MtAZK1Proof.S1.Bytes()) 
	    s6 := string(u1u1MtAZK1Proof.S2.Bytes()) 
	    ss := enode + Sep + s0 + Sep + s1 + Sep + s2 + Sep + s3 + Sep + s4 + Sep + s5 + Sep + s6
	    SendMsgToPeer(enodes,ss)
	}
    }

    _,cherr := GetChannelValue(ch_t,w.bmtazk1proof)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetMTAZK1PROOFTimeout)}
	ch <- res
	return nil,nil
    }

    return zk1proof,zkfactproof
}

func ECDSASignRoundThree(msgprex string,cointype string,save string,w *RpcReqWorker,idSign sortableIDSSlice,ch chan interface{},ukc map[string]*big.Int) bool {
    if msgprex == "" || cointype == "" || save == "" || w == nil || len(idSign) == 0 || len(ukc) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return false
    }

    // 2.3 Broadcast c_k, zk(k)
    // u1KCipher, u2KCipher, u3KCipher
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "KC"
    s1 := string(ukc[cur_enode].Bytes())
    ss := enode + Sep + s0 + Sep + s1
    SendMsgToDcrmGroup(ss,w.groupid)

    // 2.4 Receive Broadcast c_k, zk(k)
    // u1KCipher, u2KCipher, u3KCipher
    _,cherr := GetChannelValue(ch_t,w.bkc)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetKCTimeout)}
	ch <- res
	return false
    }

    kcs := make([]string,ThresHold-1)
    if w.msg_kc.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllKCFail)}
	ch <- res
	return false
    }

    itmp := 0
    iter := w.msg_kc.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	kcs[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}

	for _,v := range kcs {
	    mm := strings.Split(v, Sep)
	    if len(mm) < 3 {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_kc fail")}
		ch <- res
		return false
	    }

	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		kc := new(big.Int).SetBytes([]byte(mm[2]))
		ukc[en[0]] = kc
		break
	    }
	}
    }

    return true
}

func ECDSASignVerifyZKNtilde(msgprex string,cointype string,save string,w *RpcReqWorker,idSign sortableIDSSlice,ch chan interface{},ukc map[string]*big.Int,ukc3 map[string]*lib.PublicKey,zk1proof map[string]*lib.MtAZK1Proof_nhh,zkfactproof map[string]*lib.NtildeH1H2) bool {
    if msgprex == "" || cointype == "" || save == "" || w == nil || len(idSign) == 0 || len(ukc) == 0 || len(ukc3) == 0 || len(zk1proof) == 0 || len(zkfactproof) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return false
    }

    // example for u1, receive: u1u1MtAZK1Proof from u1, u2u1MtAZK1Proof from u2, u3u1MtAZK1Proof from u3
    mtazk1s := make([]string,ThresHold-1)
    if w.msg_mtazk1proof.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllMTAZK1PROOFFail)}
	ch <- res
	return false
    }

    itmp := 0
    iter := w.msg_mtazk1proof.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	mtazk1s[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}

	for _,v := range mtazk1s {
	    mm := strings.Split(v, Sep)
	    if len(mm) < 8 {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_mtazk1proof fail")}
		ch <- res
		return false
	    }

	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		z := new(big.Int).SetBytes([]byte(mm[2]))
		u := new(big.Int).SetBytes([]byte(mm[3]))
		w := new(big.Int).SetBytes([]byte(mm[4]))
		s := new(big.Int).SetBytes([]byte(mm[5]))
		s1 := new(big.Int).SetBytes([]byte(mm[6]))
		s2 := new(big.Int).SetBytes([]byte(mm[7]))
		mtAZK1Proof := &lib.MtAZK1Proof_nhh{Z: z, U: u, W: w, S: s, S1: s1, S2: s2}
		zk1proof[en[0]] = mtAZK1Proof
		break
	    }
	}
    }

    // 2.5 verify zk(k)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    if cur_enode == "" || zk1proof[cur_enode] == nil || zkfactproof[cur_enode] == nil || ukc[cur_enode] == nil || ukc3[cur_enode] == nil {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("mtazk1 verification fail")}
		ch <- res
		return false
	    }

	    //delete zkfactor,add ntilde h1 h2
	    u1rlt1 := zk1proof[cur_enode].MtAZK1Verify_nhh(ukc[cur_enode],ukc3[cur_enode],zkfactproof[cur_enode])
	    if !u1rlt1 {
		fmt.Println("============sign,111111111,verify mtazk1proof fail===================")
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return false
	    }
	} else {
	    if len(en) <= 0 {
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return false
	    }

	    _,exsit := zk1proof[en[0]]
	    if exsit == false {
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return false
	    }

	    _,exsit = ukc[en[0]]
	    if exsit == false {
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return false
	    }

	    u1PaillierPk := GetPaillierPk(save,k)
	    if u1PaillierPk == nil {
		fmt.Println("============sign,22222222,verify mtazk1proof fail===================")
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return false
	    }

	    _,exsit = zkfactproof[cur_enode]
	    if exsit == false {
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return false
	    }

	    if len(en) == 0 || en[0] == "" || zk1proof[en[0]] == nil || zkfactproof[cur_enode] == nil || ukc[en[0]] == nil {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("mtazk1 verification fail")}
		ch <- res
		return false
	    }

	    u1rlt1 := zk1proof[en[0]].MtAZK1Verify_nhh(ukc[en[0]],u1PaillierPk,zkfactproof[cur_enode])
	    if !u1rlt1 {
		fmt.Println("============sign,333333333,verify mtazk1proof fail===================")
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return false
	    }
	}
    }

    return true
}

func GetRandomBetaV(PaillierKeyLength int) ([]*big.Int,[]*big.Int,[]*big.Int,[]*big.Int) {
    // 2.6
    // select betaStar randomly, and calculate beta, MtA(k, gamma)
    // select betaStar randomly, and calculate beta, MtA(k, w)
   
    // [Notes]
    // 1. betaStar is in [1, paillier.N - secp256k1.N^2]
    NSalt := new(big.Int).Lsh(big.NewInt(1), uint(PaillierKeyLength-PaillierKeyLength/10))
    NSubN2 := new(big.Int).Mul(secp256k1.S256().N, secp256k1.S256().N)
    NSubN2 = new(big.Int).Sub(NSalt, NSubN2)
    // 2. MinusOne
    MinusOne := big.NewInt(-1)
    
    betaU1Star := make([]*big.Int,ThresHold)
    betaU1 := make([]*big.Int,ThresHold)
    for i:=0;i<ThresHold;i++ {
	beta1U1Star := GetRandomIntFromZn(NSubN2)
	beta1U1 := new(big.Int).Mul(MinusOne, beta1U1Star)
	betaU1Star[i] = beta1U1Star
	betaU1[i] = beta1U1
    }

    vU1Star := make([]*big.Int,ThresHold)
    vU1 := make([]*big.Int,ThresHold)
    for i:=0;i<ThresHold;i++ {
	v1U1Star := GetRandomIntFromZn(NSubN2)
	v1U1 := new(big.Int).Mul(MinusOne, v1U1Star)
	vU1Star[i] = v1U1Star
	vU1[i] = v1U1
    }

    return betaU1Star,betaU1,vU1Star,vU1
}

func ECDSASignRoundFour(msgprex string,cointype string,save string,w *RpcReqWorker,idSign sortableIDSSlice,ukc map[string]*big.Int,ukc3 map[string]*lib.PublicKey,zkfactproof map[string]*lib.NtildeH1H2,u1Gamma *big.Int,w1 *big.Int,betaU1Star []*big.Int,vU1Star []*big.Int,ch chan interface{}) (map[string]*big.Int,map[string]*lib.MtAZK2Proof_nhh,map[string]*big.Int,map[string]*lib.MtAZK3Proof_nhh,bool) {
    if msgprex == "" || cointype == "" || save == "" || w == nil || len(idSign) == 0 || len(ukc) == 0 || len(ukc3) == 0 || len(zkfactproof) == 0 || len(betaU1Star) == 0 || len(vU1Star) == 0 || u1Gamma == nil || w1 == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil,nil,nil,nil,false
    }

    // 2.7
    // send c_kGamma to proper node, MtA(k, gamma)   zk
    var mkg = make(map[string]*big.Int)
    var mkg_mtazk2 = make(map[string]*lib.MtAZK2Proof_nhh)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1PaillierPk := GetPaillierPk(save,k)
	    if u1PaillierPk == nil {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get paillier pk fail")}
		ch <- res
		return nil,nil,nil,nil,false
	    }

	    u1KGamma1Cipher := u1PaillierPk.HomoMul(ukc[en[0]], u1Gamma)
	    if betaU1Star[k] == nil {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get betaU1Star fail")}
		ch <- res
		return nil,nil,nil,nil,false
	    }

	    beta1U1StarCipher, u1BetaR1,_ := u1PaillierPk.Encrypt(betaU1Star[k])
	    u1KGamma1Cipher = u1PaillierPk.HomoAdd(u1KGamma1Cipher, beta1U1StarCipher) // send to u1
	    
	    //delete zkfactor,add ntilde h1 h2
	    u1u1MtAZK2Proof := lib.MtAZK2Prove_nhh(u1Gamma, betaU1Star[k], u1BetaR1, ukc[cur_enode],ukc3[cur_enode], zkfactproof[cur_enode])
	    mkg[en[0]] = u1KGamma1Cipher
	    mkg_mtazk2[en[0]] = u1u1MtAZK2Proof
	    continue
	}
	
	u2PaillierPk := GetPaillierPk(save,k)
	if u2PaillierPk == nil {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get paillier pk fail")}
	    ch <- res
	    return nil,nil,nil,nil,false
	}

	u2KGamma1Cipher := u2PaillierPk.HomoMul(ukc[en[0]], u1Gamma)
	if betaU1Star[k] == nil {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get betaU1Star fail")}
	    ch <- res
	    return nil,nil,nil,nil,false
	}

	beta2U1StarCipher, u2BetaR1,_ := u2PaillierPk.Encrypt(betaU1Star[k])
	u2KGamma1Cipher = u2PaillierPk.HomoAdd(u2KGamma1Cipher, beta2U1StarCipher) // send to u2
	u2u1MtAZK2Proof := lib.MtAZK2Prove_nhh(u1Gamma, betaU1Star[k], u2BetaR1, ukc[en[0]],u2PaillierPk,zkfactproof[cur_enode])
	mp := []string{msgprex,cur_enode}
	enode := strings.Join(mp,"-")
	s0 := "MKG"
	s1 := string(u2KGamma1Cipher.Bytes()) 
	//////
	s2 := string(u2u1MtAZK2Proof.Z.Bytes())
	s3 := string(u2u1MtAZK2Proof.ZBar.Bytes())
	s4 := string(u2u1MtAZK2Proof.T.Bytes())
	s5 := string(u2u1MtAZK2Proof.V.Bytes())
	s6 := string(u2u1MtAZK2Proof.W.Bytes())
	s7 := string(u2u1MtAZK2Proof.S.Bytes())
	s8 := string(u2u1MtAZK2Proof.S1.Bytes())
	s9 := string(u2u1MtAZK2Proof.S2.Bytes())
	s10 := string(u2u1MtAZK2Proof.T1.Bytes())
	s11 := string(u2u1MtAZK2Proof.T2.Bytes())
	///////
	ss := enode + Sep + s0 + Sep + s1 + Sep + s2 + Sep + s3 + Sep + s4 + Sep + s5 + Sep + s6 + Sep + s7 + Sep + s8 + Sep + s9 + Sep + s10 + Sep + s11
	SendMsgToPeer(enodes,ss)
    }
    
    // 2.8
    // send c_kw to proper node, MtA(k, w)   zk
    var mkw = make(map[string]*big.Int)
    var mkw_mtazk2 = make(map[string]*lib.MtAZK3Proof_nhh)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1PaillierPk := GetPaillierPk(save,k)
	    if u1PaillierPk == nil {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get paillier pk fail")}
		ch <- res
		return nil,nil,nil,nil,false
	    }

	    u1Kw1Cipher := u1PaillierPk.HomoMul(ukc[en[0]], w1)
	    if vU1Star[k] == nil {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get vU1Star fail")}
		ch <- res
		return nil,nil,nil,nil,false
	    }

	    v1U1StarCipher, u1VR1,_ := u1PaillierPk.Encrypt(vU1Star[k])
	    u1Kw1Cipher = u1PaillierPk.HomoAdd(u1Kw1Cipher, v1U1StarCipher) // send to u1
	    u1u1MtAZK2Proof2 := lib.MtAZK3Prove_nhh(w1, vU1Star[k], u1VR1, ukc[cur_enode], ukc3[cur_enode], zkfactproof[cur_enode]) //Fusion_dcrm question 8
	    mkw[en[0]] = u1Kw1Cipher
	    mkw_mtazk2[en[0]] = u1u1MtAZK2Proof2
	    continue
	}
	
	u2PaillierPk := GetPaillierPk(save,k)
	if u2PaillierPk == nil {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get paillier pk fail")}
	    ch <- res
	    return nil,nil,nil,nil,false
	}

	u2Kw1Cipher := u2PaillierPk.HomoMul(ukc[en[0]], w1)
	if vU1Star[k] == nil {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get vU1Star fail")}
	    ch <- res
	    return nil,nil,nil,nil,false
	}

	v2U1StarCipher, u2VR1,_ := u2PaillierPk.Encrypt(vU1Star[k])
	u2Kw1Cipher = u2PaillierPk.HomoAdd(u2Kw1Cipher,v2U1StarCipher) // send to u2
	u2u1MtAZK2Proof2 := lib.MtAZK3Prove_nhh(w1, vU1Star[k], u2VR1, ukc[en[0]], u2PaillierPk, zkfactproof[cur_enode])

	mp := []string{msgprex,cur_enode}
	enode := strings.Join(mp,"-")
	s0 := "MKW"
	s1 := string(u2Kw1Cipher.Bytes()) 
	//////
	//bug
	s2 := string(u2u1MtAZK2Proof2.Ux.Bytes())
	s3 := string(u2u1MtAZK2Proof2.Uy.Bytes())
	//bug
	s4 := string(u2u1MtAZK2Proof2.Z.Bytes())
	s5 := string(u2u1MtAZK2Proof2.ZBar.Bytes())
	s6 := string(u2u1MtAZK2Proof2.T.Bytes())
	s7 := string(u2u1MtAZK2Proof2.V.Bytes())
	s8 := string(u2u1MtAZK2Proof2.W.Bytes())
	s9 := string(u2u1MtAZK2Proof2.S.Bytes())
	s10 := string(u2u1MtAZK2Proof2.S1.Bytes())
	s11 := string(u2u1MtAZK2Proof2.S2.Bytes())
	s12 := string(u2u1MtAZK2Proof2.T1.Bytes())
	s13 := string(u2u1MtAZK2Proof2.T2.Bytes())
	///////

	ss := enode + Sep + s0 + Sep + s1 + Sep + s2 + Sep + s3 + Sep + s4 + Sep + s5 + Sep + s6 + Sep + s7 + Sep + s8 + Sep + s9 + Sep + s10 + Sep + s11 + Sep + s12 + Sep + s13
	SendMsgToPeer(enodes,ss)
    }

    return mkg,mkg_mtazk2,mkw,mkw_mtazk2,true
}

func ECDSASignVerifyZKGammaW(cointype string,save string,w *RpcReqWorker,idSign sortableIDSSlice,ukc map[string]*big.Int,ukc3 map[string]*lib.PublicKey,zkfactproof map[string]*lib.NtildeH1H2,mkg map[string]*big.Int,mkg_mtazk2 map[string]*lib.MtAZK2Proof_nhh,mkw map[string]*big.Int,mkw_mtazk2 map[string]*lib.MtAZK3Proof_nhh,ch chan interface{}) bool {
    if cointype == "" || save == "" || w == nil || len(idSign) == 0 || len(ukc) == 0 || len(ukc3) == 0 || len(zkfactproof) == 0 || len(mkg) == 0 || len(mkw) == 0 || len(mkg_mtazk2) == 0 || len(mkw_mtazk2) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return false
    }

    // 2.9
    // receive c_kGamma from proper node, MtA(k, gamma)   zk
    _,cherr := GetChannelValue(ch_t,w.bmkg)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetMKGTimeout)}
	ch <- res
	return false
    }

    mkgs := make([]string,ThresHold-1)
    if w.msg_mkg.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllMKGFail)}
	ch <- res
	return false
    }

    itmp := 0
    iter := w.msg_mkg.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	mkgs[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return false
	}
	////////
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range mkgs {
	    mm := strings.Split(v, Sep)
	    if len(mm) < 13 {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_mkg fail")}
		ch <- res
		return false
	    }

	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		kg := new(big.Int).SetBytes([]byte(mm[2]))
		mkg[en[0]] = kg
		
		z := new(big.Int).SetBytes([]byte(mm[3]))
		zbar := new(big.Int).SetBytes([]byte(mm[4]))
		t := new(big.Int).SetBytes([]byte(mm[5]))
		v := new(big.Int).SetBytes([]byte(mm[6]))
		w := new(big.Int).SetBytes([]byte(mm[7]))
		s := new(big.Int).SetBytes([]byte(mm[8]))
		s1 := new(big.Int).SetBytes([]byte(mm[9]))
		s2 := new(big.Int).SetBytes([]byte(mm[10]))
		t1 := new(big.Int).SetBytes([]byte(mm[11]))
		t2 := new(big.Int).SetBytes([]byte(mm[12]))
		mtAZK2Proof := &lib.MtAZK2Proof_nhh{Z: z, ZBar: zbar, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}
		mkg_mtazk2[en[0]] = mtAZK2Proof
		break
	    }
	}
    }

    // 2.10
    // receive c_kw from proper node, MtA(k, w)    zk
    _,cherr = GetChannelValue(ch_t,w.bmkw)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetMKWTimeout)}
	ch <- res
	return false
    }

    mkws := make([]string,ThresHold-1)
    if w.msg_mkw.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllMKWFail)}
	ch <- res
	return false
    }

    itmp = 0
    iter = w.msg_mkw.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	mkws[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return false
	}
	////////
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range mkws {
	    mm := strings.Split(v, Sep)
	    if len(mm) < 15 {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_mkw fail")}
		ch <- res
		return false
	    }

	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		kw := new(big.Int).SetBytes([]byte(mm[2]))
		mkw[en[0]] = kw

		ux := new(big.Int).SetBytes([]byte(mm[3]))
		uy := new(big.Int).SetBytes([]byte(mm[4]))
		z := new(big.Int).SetBytes([]byte(mm[5]))
		zbar := new(big.Int).SetBytes([]byte(mm[6]))
		t := new(big.Int).SetBytes([]byte(mm[7]))
		v := new(big.Int).SetBytes([]byte(mm[8]))
		w := new(big.Int).SetBytes([]byte(mm[9]))
		s := new(big.Int).SetBytes([]byte(mm[10]))
		s1 := new(big.Int).SetBytes([]byte(mm[11]))
		s2 := new(big.Int).SetBytes([]byte(mm[12]))
		t1 := new(big.Int).SetBytes([]byte(mm[13]))
		t2 := new(big.Int).SetBytes([]byte(mm[14]))
		mtAZK2Proof := &lib.MtAZK3Proof_nhh{Ux:ux,Uy:uy,Z: z, ZBar: zbar, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}
		mkw_mtazk2[en[0]] = mtAZK2Proof
		break
	    }
	}
    }
    
    // 2.11 verify zk
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return false
	}

	////////
	en := strings.Split(string(enodes[8:]),"@")
	//bug
	if len(en) == 0 || en[0] == "" || mkg_mtazk2[en[0]] == nil || cur_enode == "" || ukc[cur_enode] == nil || mkg[en[0]] == nil || ukc3[cur_enode] == nil || zkfactproof[en[0]] == nil {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("mkw mtazk2 verify fail.")}
	    ch <- res
	    return false
	}

	//
	//delete zkfactor,add ntilde h1 h2
	rlt111 := mkg_mtazk2[en[0]].MtAZK2Verify_nhh(ukc[cur_enode], mkg[en[0]],ukc3[cur_enode], zkfactproof[en[0]])
	if !rlt111 {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMKGFail)}
	    ch <- res
	    return false
	}

	if len(en) == 0 || en[0] == "" || mkw_mtazk2[en[0]] == nil || cur_enode == "" || ukc[cur_enode] == nil || mkw[en[0]] == nil || ukc3[cur_enode] == nil || zkfactproof[en[0]] == nil {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("mkw mtazk2 verify fail.")}
	    ch <- res
	    return false
	}

	rlt112 := mkw_mtazk2[en[0]].MtAZK3Verify_nhh(ukc[cur_enode], mkw[en[0]], ukc3[cur_enode], zkfactproof[en[0]])
	if !rlt112 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("mkw mtazk2 verify fail.")}
	    ch <- res
	    return false
	}
    }

    return true
}

func GetSelfPrivKey(cointype string,idSign sortableIDSSlice,w *RpcReqWorker,save string,ch chan interface{}) *lib.PrivateKey {
    if cointype == "" || len(idSign) == 0 || w == nil || save == "" {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil 
    }

    // 2.12
    // decrypt c_kGamma to get alpha, MtA(k, gamma)
    // MtA(k, gamma)
    var index int
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return nil
	}
	////////
	if IsCurNode(enodes,cur_enode) {
	    index = k
	    break
	}
    }

    u1PaillierSk := GetPaillierSk(save,index) //get self privkey
    if u1PaillierSk == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get sk fail.")}
	ch <- res
	return nil
    }

    return u1PaillierSk
}

func DecryptCkGamma(cointype string,idSign sortableIDSSlice,w *RpcReqWorker,u1PaillierSk *lib.PrivateKey,mkg map[string]*big.Int,ch chan interface{}) []*big.Int {
    if cointype == "" || len(idSign) == 0 || w == nil || u1PaillierSk == nil || len(mkg) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil
    }

    alpha1 := make([]*big.Int,ThresHold)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return nil
	}

	////////
	en := strings.Split(string(enodes[8:]),"@")
	alpha1U1, _ := u1PaillierSk.Decrypt(mkg[en[0]])
	alpha1[k] = alpha1U1
    }

    return alpha1
}

func DecryptCkW(cointype string,idSign sortableIDSSlice,w *RpcReqWorker,u1PaillierSk *lib.PrivateKey,mkw map[string]*big.Int,ch chan interface{}) []*big.Int {
    if cointype == "" || len(idSign) == 0 || w == nil || u1PaillierSk == nil || len(mkw) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil
    }
    
    // 2.13
    // decrypt c_kw to get u, MtA(k, w)
    // MtA(k, w)
    uu1 := make([]*big.Int,ThresHold)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return nil
	}

	////////
	en := strings.Split(string(enodes[8:]),"@")
	u1U1, _ := u1PaillierSk.Decrypt(mkw[en[0]])
	uu1[k] = u1U1
    }

    return uu1
}

func CalcDelta(alpha1 []*big.Int,betaU1 []*big.Int,ch chan interface{}) *big.Int {
    if len(alpha1) == 0 || len(betaU1) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil
    }

    // 2.14
    // calculate delta, MtA(k, gamma)
    delta1 := alpha1[0]
    for i:=0;i<ThresHold;i++ {
	if i == 0 {
	    continue
	}
	delta1 = new(big.Int).Add(delta1,alpha1[i])
    }
    for i:=0;i<ThresHold;i++ {
	delta1 = new(big.Int).Add(delta1, betaU1[i])
    }

    return delta1
}

func CalcSigma(uu1 []*big.Int,vU1 []*big.Int,ch chan interface{}) *big.Int {
    if len(uu1) == 0 || len(vU1) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil
    }
    
    // 2.15
    // calculate sigma, MtA(k, w)
    sigma1 := uu1[0]
    for i:=0;i<ThresHold;i++ {
	if i == 0 {
	    continue
	}
	sigma1 = new(big.Int).Add(sigma1,uu1[i])
    }
    for i:=0;i<ThresHold;i++ {
	sigma1 = new(big.Int).Add(sigma1, vU1[i])
    }

    return sigma1
}

func ECDSASignRoundFive(msgprex string,cointype string,delta1 *big.Int,idSign sortableIDSSlice,w *RpcReqWorker,ch chan interface{}) *big.Int {
    if cointype == "" || len(idSign) == 0 || w == nil || msgprex == "" || delta1 == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil 
    }

    // 3. Broadcast
    // delta: delta1, delta2, delta3
    var s1 string
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "DELTA1"
    zero,_ := new(big.Int).SetString("0",10)
    if delta1.Cmp(zero) < 0 { //bug
	s1 = "0" + SepDel + string(delta1.Bytes())
    } else {
	s1 = string(delta1.Bytes())
    }
    ss := enode + Sep + s0 + Sep + s1
    SendMsgToDcrmGroup(ss,w.groupid)

    // 1. Receive Broadcast
    // delta: delta1, delta2, delta3
    _,cherr := GetChannelValue(ch_t,w.bdelta1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all delta timeout.")}
	ch <- res
	return nil
    }
    
    var delta1s = make(map[string]*big.Int)
    delta1s[cur_enode] = delta1

    dels := make([]string,ThresHold-1)
    if w.msg_delta1.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all delta fail.")}
	ch <- res
	return nil
    }

    itmp := 0
    iter := w.msg_delta1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	dels[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return nil
	}

	////////
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}

	for _,v := range dels {
	    mm := strings.Split(v, Sep)
	    if len(mm) < 3 {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_delta1 fail.")}
		ch <- res
		return nil
	    }

	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		tmps := strings.Split(mm[2], SepDel)
		if len(tmps) == 2 {
		    del := new(big.Int).SetBytes([]byte(tmps[1]))
		    del = new(big.Int).Sub(zero,del) //bug:-xxxxxxx
		    delta1s[en[0]] = del
		} else {
		    del := new(big.Int).SetBytes([]byte(mm[2]))
		    delta1s[en[0]] = del
		}

		break
	    }
	}
    }
    
    // 2. calculate deltaSum
    var deltaSum *big.Int
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return nil
	}
	////////

	en := strings.Split(string(enodes[8:]),"@")
	deltaSum = delta1s[en[0]]
	break
    }

    for k,id := range idSign {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return nil
	}
	////////

	en := strings.Split(string(enodes[8:]),"@")
	//bug
	if deltaSum == nil || len(en) < 1 || en[0] == "" || delta1s[en[0]] == nil {
	    var ret2 Err
	    ret2.Info = "calc deltaSum error"
	    res := RpcDcrmRes{Ret:"",Err:ret2}
	    ch <- res
	    return nil
	}
	deltaSum = new(big.Int).Add(deltaSum,delta1s[en[0]])
    }
    deltaSum = new(big.Int).Mod(deltaSum, secp256k1.S256().N)

    return deltaSum
}

func ECDSASignRoundSix(msgprex string,u1Gamma *big.Int,commitU1GammaG *lib.Commitment,w *RpcReqWorker,ch chan interface{}) *lib.ZkUProof {
    if msgprex == "" || u1Gamma == nil || commitU1GammaG == nil || w == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil
    }

    u1GammaZKProof := lib.ZkUProve(u1Gamma)

    // 3. Broadcast
    // commitU1GammaG.D, commitU2GammaG.D, commitU3GammaG.D
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "D11"
    dlen := len(commitU1GammaG.D)
    s1 := strconv.Itoa(dlen)

    ss := enode + Sep + s0 + Sep + s1 + Sep
    for _,d := range commitU1GammaG.D {
	ss += string(d.Bytes())
	ss += Sep
    }
    ss += string(u1GammaZKProof.E.Bytes()) + Sep + string(u1GammaZKProof.S.Bytes()) + Sep
    ss = ss + "NULL"
    SendMsgToDcrmGroup(ss,w.groupid)

    // 1. Receive Broadcast
    // commitU1GammaG.D, commitU2GammaG.D, commitU3GammaG.D
    _,cherr := GetChannelValue(ch_t,w.bd11_1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all d11 fail.")}
	ch <- res
	return nil
    }
    
    return u1GammaZKProof
}

func ECDSASignVerifyCommitment(cointype string,w *RpcReqWorker,idSign sortableIDSSlice,commitU1GammaG *lib.Commitment,u1GammaZKProof *lib.ZkUProof,ch chan interface{}) map[string][]*big.Int {
    if cointype == "" || w == nil || len(idSign) == 0 || commitU1GammaG == nil || u1GammaZKProof == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil
    }

    d11s := make([]string,ThresHold-1)
    if w.msg_d11_1.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all d11 fail.")}
	ch <- res
	return nil
    }

    itmp := 0
    iter := w.msg_d11_1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	d11s[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    c11s := make([]string,ThresHold-1)
    if w.msg_c11.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all c11 fail.")}
	ch <- res
	return nil
    }

    itmp = 0
    iter = w.msg_c11.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	c11s[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    // 2. verify and de-commitment to get GammaG
    
    // for all nodes, construct the commitment by the receiving C and D
    var udecom = make(map[string]*lib.Commitment)
    for _,v := range c11s {
	mm := strings.Split(v, Sep)
	if len(mm) < 3 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_c11 fail.")}
	    ch <- res
	    return nil
	}

	prex := mm[0]
	prexs := strings.Split(prex,"-")
	for _,vv := range d11s {
	    mmm := strings.Split(vv, Sep)
	    if len(mmm) < 3 {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_d11 fail.")}
		ch <- res
		return nil
	    }

	    prex2 := mmm[0]
	    prexs2 := strings.Split(prex2,"-")
	    if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
		dlen,_ := strconv.Atoi(mmm[2])
		var gg = make([]*big.Int,0)
		l := 0
		for j:=0;j<dlen;j++ {
		    l++
		    if len(mmm) < (3+l) {
			res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_d11 fail.")}
			ch <- res
			return nil
		    }

		    gg = append(gg,new(big.Int).SetBytes([]byte(mmm[2+l])))
		}

		deCommit := &lib.Commitment{C:new(big.Int).SetBytes([]byte(mm[2])), D:gg}
		udecom[prexs[len(prexs)-1]] = deCommit
		break
	    }
	}
    }

    deCommit_commitU1GammaG := &lib.Commitment{C: commitU1GammaG.C, D: commitU1GammaG.D}
    udecom[cur_enode] = deCommit_commitU1GammaG
    
    var zkuproof = make(map[string]*lib.ZkUProof)
    zkuproof[cur_enode] = u1GammaZKProof 
    for _,vv := range d11s {
	mmm := strings.Split(vv, Sep)
	prex2 := mmm[0]
	prexs2 := strings.Split(prex2,"-")
	dlen,_ := strconv.Atoi(mmm[2])
	e := new(big.Int).SetBytes([]byte(mmm[3+dlen]))
	s := new(big.Int).SetBytes([]byte(mmm[4+dlen]))
	zkuf := &lib.ZkUProof{E: e, S: s}
	zkuproof[prexs2[len(prexs2)-1]] = zkuf
    }

    // for all nodes, verify the commitment
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return nil
	}
	////////
	en := strings.Split(string(enodes[8:]),"@")
	//bug
	if len(en) <= 0 || en[0] == "" {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("verify commit fail.")}
	    ch <- res
	    return nil
	}

	_,exsit := udecom[en[0]]
	if exsit == false {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("verify commit fail.")}
	    ch <- res
	    return nil
	}
	//

	if udecom[en[0]] == nil {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("verify commit fail.")}
	    ch <- res
	    return nil
	}

	if udecom[en[0]].Verify() == false {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("verify commit fail.")}
	    ch <- res
	    return nil
	}
    }

    // for all nodes, de-commitment
    var ug = make(map[string][]*big.Int)
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return nil
	}
	////////

	en := strings.Split(string(enodes[8:]),"@")
	_, u1GammaG := udecom[en[0]].DeCommit()
	ug[en[0]] = u1GammaG
	if lib.ZkUVerify(u1GammaG,zkuproof[en[0]]) == false {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("verify zkuproof fail.")}
	    ch <- res
	    return nil
	}
    }

    return ug
}

func Calc_r(cointype string,w *RpcReqWorker,idSign sortableIDSSlice,ug map[string][]*big.Int,deltaSum *big.Int,ch chan interface{}) (*big.Int,*big.Int) {
    if cointype == "" || w == nil || len(idSign) == 0 || len(ug) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil,nil
    }
    
    // for all nodes, calculate the GammaGSum
    var GammaGSumx *big.Int
    var GammaGSumy *big.Int
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return nil,nil
	}
	////////

	en := strings.Split(string(enodes[8:]),"@")
	GammaGSumx = (ug[en[0]])[0]
	GammaGSumy = (ug[en[0]])[1]
	break
    }

    for k,id := range idSign {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return nil,nil
	}
	////////

	en := strings.Split(string(enodes[8:]),"@")
	GammaGSumx, GammaGSumy = secp256k1.S256().Add(GammaGSumx, GammaGSumy, (ug[en[0]])[0],(ug[en[0]])[1])
    }
	
    // 3. calculate deltaSum^-1 * GammaGSum
    deltaSumInverse := new(big.Int).ModInverse(deltaSum, secp256k1.S256().N)
    deltaGammaGx, deltaGammaGy := secp256k1.S256().ScalarMult(GammaGSumx, GammaGSumy, deltaSumInverse.Bytes())

    // 4. get r = deltaGammaGx
    r := deltaGammaGx

    zero,_ := new(big.Int).SetString("0",10)
    if r.Cmp(zero) == 0 {
//	log.Debug("sign error: r equal zero.")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("r == 0.")}
	ch <- res
	return nil,nil
    }

    return r,deltaGammaGy
}

func CalcUs(mMtA *big.Int,u1K *big.Int,r *big.Int,sigma1 *big.Int) *big.Int {
    mk1 := new(big.Int).Mul(mMtA, u1K)
    rSigma1 := new(big.Int).Mul(r, sigma1)
    us1 := new(big.Int).Add(mk1, rSigma1)
    us1 = new(big.Int).Mod(us1, secp256k1.S256().N)
   
    return us1
}

func ECDSASignRoundSeven(msgprex string,r *big.Int,deltaGammaGy *big.Int,us1 *big.Int,w *RpcReqWorker,ch chan interface{}) (*lib.Commitment,[]string,*big.Int,*big.Int) {
    if msgprex == "" || r == nil || deltaGammaGy == nil || us1 == nil || w == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil,nil,nil,nil
    }

    // *** Round 5A
    l1 := GetRandomIntFromZn(secp256k1.S256().N)
    rho1 := GetRandomIntFromZn(secp256k1.S256().N)

    bigV1x, bigV1y := secp256k1.S256().ScalarMult(r, deltaGammaGy, us1.Bytes())
    l1Gx, l1Gy := secp256k1.S256().ScalarBaseMult(l1.Bytes())
    bigV1x, bigV1y = secp256k1.S256().Add(bigV1x, bigV1y, l1Gx, l1Gy)

    bigA1x, bigA1y := secp256k1.S256().ScalarBaseMult(rho1.Bytes())

    l1rho1 := new(big.Int).Mul(l1, rho1)
    l1rho1 = new(big.Int).Mod(l1rho1, secp256k1.S256().N)
    bigB1x, bigB1y := secp256k1.S256().ScalarBaseMult(l1rho1.Bytes())

    commitBigVAB1 := new(lib.Commitment).Commit(bigV1x, bigV1y, bigA1x, bigA1y, bigB1x, bigB1y)
    
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "CommitBigVAB"
    s1 := string(commitBigVAB1.C.Bytes())
    ss := enode + Sep + s0 + Sep + s1
    SendMsgToDcrmGroup(ss,w.groupid)

    _,cherr := GetChannelValue(ch_t,w.bcommitbigvab)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all CommitBigVAB timeout.")}
	ch <- res
	return nil,nil,nil,nil
    }
    
    commitbigvabs := make([]string,ThresHold-1)
    if w.msg_commitbigvab.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all CommitBigVAB fail.")}
	ch <- res
	return nil,nil,nil,nil
    }

    itmp := 0
    iter := w.msg_commitbigvab.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	commitbigvabs[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    return commitBigVAB1,commitbigvabs,rho1,l1
}

func ECDSASignRoundEight(msgprex string,r *big.Int,deltaGammaGy *big.Int,us1 *big.Int,l1 *big.Int,rho1 *big.Int,w *RpcReqWorker,ch chan interface{},commitBigVAB1 *lib.Commitment) (*lib.ZkABProof,[]string) {
    if msgprex == "" || r == nil || deltaGammaGy == nil || us1 == nil || w == nil || l1 == nil || rho1 == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error")}
	ch <- res
	return nil,nil
    }

    // *** Round 5B
    u1zkABProof := lib.ZkABProve(rho1, l1, us1, []*big.Int{r, deltaGammaGy})
    
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "ZKABPROOF"
    dlen := len(commitBigVAB1.D)
    s1 := strconv.Itoa(dlen)

    ss := enode + Sep + s0 + Sep + s1 + Sep
    for _,d := range commitBigVAB1.D {
	ss += string(d.Bytes())
	ss += Sep
    }
    
    dlen = len(u1zkABProof.Alpha)
    s22 := strconv.Itoa(dlen)
    ss += (s22 + Sep)
    for _,alp := range u1zkABProof.Alpha {
	ss += string(alp.Bytes())
	ss += Sep
    }
    
    dlen = len(u1zkABProof.Beta)
    s3 := strconv.Itoa(dlen)
    ss += (s3 + Sep)
    for _,bet := range u1zkABProof.Beta {
	ss += string(bet.Bytes())
	ss += Sep
    }

    //ss = prex-enode:ZKABPROOF:dlen:d1:d2:...:dl:alplen:a1:a2:....aalp:betlen:b1:b2:...bbet:t:u:NULL
    ss += (string(u1zkABProof.T.Bytes())+Sep+string(u1zkABProof.U.Bytes())+Sep)
    ss = ss + "NULL"
    SendMsgToDcrmGroup(ss,w.groupid)

    _,cherr := GetChannelValue(ch_t,w.bzkabproof)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all ZKABPROOF timeout.")}
	ch <- res
	return nil,nil
    }
    
    zkabproofs := make([]string,ThresHold-1)
    if w.msg_zkabproof.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all ZKABPROOF fail.")}
	ch <- res
	return nil,nil
    }

    itmp := 0
    iter := w.msg_zkabproof.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	zkabproofs[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    return u1zkABProof,zkabproofs
}

func ECDSASignVerifyBigVAB(cointype string,w *RpcReqWorker,commitbigvabs []string,zkabproofs []string,commitBigVAB1 *lib.Commitment,u1zkABProof *lib.ZkABProof,idSign sortableIDSSlice,r *big.Int, deltaGammaGy *big.Int,ch chan interface{}) (map[string]*lib.Commitment,*big.Int,*big.Int) {
    if len(commitbigvabs) == 0 || len(zkabproofs) == 0 || commitBigVAB1 == nil || u1zkABProof == nil || cointype == "" || w == nil || len(idSign) == 0 || r == nil || deltaGammaGy == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error.")}
	ch <- res
	return nil,nil,nil
    }

    var commitbigcom = make(map[string]*lib.Commitment)
    for _,v := range commitbigvabs {
	mm := strings.Split(v, Sep)
	if len(mm) < 3 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_commitbigvab fail.")}
	    ch <- res
	    return nil,nil,nil
	}

	prex := mm[0]
	prexs := strings.Split(prex,"-")
	for _,vv := range zkabproofs {
	    mmm := strings.Split(vv, Sep)
	    if len(mmm) < 3 {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_zkabproof fail.")}
		ch <- res
		return nil,nil,nil
	    }

	    prex2 := mmm[0]
	    prexs2 := strings.Split(prex2,"-")
	    if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
		dlen,_ := strconv.Atoi(mmm[2])
		var gg = make([]*big.Int,0)
		l := 0
		for j:=0;j<dlen;j++ {
		    l++
		    if len(mmm) < (3+l) {
			res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_zkabproof fail.")}
			ch <- res
			return nil,nil,nil
		    }

		    gg = append(gg,new(big.Int).SetBytes([]byte(mmm[2+l])))
		}

		deCommit := &lib.Commitment{C:new(big.Int).SetBytes([]byte(mm[2])), D:gg}
		commitbigcom[prexs[len(prexs)-1]] = deCommit
		break
	    }
	}
    }

    commitbigcom[cur_enode] = commitBigVAB1
    
    var zkabproofmap = make(map[string]*lib.ZkABProof)
    zkabproofmap[cur_enode] = u1zkABProof

    for _,vv := range zkabproofs {
	mmm := strings.Split(vv, Sep)
	prex2 := mmm[0]
	prexs2 := strings.Split(prex2,"-")

	//alpha
	dlen,_ := strconv.Atoi(mmm[2])
	alplen,_ := strconv.Atoi(mmm[3+dlen])
	var alp = make([]*big.Int,0)
	l := 0
	for j:=0;j<alplen;j++ {
	    l++
	    if len(mmm) < (4+dlen+l) {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_zkabproof fail.")}
		ch <- res
		return nil,nil,nil
	    }

	    alp = append(alp,new(big.Int).SetBytes([]byte(mmm[3+dlen+l])))
	}
	
	//beta
	betlen,_ := strconv.Atoi(mmm[3+dlen+1+alplen])
	var bet = make([]*big.Int,0)
	l = 0
	for j:=0;j<betlen;j++ {
	    l++
	    if len(mmm) < (5+dlen+alplen+l) {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_zkabproof fail.")}
		ch <- res
		return nil,nil,nil
	    }

	    bet = append(bet,new(big.Int).SetBytes([]byte(mmm[3+dlen+1+alplen+l])))
	}

	t := new(big.Int).SetBytes([]byte(mmm[3+dlen+1+alplen+1+betlen]))
	u := new(big.Int).SetBytes([]byte(mmm[3+dlen+1+alplen+1+betlen+1]))

	zkABProof := &lib.ZkABProof{Alpha: alp, Beta: bet, T: t, U: u}
	zkabproofmap[prexs2[len(prexs2)-1]] = zkABProof
    }

    var BigVx,BigVy *big.Int
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return nil,nil,nil
	}
	////////

	en := strings.Split(string(enodes[8:]),"@")
	if commitbigcom[en[0]].Verify() == false {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("verify commitbigvab fail.")}
	    ch <- res
	    return nil,nil,nil
	}

	_, BigVAB1 := commitbigcom[en[0]].DeCommit()
	if lib.ZkABVerify([]*big.Int{BigVAB1[2], BigVAB1[3]}, []*big.Int{BigVAB1[4], BigVAB1[5]}, []*big.Int{BigVAB1[0], BigVAB1[1]}, []*big.Int{r, deltaGammaGy}, zkabproofmap[en[0]]) == false {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("verify zkabproof fail.")}
	    ch <- res
	    return nil,nil,nil
	}

	if k == 0 {
	    BigVx = BigVAB1[0]
	    BigVy = BigVAB1[1]
	    continue
	}

	BigVx, BigVy = secp256k1.S256().Add(BigVx, BigVy, BigVAB1[0], BigVAB1[1])
    }

    return commitbigcom,BigVx,BigVy
}

func ECDSASignRoundNine(msgprex string,cointype string,w *RpcReqWorker,idSign sortableIDSSlice,mMtA *big.Int,r *big.Int,pkx *big.Int,pky *big.Int,BigVx *big.Int,BigVy *big.Int,rho1 *big.Int,commitbigcom map[string]*lib.Commitment,l1 *big.Int,ch chan interface{}) ([]string,*lib.Commitment) {
    if len(idSign) == 0 || len(commitbigcom) == 0 || msgprex == "" || w == nil || cointype == "" || mMtA == nil || r == nil || pkx == nil || pky == nil || l1 == nil || rho1 == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error.")}
	ch <- res
	return nil,nil
    }

    minusM := new(big.Int).Mul(big.NewInt(-1), mMtA)
    minusM = new(big.Int).Mod(minusM, secp256k1.S256().N)

    minusR := new(big.Int).Mul(big.NewInt(-1), r)
    minusR = new(big.Int).Mod(minusR, secp256k1.S256().N)

    G_mY_rx, G_mY_ry := secp256k1.S256().ScalarBaseMult(minusM.Bytes())
    Y_rx, Y_ry := secp256k1.S256().ScalarMult(pkx, pky, minusR.Bytes())
    G_mY_rx, G_mY_ry = secp256k1.S256().Add(G_mY_rx, G_mY_ry, Y_rx, Y_ry)

    VAllx, VAlly := secp256k1.S256().Add(G_mY_rx, G_mY_ry, BigVx, BigVy)
    
    // *** Round 5C
    bigU1x, bigU1y := secp256k1.S256().ScalarMult(VAllx, VAlly, rho1.Bytes())
    // bigA23 = bigA2 + bigA3
    var bigT1x,bigT1y *big.Int
    var ind int
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return nil,nil
	}
	////////

	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}

	_, BigVAB1 := commitbigcom[en[0]].DeCommit()
	bigT1x = BigVAB1[2]
	bigT1y = BigVAB1[3]
	ind = k
	break
    }

    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return nil,nil
	}
	////////
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}

	if k == ind {
	    continue
	}

	_, BigVAB1 := commitbigcom[en[0]].DeCommit()
	bigT1x, bigT1y = secp256k1.S256().Add(bigT1x,bigT1y,BigVAB1[2], BigVAB1[3])
    }
    bigT1x, bigT1y = secp256k1.S256().ScalarMult(bigT1x, bigT1y, l1.Bytes())

    commitBigUT1 := new(lib.Commitment).Commit(bigU1x, bigU1y, bigT1x, bigT1y)
    // Broadcast commitBigUT1.C
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "CommitBigUT"
    s1 := string(commitBigUT1.C.Bytes())
    ss := enode + Sep + s0 + Sep + s1
    SendMsgToDcrmGroup(ss,w.groupid)

    _,cherr := GetChannelValue(ch_t,w.bcommitbigut)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all CommitBigUT timeout.")}
	ch <- res
	return nil,nil
    }
    
    commitbiguts := make([]string,ThresHold-1)
    if w.msg_commitbigut.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all CommitBigUT fail.")}
	ch <- res
	return nil,nil
    }

    itmp := 0
    iter := w.msg_commitbigut.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	commitbiguts[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    return commitbiguts,commitBigUT1
}

func ECDSASignRoundTen(msgprex string,commitBigUT1 *lib.Commitment,w *RpcReqWorker,ch chan interface{}) []string {
    if msgprex == "" || commitBigUT1 == nil || w == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error.")}
	ch <- res
	return nil
    }

    // *** Round 5D
    // Broadcast
    // commitBigUT1.D,  commitBigUT2.D,  commitBigUT3.D
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "CommitBigUTD11"
    dlen := len(commitBigUT1.D)
    s1 := strconv.Itoa(dlen)

    ss := enode + Sep + s0 + Sep + s1 + Sep
    for _,d := range commitBigUT1.D {
	ss += string(d.Bytes())
	ss += Sep
    }
    ss = ss + "NULL"
    SendMsgToDcrmGroup(ss,w.groupid)

    _,cherr := GetChannelValue(ch_t,w.bcommitbigutd11)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all CommitBigUTD11 fail.")}
	ch <- res
	return nil
    }

    commitbigutd11s := make([]string,ThresHold-1)
    if w.msg_commitbigutd11.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all CommitBigUTD11 fail.")}
	ch <- res
	return nil
    }

    itmp := 0
    iter := w.msg_commitbigutd11.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	commitbigutd11s[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    return commitbigutd11s
}

func ECDSASignVerifyBigUTCommitment(cointype string,commitbiguts []string,commitbigutd11s []string,commitBigUT1 *lib.Commitment,w *RpcReqWorker,idSign sortableIDSSlice,ch chan interface{},commitbigcom map[string]*lib.Commitment) bool {
    if cointype == "" || len(commitbiguts) == 0 || len(commitbigutd11s) == 0 || commitBigUT1 == nil || w == nil || len(idSign) == 0 || commitbigcom == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error.")}
	ch <- res
	return false
    }

    var commitbigutmap = make(map[string]*lib.Commitment)
    for _,v := range commitbiguts {
	mm := strings.Split(v, Sep)
	if len(mm) < 3 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_commitbigut fail.")}
	    ch <- res
	    return false
	}

	prex := mm[0]
	prexs := strings.Split(prex,"-")
	for _,vv := range commitbigutd11s {
	    mmm := strings.Split(vv, Sep)
	    if len(mmm) < 3 {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_commitbigutd11 fail.")}
		ch <- res
		return false
	    }

	    prex2 := mmm[0]
	    prexs2 := strings.Split(prex2,"-")
	    if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
		dlen,_ := strconv.Atoi(mmm[2])
		var gg = make([]*big.Int,0)
		l := 0
		for j:=0;j<dlen;j++ {
		    l++
		    if len(mmm) < (3+l) {
			res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get msg_commitbigutd11 fail.")}
			ch <- res
			return false
		    }

		    gg = append(gg,new(big.Int).SetBytes([]byte(mmm[2+l])))
		}

		deCommit := &lib.Commitment{C:new(big.Int).SetBytes([]byte(mm[2])), D:gg}
		commitbigutmap[prexs[len(prexs)-1]] = deCommit
		break
	    }
	}
    }

    commitbigutmap[cur_enode] = commitBigUT1 

    var bigTBx,bigTBy *big.Int
    var bigUx,bigUy *big.Int
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return false
	}
	////////

	en := strings.Split(string(enodes[8:]),"@")
	if commitbigutmap[en[0]].Verify() == false {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("verify commit big ut fail.")}
	    ch <- res
	    return false
	}

	_, BigUT1 := commitbigutmap[en[0]].DeCommit()
	_, BigVAB1 := commitbigcom[en[0]].DeCommit()
	if k == 0 {
	    bigTBx = BigUT1[2] 
	    bigTBy = BigUT1[3] 
	    bigUx = BigUT1[0] 
	    bigUy = BigUT1[1] 
	    bigTBx, bigTBy = secp256k1.S256().Add(bigTBx,bigTBy, BigVAB1[4], BigVAB1[5])
	    continue
	}

	bigTBx, bigTBy = secp256k1.S256().Add(bigTBx,bigTBy,BigUT1[2], BigUT1[3])
	bigTBx, bigTBy = secp256k1.S256().Add(bigTBx,bigTBy, BigVAB1[4], BigVAB1[5])
	bigUx, bigUy = secp256k1.S256().Add(bigUx,bigUy,BigUT1[0], BigUT1[1])
    }

    if bigTBx.Cmp(bigUx) != 0 || bigTBy.Cmp(bigUy) != 0 {
	fmt.Println("verify bigTB = BigU fails.")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("verify bigTB = BigU fails.")}
	ch <- res
	return false
    }

    return true
}

func ECDSASignRoundEleven(msgprex string,cointype string,w *RpcReqWorker,idSign sortableIDSSlice,ch chan interface{},us1 *big.Int) map[string]*big.Int {
    if cointype == "" || msgprex == "" || w == nil || len(idSign) == 0 || us1 == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error.")}
	ch <- res
	return nil
    }

    // 4. Broadcast
    // s: s1, s2, s3
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "SS1"
    s1 := string(us1.Bytes())
    ss := enode + Sep + s0 + Sep + s1
    SendMsgToDcrmGroup(ss,w.groupid)

    // 1. Receive Broadcast
    // s: s1, s2, s3
    _,cherr := GetChannelValue(ch_t,w.bss1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get ss1 timeout.")}
	ch <- res
	return nil
    }

    var ss1s = make(map[string]*big.Int)
    ss1s[cur_enode] = us1

    uss1s := make([]string,ThresHold-1)
    if w.msg_ss1.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get ss1 fail.")}
	ch <- res
	return nil
    }

    itmp := 0
    iter := w.msg_ss1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	uss1s[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return nil
	}
	////////
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}

	for _,v := range uss1s {
	    mm := strings.Split(v, Sep)
	    if len(mm) < 3 {
		res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get ss1 fail.")}
		ch <- res
		return nil
	    }

	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		tmp := new(big.Int).SetBytes([]byte(mm[2]))
		ss1s[en[0]] = tmp
		break
	    }
	}
    }

    return ss1s
}

func Calc_s(cointype string,w *RpcReqWorker,idSign sortableIDSSlice,ss1s map[string]*big.Int,ch chan interface{}) *big.Int {
    if cointype == "" || len(idSign) == 0 || w == nil || len(ss1s) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("param error.")}
	ch <- res
	return nil 
    }

    // 2. calculate s
    var s *big.Int
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return nil
	}
	////////

	en := strings.Split(string(enodes[8:]),"@")
	s = ss1s[en[0]]
	break
    }

    for k,id := range idSign {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id,cointype,w.groupid)
	////////bug
	if len(enodes) < 9 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get enodes error")}
	    ch <- res
	    return nil
	}
	////////
	en := strings.Split(string(enodes[8:]),"@")

	//bug
	if s == nil || len(en) == 0 || en[0] == "" || len(ss1s) == 0 || ss1s[en[0]] == nil {
	    fmt.Println("=================================== !!!Sign_ec2,calc s error. !!! =======================================",)
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("calculate s error.")}
	    ch <- res
	    return nil
	}
	//
	s = new(big.Int).Add(s,ss1s[en[0]])
    }

    s = new(big.Int).Mod(s, secp256k1.S256().N) 

    return s
}

//msgprex = hash
//return value is the backup for the dcrm sig
func Sign_ec2(msgprex string,save string,message string,cointype string,pkx *big.Int,pky *big.Int,ch chan interface{},id int) string {
    if id < 0 || id >= len(workers) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("no find worker.")}
	ch <- res
	return ""
    }
    w := workers[id]
    fmt.Println("================ Sign_ec2,Nonce =%s,GroupId = %s =============",msgprex,w.groupid)
    if w.groupid == "" {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get group id fail.")}
	ch <- res
	return ""
    }

    hashBytes, err2 := hex.DecodeString(message)
    if err2 != nil {
	res := RpcDcrmRes{Ret:"",Err:err2}
	ch <- res
	return ""
    }

    mm := strings.Split(save, SepSave)
    if len(mm) == 0 {
	fmt.Println("=============Sign_ec2,get save data fail. Nonce =%s,save = %s,sep = %s ================",msgprex,save,SepSave)
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get save data fail")}
	ch <- res
	return ""
    }

    // [Notes]
    // 1. assume the nodes who take part in the signature generation as follows
    ids := GetIds(cointype,w.groupid)
    idSign := ids[:ThresHold]
    mMtA,_ := new(big.Int).SetString(message,16)

    //*******************!!!Distributed ECDSA Sign Start!!!**********************************

    skU1,w1 := MapPrivKeyShare(cointype,w,idSign,mm[0])
    if skU1 == nil || w1 == nil {
	return ""
    }
    fmt.Println("===================sign,map privkey finish===========================")

    u1K,u1Gamma,commitU1GammaG := ECDSASignRoundOne(msgprex,w,idSign,ch)
    if u1K == nil || u1Gamma == nil || commitU1GammaG == nil {
	return ""
    }
    fmt.Println("===================sign,round one finish===========================")

    ukc,ukc2,ukc3 := ECDSASignPaillierEncrypt(cointype,save,w,idSign,u1K,ch)
    if ukc == nil || ukc2 == nil || ukc3 == nil {
	return ""
    }
    fmt.Println("===================sign,paillier encrypt finish===========================")

    zk1proof,zkfactproof := ECDSASignRoundTwo(msgprex,cointype,save,w,idSign,ch,u1K,ukc2,ukc3)
    if zk1proof == nil || zkfactproof == nil {
	return ""
    }
    fmt.Println("===================sign,round two finish===========================")

    if ECDSASignRoundThree(msgprex,cointype,save,w,idSign,ch,ukc) == false {
	return ""
    }
    fmt.Println("===================sign,round three finish===========================")

    if ECDSASignVerifyZKNtilde(msgprex,cointype,save,w,idSign,ch,ukc,ukc3,zk1proof,zkfactproof) == false {
	return ""
    }
    fmt.Println("===================sign,verify zk ntilde finish===========================")

    betaU1Star,betaU1,vU1Star,vU1 := GetRandomBetaV(PaillierKeyLength)
    fmt.Println("===================sign,get random betaU1Star/vU1Star finish===========================")

    mkg,mkg_mtazk2,mkw,mkw_mtazk2,status := ECDSASignRoundFour(msgprex,cointype,save,w,idSign,ukc,ukc3,zkfactproof,u1Gamma,w1,betaU1Star,vU1Star,ch)
    if status != true {
	return ""
    }
    fmt.Println("===================sign,round four finish===========================")

    if ECDSASignVerifyZKGammaW(cointype,save,w,idSign,ukc,ukc3,zkfactproof,mkg,mkg_mtazk2,mkw,mkw_mtazk2,ch) != true {
	return ""
    }
    fmt.Println("===================sign,verify zk gamma/w finish===========================")

    u1PaillierSk := GetSelfPrivKey(cointype,idSign,w,save,ch)
    if u1PaillierSk == nil {
	return ""
    }
    fmt.Println("===================sign,get self privkey finish===========================")

    alpha1 := DecryptCkGamma(cointype,idSign,w,u1PaillierSk,mkg,ch)
    if alpha1 == nil {
	return ""
    }
    fmt.Println("===================sign,decrypt paillier(k)XGamma finish===========================")

    uu1 := DecryptCkW(cointype,idSign,w,u1PaillierSk,mkw,ch)
    if uu1 == nil {
	return ""
    }
    fmt.Println("===================sign,decrypt paillier(k)Xw1 finish===========================")

    delta1 := CalcDelta(alpha1,betaU1,ch)
    if delta1 == nil {
	return ""
    }
    fmt.Println("===================sign,calc delta finish===========================")

    sigma1 := CalcSigma(uu1,vU1,ch)
    if sigma1 == nil {
	return ""
    }
    fmt.Println("===================sign,calc sigma finish===========================")

    deltaSum := ECDSASignRoundFive(msgprex,cointype,delta1,idSign,w,ch)
    if deltaSum == nil {
	return ""
    }
    fmt.Println("===================sign,round five finish===========================")

    u1GammaZKProof := ECDSASignRoundSix(msgprex,u1Gamma,commitU1GammaG,w,ch)
    if u1GammaZKProof == nil {
	return ""
    }
    fmt.Println("===================sign,round six finish===========================")

    ug := ECDSASignVerifyCommitment(cointype,w,idSign,commitU1GammaG,u1GammaZKProof,ch)
    if ug == nil {
	return ""
    }
    fmt.Println("===================sign,verify commitment finish===========================")

    r,deltaGammaGy := Calc_r(cointype,w,idSign,ug,deltaSum,ch)
    if r == nil || deltaGammaGy == nil {
	return ""
    }
    fmt.Println("===================sign,calc r finish===========================")

    // 5. calculate s
    us1 := CalcUs(mMtA,u1K,r,sigma1)
    fmt.Println("===================sign,calc self s finish===========================")

    commitBigVAB1,commitbigvabs,rho1,l1 := ECDSASignRoundSeven(msgprex,r,deltaGammaGy,us1,w,ch)
    if commitBigVAB1 == nil || commitbigvabs == nil || rho1 == nil || l1 == nil {
	return ""
    }
    fmt.Println("===================sign,round seven finish===========================")

    u1zkABProof,zkabproofs := ECDSASignRoundEight(msgprex,r,deltaGammaGy,us1,l1,rho1,w,ch,commitBigVAB1)
    if u1zkABProof == nil || zkabproofs == nil {
	return ""
    }
    fmt.Println("===================sign,round eight finish===========================")

    commitbigcom,BigVx,BigVy := ECDSASignVerifyBigVAB(cointype,w,commitbigvabs,zkabproofs,commitBigVAB1,u1zkABProof,idSign,r,deltaGammaGy,ch)
    if commitbigcom == nil || BigVx == nil || BigVy == nil {
	return ""
    }
    fmt.Println("===================sign,verify BigVAB finish===========================")

    commitbiguts,commitBigUT1 := ECDSASignRoundNine(msgprex,cointype,w,idSign,mMtA,r,pkx,pky,BigVx,BigVy,rho1,commitbigcom,l1,ch)
    if commitbiguts == nil || commitBigUT1 == nil {
	return ""
    }
    fmt.Println("===================sign,round nine finish===========================")

    commitbigutd11s := ECDSASignRoundTen(msgprex,commitBigUT1,w,ch) 
    if commitbigutd11s == nil {
	return ""
    }
    fmt.Println("===================sign,round ten finish===========================")
    
    if ECDSASignVerifyBigUTCommitment(cointype,commitbiguts,commitbigutd11s,commitBigUT1,w,idSign,ch,commitbigcom) != true {
	return ""
    }
    fmt.Println("===================sign,verify BigUT commitment finish===========================")

    ss1s := ECDSASignRoundEleven(msgprex,cointype,w,idSign,ch,us1)
    if ss1s == nil {
	return ""
    }
    fmt.Println("===================sign,round eleven finish===========================")

    s := Calc_s(cointype,w,idSign,ss1s,ch)
    if s == nil {
	return ""
    }
    fmt.Println("===================sign,calc s finish===========================")

    // 3. justify the s
    bb := false
    halfN := new(big.Int).Div(secp256k1.S256().N, big.NewInt(2))
    if s.Cmp(halfN) > 0 {
	bb = true
	s = new(big.Int).Sub(secp256k1.S256().N, s)
    }

    zero,_ := new(big.Int).SetString("0",10)
    if s.Cmp(zero) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("s == 0.")}
	ch <- res
	return ""
    }
    fmt.Println("===================sign,justify s finish===========================")

    // **[End-Test]  verify signature with MtA
    signature := new(ECDSASignature)
    signature.New()
    signature.SetR(r)
    signature.SetS(s)

    //v
    recid := secp256k1.Get_ecdsa_sign_v(r, deltaGammaGy)
    if cointype == "ETH" && bb {
	recid ^=1
    }
    if cointype == "BTC" && bb {
	recid ^= 1
    }

    ////check v
    ys := secp256k1.S256().Marshal(pkx,pky)
    pubkeyhex := hex.EncodeToString(ys)
    pbhs := []rune(pubkeyhex)
    if string(pbhs[0:2]) == "0x" {
	pubkeyhex = string(pbhs[2:])
    }
    
    rsvBytes1 := append(signature.GetR().Bytes(), signature.GetS().Bytes()...)
    for j := 0; j < 4; j++ {
	rsvBytes2 := append(rsvBytes1, byte(j))
	pkr, e := secp256k1.RecoverPubkey(hashBytes,rsvBytes2)
	pkr2 := hex.EncodeToString(pkr)
	pbhs2 := []rune(pkr2)
	if string(pbhs2[0:2]) == "0x" {
	    pkr2 = string(pbhs2[2:])
	}
	if e == nil && strings.EqualFold(pkr2,pubkeyhex) {
	    recid = j
	    break
	}
    }
    ///// 
    signature.SetRecoveryParam(int32(recid))

    if Verify(signature.GetR(),signature.GetS(),signature.GetRecoveryParam(),message,pkx,pky) == false {
	fmt.Println("===================dcrm sign,verify is false=================")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("sign verify fail.")}
	ch <- res
	return ""
    }
    fmt.Println("===================sign,verify (r,s) finish===========================")

    signature2 := GetSignString(signature.GetR(),signature.GetS(),signature.GetRecoveryParam(),int(signature.GetRecoveryParam()))
    rstring := "========================== r = " + fmt.Sprintf("%v",signature.GetR()) + " ========================="
    sstring := "========================== s = " + fmt.Sprintf("%v",signature.GetS()) + " =========================="
    fmt.Println(rstring)
    fmt.Println(sstring)
    sigstring := "========================== rsv str = " + signature2 + " ==========================="
    fmt.Println(sigstring)
    res := RpcDcrmRes{Ret:signature2,Err:nil}
    ch <- res
    
    //*******************!!!Distributed ECDSA Sign End!!!**********************************
    
    return "" 
}

func GetPaillierPk(save string,index int) *lib.PublicKey {
    if save == "" || index < 0 {
	return nil
    }

    mm := strings.Split(save, SepSave)
    s := 4 + 4*index
    if len(mm) < (s+4) {
	return nil
    }

    l := mm[s]
    n := new(big.Int).SetBytes([]byte(mm[s+1]))
    g := new(big.Int).SetBytes([]byte(mm[s+2]))
    n2 := new(big.Int).SetBytes([]byte(mm[s+3]))
    publicKey := &lib.PublicKey{Length: l, N: n, G: g, N2: n2}
    return publicKey
}

func GetPaillierSk(save string,index int) *lib.PrivateKey {
    publicKey := GetPaillierPk(save,index)
    if publicKey != nil {
	mm := strings.Split(save, SepSave)
	if len(mm) < 4 {
	    return nil
	}

	l := mm[1]
	ll := new(big.Int).SetBytes([]byte(mm[2]))
	uu := new(big.Int).SetBytes([]byte(mm[3]))
	privateKey := &lib.PrivateKey{Length: l, PublicKey: *publicKey, L: ll, U: uu}
	return privateKey
    }

    return nil
}

//paillier question 2,delete zkfactor,add ntilde h1 h2
func GetZkFactProof(save string,index int) *lib.NtildeH1H2 {
    if save == "" || index < 0 {
	fmt.Println("===============GetZkFactProof,get zkfactproof error,save = %s,index = %v ==============",save,index)
	return nil
    }

    mm := strings.Split(save, SepSave)
    s := 4 + 4*NodeCnt + 3*index////????? TODO
    if len(mm) < (s+3) {
	fmt.Println("===============GetZkFactProof,get zkfactproof error,save = %s,index = %v ==============",save,index)
	return nil
    }

    ntilde := new(big.Int).SetBytes([]byte(mm[s]))
    h1 := new(big.Int).SetBytes([]byte(mm[s+1]))
    h2 := new(big.Int).SetBytes([]byte(mm[s+2]))
    zkFactProof := &lib.NtildeH1H2{Ntilde:ntilde,H1: h1, H2: h2}
    return zkFactProof
}

func SendMsgToDcrmGroup(msg string,groupid string) {
    fmt.Println("============SendMsgToDcrmGroup,msg = %s,groupid = %s ==============",msg,groupid)
    _,err := BroadcastInGroupOthers(groupid,msg)
    if err != nil {
	fmt.Println("==============SendMsgToDcrmGroup,broadcast msg to group others fail,error =%v ===================",err)
    }
}

func EncryptMsg (msg string,enodeID string) (string, error) {

    fmt.Println("=============EncryptMsg,KeyFile = %s,enodeID = %s ================",KeyFile,enodeID)

    /////////////////

    hprv, err1 := hex.DecodeString(enodeID)
    if err1 != nil {
	return "",err1
    }

    p := &ecdsa.PublicKey{Curve: crypto.S256(), X: new(big.Int), Y: new(big.Int)}
    half := len(hprv) / 2
    p.X.SetBytes(hprv[:half])
    p.Y.SetBytes(hprv[half:])
    if !p.Curve.IsOnCurve(p.X, p.Y) {
	    return "", fmt.Errorf("id is invalid secp256k1 curve point")
    }

    var cm []byte
    pub := ecies.ImportECDSAPublic(p)
    cm, err := ecies.Encrypt(crand.Reader, pub, []byte(msg), nil, nil)
    if err != nil {
	return "",err
    }

    return string(cm),nil
}

func DecryptMsg (cm string) (string, error) {
    fmt.Println("=============DecryptMsg,KeyFile = %s ================",KeyFile)
    nodeKey, errkey := crypto.LoadECDSA(KeyFile)
    if errkey != nil {
	return "",errkey
    }

    prv := ecies.ImportECDSA(nodeKey)
    var m []byte
    m, err := prv.Decrypt([]byte(cm), nil, nil)
    if err != nil {
	return "",err
    }

    return string(m),nil
}

func SendMsgToPeer(enodes string,msg string) {
    en := strings.Split(string(enodes[8:]),"@")
    cm,err := EncryptMsg(msg,en[0])
    if err != nil {
	fmt.Println("==============SendMsgToPeer,encrypt msg fail,err = %v ===================",err)
	return
    }

    err = SendToPeer(enodes,cm)
    if err != nil {
	fmt.Println("==============SendMsgToPeer,send to peer fail,error =%v ===================",err)
    }
}

type ECDSASignature struct {
	r *big.Int
	s *big.Int
	recoveryParam int32
	roudFiveAborted bool
}

func (this *ECDSASignature) New() {
}

func (this *ECDSASignature) New2(r *big.Int,s *big.Int) {
    this.r = r
    this.s = s
}

func (this *ECDSASignature) New3(r *big.Int,s *big.Int,recoveryParam int32) {
    this.r =r 
    this.s = s
    this.recoveryParam = recoveryParam
}

func Verify2(r *big.Int,s *big.Int,v int32,message string,pkx *big.Int,pky *big.Int) bool {
    z,_ := new(big.Int).SetString(message,16)
    ss := new(big.Int).ModInverse(s,secp256k1.S256().N)
    zz := new(big.Int).Mul(z,ss)
    u1 := new(big.Int).Mod(zz,secp256k1.S256().N)

    zz2 := new(big.Int).Mul(r,ss)
    u2 := new(big.Int).Mod(zz2,secp256k1.S256().N)
    
    if u1.Sign() == -1 {
		u1.Add(u1,secp256k1.S256().P)
    }
    ug := make([]byte, 32)
    ReadBits(u1, ug[:])
    ugx,ugy := secp256k1.KMulG(ug[:])

    if u2.Sign() == -1 {
		u2.Add(u2,secp256k1.S256().P)
	}
    upk := make([]byte, 32)
    ReadBits(u2,upk[:])
    upkx,upky := secp256k1.S256().ScalarMult(pkx,pky,upk[:])

    xxx,_ := secp256k1.S256().Add(ugx,ugy,upkx,upky)
    xR := new(big.Int).Mod(xxx,secp256k1.S256().N)

    if xR.Cmp(r) == 0 {
	errstring := "============= ECDSA Signature Verify Passed! (r,s) is a Valid Signature ================"
	fmt.Println(errstring)
	return true
    }

    errstring := "================ @@ERROR@@@@@@@@@@@@@@@@@@@@@@@@@@@@: ECDSA Signature Verify NOT Passed! (r,s) is a InValid Siganture! ================"
    fmt.Println(errstring)
    return false
}

func (this *ECDSASignature) GetRoudFiveAborted() bool {
    return this.roudFiveAborted
}

func (this *ECDSASignature) SetRoudFiveAborted(roudFiveAborted bool) {
    this.roudFiveAborted = roudFiveAborted
}

func (this *ECDSASignature) GetR() *big.Int {
    return this.r
}

func (this *ECDSASignature) SetR(r *big.Int) {
    this.r = r
}

func (this *ECDSASignature) GetS() *big.Int {
    return this.s
}

func (this *ECDSASignature) SetS(s *big.Int) {
    this.s = s
}

func (this *ECDSASignature) GetRecoveryParam() int32 {
    return this.recoveryParam
}

func (this *ECDSASignature) SetRecoveryParam(recoveryParam int32) {
    this.recoveryParam = recoveryParam
}

func IsCurNode(enodes string,cur string) bool {
    if enodes == "" || cur == "" {
	return false
    }

    s := []rune(enodes)
    en := strings.Split(string(s[8:]),"@")
    if en[0] == cur {
	return true
    }

    return false
}

//commitment question 1,only use sha3-256
func DoubleHash(id string,keytype string) *big.Int {
    // Generate the random num

    // First, hash with the keccak256
    sha3256 := sha3.New256()
    sha3256.Write([]byte(id))
    digestKeccak256 := sha3256.Sum(nil)

    //second, hash with the SHA3-256
    sha3256.Write(digestKeccak256)
    digest := sha3256.Sum(nil)
    // convert the hash ([]byte) to big.Int
    digestBigInt := new(big.Int).SetBytes(digest)
    zero,_ := new(big.Int).SetString("0",10)

    //Fusion_dcrm question 1,check id != 0
    if digestBigInt.Cmp(zero) == 0 {
	sha3256.Write(digest)
	digest = sha3256.Sum(nil)
	digestBigInt = new(big.Int).SetBytes(digest)
    }

    return digestBigInt
}

func GetRandomInt(length int) *big.Int {
	// NewInt allocates and returns a new Int set to x.
	one := big.NewInt(1)
	// Lsh sets z = x << n and returns z.
	maxi := new(big.Int).Lsh(one, uint(length))

	// TODO: Random Seed, need to be replace!!!
	// New returns a new Rand that uses random values from src to generate other random values.
	// NewSource returns a new pseudo-random Source seeded with the given value.
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	// Rand sets z to a pseudo-random number in [0, n) and returns z.
	rndNum := new(big.Int).Rand(rnd, maxi)
	return rndNum
}

func GetRandomIntFromZn(n *big.Int) *big.Int {
	var rndNumZn *big.Int
	zero := big.NewInt(0)

	for {
		rndNumZn = GetRandomInt(n.BitLen())
		if rndNumZn.Cmp(n) < 0 && rndNumZn.Cmp(zero) >= 0 {
			break
		}
	}

	return rndNumZn
}

func Tool_DecimalByteSlice2HexString(DecimalSlice []byte) string {
    var sa = make([]string, 0)
    for _, v := range DecimalSlice {
        sa = append(sa, fmt.Sprintf("%02X", v))
    }
    ss := strings.Join(sa, "")
    return ss
}

// ReadBits encodes the absolute value of bigint as big-endian bytes. Callers must ensure
// that buf has enough space. If buf is too short the result will be incomplete.
func ReadBits(bigint *big.Int, buf []byte) {
	// number of bits in a big.Word
	wordBits := 32 << (uint64(^big.Word(0)) >> 63)
	// number of bytes in a big.Word
	wordBytes := wordBits / 8
	i := len(buf)
	for _, d := range bigint.Bits() {
		for j := 0; j < wordBytes && i > 0; j++ {
			i--
			buf[i] = byte(d)
			d >>= 8
		}
	}
}

func GetSignString(r *big.Int,s *big.Int,v int32,i int) string {
    rr :=  r.Bytes()
    sss :=  s.Bytes()

    //bug
    if len(rr) == 31 && len(sss) == 32 {
	sigs := make([]byte,65)
	sigs[0] = byte(0)
	ReadBits(r,sigs[1:32])
	ReadBits(s,sigs[32:64])
	sigs[64] = byte(i)
	ret := Tool_DecimalByteSlice2HexString(sigs)
	return ret
    }
    if len(rr) == 31 && len(sss) == 31 {
	sigs := make([]byte,65)
	sigs[0] = byte(0)
	sigs[32] = byte(0)
	ReadBits(r,sigs[1:32])
	ReadBits(s,sigs[33:64])
	sigs[64] = byte(i)
	ret := Tool_DecimalByteSlice2HexString(sigs)
	return ret
    }
    if len(rr) == 32 && len(sss) == 31 {
	sigs := make([]byte,65)
	sigs[32] = byte(0)
	ReadBits(r,sigs[0:32])
	ReadBits(s,sigs[33:64])
	sigs[64] = byte(i)
	ret := Tool_DecimalByteSlice2HexString(sigs)
	return ret
    }
    //

    n := len(rr) + len(sss) + 1
    sigs := make([]byte,n)
    ReadBits(r,sigs[0:len(rr)])
    ReadBits(s,sigs[len(rr):len(rr)+len(sss)])

    sigs[len(rr)+len(sss)] = byte(i)
    ret := Tool_DecimalByteSlice2HexString(sigs)

    return ret
}

func Verify(r *big.Int,s *big.Int,v int32,message string,pkx *big.Int,pky *big.Int) bool {
    return Verify2(r,s,v,message,pkx,pky)
}

func GetEnodesByUid(uid *big.Int,cointype string,groupid string) string {
    _,nodes := GetGroup(groupid)
    others := strings.Split(nodes,SepSg)
    for _,v := range others {
	id := DoubleHash(v,cointype)
	if id.Cmp(uid) == 0 {
	    return v
	}
    }

    return ""
}

type sortableIDSSlice []*big.Int

func (s sortableIDSSlice) Len() int {
	return len(s)
}

func (s sortableIDSSlice) Less(i, j int) bool {
	return s[i].Cmp(s[j]) <= 0
}

func (s sortableIDSSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func GetIds(cointype string,groupid string) sortableIDSSlice {
    var ids sortableIDSSlice
    _,nodes := GetGroup(groupid)
    others := strings.Split(nodes,SepSg)
    for _,v := range others {
	uid := DoubleHash(v,cointype)
	ids = append(ids,uid)
    }
    sort.Sort(ids)
    return ids
}

