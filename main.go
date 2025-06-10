package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"math/big"
)

func randomGenerator() (twistededwards.PointAffine, error) {
	curve := twistededwards.GetEdwardsCurve()
	r, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		return twistededwards.PointAffine{}, err
	}
	var randGenerator twistededwards.PointAffine
	randGenerator.ScalarMultiplication(&curve.Base, r)
	return randGenerator, nil
}

func main() {
	// 1. 公共参数
	curve := twistededwards.GetEdwardsCurve()

	// 2. 生成公私钥对
	// 接收方
	sk_r, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	var pk_r twistededwards.PointAffine
	pk_r.ScalarMultiplication(&curve.Base, sk_r)
	// 监管方
	sk_rev, _ := rand.Int(rand.Reader, &curve.Order)
	var pk_rev twistededwards.PointAffine
	pk_rev.ScalarMultiplication(&curve.Base, sk_rev)

	// 3. 生成一次性地址
	r_t, _ := rand.Int(rand.Reader, &curve.Order)
	var Rt, pk_r_rt, ota twistededwards.PointAffine
	Rt.ScalarMultiplication(&curve.Base, r_t)
	pk_r_rt.ScalarMultiplication(&pk_r, r_t)

	hash := sha256.New()
	hash.Write(pk_r_rt.Marshal())
	t := new(big.Int).SetBytes(hash.Sum(nil))
	ota.ScalarMultiplication(&curve.Base, t)
	ota.Add(&ota, &pk_r)

	// 4. 加密接收方地址
	u, _ := rand.Int(rand.Reader, &curve.Order)
	var C1, C2 twistededwards.PointAffine
	C1.ScalarMultiplication(&curve.Base, u)
	C2.ScalarMultiplication(&pk_rev, u)
	C2.Add(&C2, &pk_r)

	// 5. ZkAddrProofGen
	r_u, _ := rand.Int(rand.Reader, &curve.Order)
	r_t, _ = rand.Int(rand.Reader, &curve.Order)
	var Q1, Q2, ind twistededwards.PointAffine
	Q1.ScalarMultiplication(&curve.Base, r_u)
	Q2.ScalarMultiplication(&pk_rev, r_u)
	ind.ScalarMultiplication(&curve.Base, new(big.Int).Neg(r_t))
	Q2.Add(&Q2, &ind)

	hash.Reset()
	hash.Write(curve.Base.Marshal())
	hash.Write(ota.Marshal())
	hash.Write(pk_rev.Marshal())
	hash.Write(C1.Marshal())
	hash.Write(C2.Marshal())
	hash.Write(Q1.Marshal())
	hash.Write(Q2.Marshal())
	hOut := new(big.Int).SetBytes(hash.Sum(nil))

	var w1, wt big.Int
	w1.Mul(hOut, u)
	w1.Add(&w1, r_u)
	wt.Mul(hOut, t)
	wt.Add(&wt, r_t)

	// 6. ZkAddrProofVer
	var Q1_, Q1_ind, Q2_, Q2_ind, Q2_ind1, Q2_ind2 twistededwards.PointAffine
	Q1_.ScalarMultiplication(&curve.Base, &w1)
	Q1_ind.ScalarMultiplication(&C1, new(big.Int).Neg(hOut))
	Q1_.Add(&Q1_, &Q1_ind)

	Q2_ind.ScalarMultiplication(&pk_rev, &w1)
	Q2_ind1.ScalarMultiplication(&curve.Base, new(big.Int).Neg(&wt))
	Q2_ind.Add(&Q2_ind, &Q2_ind1)

	Q2_ind2.Neg(&C2)
	Q2_ind2.Add(&ota, &Q2_ind2)
	Q2_.ScalarMultiplication(&Q2_ind2, hOut)
	Q2_.Add(&Q2_, &Q2_ind)

	hash.Reset()
	hash.Write(curve.Base.Marshal())
	hash.Write(ota.Marshal())
	hash.Write(pk_rev.Marshal())
	hash.Write(C1.Marshal())
	hash.Write(C2.Marshal())
	hash.Write(Q1_.Marshal())
	hash.Write(Q2_.Marshal())
	h_ := new(big.Int).SetBytes(hash.Sum(nil))

	if h_.Cmp(hOut) == 0 {
		fmt.Println("ZKP success!")
	}

	// 7. 一次性地址验证
	// // 随机用户
	sk_u, _ := rand.Int(rand.Reader, &curve.Order)
	var pk_u twistededwards.PointAffine
	pk_u.ScalarMultiplication(&curve.Base, sk_u)
	var Rt_sk_u twistededwards.PointAffine
	Rt_sk_u.ScalarMultiplication(&Rt, sk_u)

	hash.Reset()
	hash.Write(Rt_sk_u.Marshal())
	h_sk_u := new(big.Int).SetBytes(hash.Sum(nil))
	var pku_ twistededwards.PointAffine
	pku_.ScalarMultiplication(&curve.Base, h_sk_u)
	pku_.Add(&pku_, &pk_u)
	if pku_.Equal(&ota) {
		fmt.Println("That's my money :)")
	} else {
		fmt.Println("That's not my money :(")
	}

	// // 交易接收方
	var Rt_sk_r twistededwards.PointAffine
	Rt_sk_r.ScalarMultiplication(&Rt, sk_r)

	hash.Reset()
	hash.Write(Rt_sk_r.Marshal())
	h_sk_r := new(big.Int).SetBytes(hash.Sum(nil))
	var pk_r_ twistededwards.PointAffine
	pk_r_.ScalarMultiplication(&curve.Base, h_sk_r)
	pk_r_.Add(&pk_r_, &pk_r)
	if pk_r_.Equal(&ota) {
		fmt.Println("That's my money :)")
	} else {
		fmt.Println("That's not my money :(")
	}

	// 8. 一次性私钥生成
	var sk_r_ big.Int
	sk_r_.Add(h_sk_r, &sk_r_)

	// 9. 监管恢复算法
	var otaPubKey twistededwards.PointAffine
	otaPubKey.ScalarMultiplication(&C1, new(big.Int).Neg(sk_rev))
	otaPubKey.Add(&C2, &otaPubKey)
	if otaPubKey.Equal(&pk_r) {
		fmt.Println("Recover successfully :)")
	}

	// 10. 交易金额加密算法
	// // 参数初始化
	p1, _ := rand.Int(rand.Reader, &curve.Order)
	p2, _ := rand.Int(rand.Reader, &curve.Order)
	p3, _ := rand.Int(rand.Reader, &curve.Order)
	pu, _ := rand.Int(rand.Reader, &curve.Order)
	var P1, P2, P3, Pu twistededwards.PointAffine
	P1.ScalarMultiplication(&curve.Base, p1)
	P2.ScalarMultiplication(&curve.Base, p2)
	P3.ScalarMultiplication(&curve.Base, p3)
	Pu.ScalarMultiplication(&curve.Base, pu)
	h, _ := randomGenerator()

	// 加密
	r1, _ := rand.Int(rand.Reader, &curve.Order)
	r2, _ := rand.Int(rand.Reader, &curve.Order)
	r3, _ := rand.Int(rand.Reader, &curve.Order)
	m1 := big.NewInt(20)
	m2 := big.NewInt(17)
	m3 := big.NewInt(3)
	var X1, X2, X3, Xu, Y1, Y2, Y3, Yu, YInd twistededwards.PointAffine
	X1.ScalarMultiplication(&P1, r1)
	X2.ScalarMultiplication(&P2, r2)
	X3.ScalarMultiplication(&P3, r3)
	Xu.ScalarMultiplication(&Pu, r2)

	Y1.ScalarMultiplication(&curve.Base, r1)
	YInd.ScalarMultiplication(&h, m1)
	Y1.Add(&Y1, &YInd)

	Y2.ScalarMultiplication(&curve.Base, r2)
	YInd.ScalarMultiplication(&h, m2)
	Y2.Add(&Y2, &YInd)

	Y3.ScalarMultiplication(&curve.Base, r3)
	YInd.ScalarMultiplication(&h, m3)
	Y3.Add(&Y3, &YInd)

	Yu.ScalarMultiplication(&curve.Base, r2)
	YInd.ScalarMultiplication(&h, m2)
	Yu.Add(&Yu, &YInd)

	// 11. 交易金额加密零知识证明算法
	r1_, _ := rand.Int(rand.Reader, &curve.Order)
	r2_, _ := rand.Int(rand.Reader, &curve.Order)
	r3_, _ := rand.Int(rand.Reader, &curve.Order)
	m1_, _ := rand.Int(rand.Reader, &curve.Order)
	m2_, _ := rand.Int(rand.Reader, &curve.Order)
	m3_, _ := rand.Int(rand.Reader, &curve.Order)

	var X1_, X2_, X3_, Xu_, Y1_, Y2_, Y3_, Yu_, YInd_ twistededwards.PointAffine
	X1_.ScalarMultiplication(&P1, r1_)
	X2_.ScalarMultiplication(&P2, r2_)
	X3_.ScalarMultiplication(&P3, r3_)
	Xu_.ScalarMultiplication(&Pu, r2_)

	Y1_.ScalarMultiplication(&curve.Base, r1_)
	YInd_.ScalarMultiplication(&h, m1_)
	Y1_.Add(&Y1_, &YInd_)

	Y2_.ScalarMultiplication(&curve.Base, r2_)
	YInd_.ScalarMultiplication(&h, m2_)
	Y2_.Add(&Y2_, &YInd_)

	Y3_.ScalarMultiplication(&curve.Base, r3_)
	YInd_.ScalarMultiplication(&h, m3_)
	Y3_.Add(&Y3_, &YInd_)

	Yu_.ScalarMultiplication(&curve.Base, r2_)
	YInd_.ScalarMultiplication(&h, m2_)
	Yu_.Add(&Yu_, &YInd_)

	hash.Reset()
	hash.Write(X1.Marshal())
	hash.Write(X2.Marshal())
	hash.Write(X3.Marshal())
	hash.Write(Xu.Marshal())
	hash.Write(Y1.Marshal())
	hash.Write(Y2.Marshal())
	hash.Write(Y3.Marshal())
	hash.Write(Yu.Marshal())
	hash.Write(X1_.Marshal())
	hash.Write(X2_.Marshal())
	hash.Write(X3_.Marshal())
	hash.Write(Xu_.Marshal())
	hash.Write(Y1_.Marshal())
	hash.Write(Y2_.Marshal())
	hash.Write(Y3_.Marshal())
	hash.Write(Yu_.Marshal())
	hOut = new(big.Int).SetBytes(hash.Sum(nil))

	var s1, s2, s3, sm1, sm2, sm3 big.Int
	s1.Mul(hOut, r1)
	s1.Add(&s1, r1_)

	s2.Mul(hOut, r2)
	s2.Add(&s2, r2_)

	s3.Mul(hOut, r3)
	s3.Add(&s3, r3_)

	sm1.Mul(hOut, m1)
	sm1.Add(&sm1, m1_)

	sm2.Mul(hOut, m2)
	sm2.Add(&sm2, m2_)

	sm3.Mul(hOut, m3)
	sm3.Add(&sm3, m3_)

	// 12. 验证
	var X_1_, X_2_, X_3_, X_u_, X_Ind_, Y_1_, Y_2_, Y_3_, Y_u_, Y_Ind_, Y_Ind_1 twistededwards.PointAffine
	X_1_.ScalarMultiplication(&P1, &s1)
	X_Ind_.ScalarMultiplication(&X1, new(big.Int).Neg(hOut))
	X_1_.Add(&X_1_, &X_Ind_)

	X_2_.ScalarMultiplication(&P2, &s2)
	X_Ind_.ScalarMultiplication(&X2, new(big.Int).Neg(hOut))
	X_2_.Add(&X_2_, &X_Ind_)

	X_3_.ScalarMultiplication(&P3, &s3)
	X_Ind_.ScalarMultiplication(&X3, new(big.Int).Neg(hOut))
	X_3_.Add(&X_3_, &X_Ind_)

	X_u_.ScalarMultiplication(&Pu, &s2)
	X_Ind_.ScalarMultiplication(&Xu, new(big.Int).Neg(hOut))
	X_u_.Add(&X_u_, &X_Ind_)

	Y_1_.ScalarMultiplication(&curve.Base, &s1)
	Y_Ind_.ScalarMultiplication(&h, &sm1)
	Y_Ind_1.ScalarMultiplication(&Y1, new(big.Int).Neg(hOut))
	Y_1_.Add(&Y_1_, &Y_Ind_)
	Y_1_.Add(&Y_1_, &Y_Ind_1)

	Y_2_.ScalarMultiplication(&curve.Base, &s2)
	Y_Ind_.ScalarMultiplication(&h, &sm2)
	Y_Ind_1.ScalarMultiplication(&Y2, new(big.Int).Neg(hOut))
	Y_2_.Add(&Y_2_, &Y_Ind_)
	Y_2_.Add(&Y_2_, &Y_Ind_1)

	Y_3_.ScalarMultiplication(&curve.Base, &s3)
	Y_Ind_.ScalarMultiplication(&h, &sm3)
	Y_Ind_1.ScalarMultiplication(&Y3, new(big.Int).Neg(hOut))
	Y_3_.Add(&Y_3_, &Y_Ind_)
	Y_3_.Add(&Y_3_, &Y_Ind_1)

	Y_u_.ScalarMultiplication(&curve.Base, &s2)
	Y_Ind_.ScalarMultiplication(&h, &sm2)
	Y_Ind_1.ScalarMultiplication(&Yu, new(big.Int).Neg(hOut))
	Y_u_.Add(&Y_u_, &Y_Ind_)
	Y_u_.Add(&Y_u_, &Y_Ind_1)

	hash.Reset()
	hash.Write(X1.Marshal())
	hash.Write(X2.Marshal())
	hash.Write(X3.Marshal())
	hash.Write(Xu.Marshal())
	hash.Write(Y1.Marshal())
	hash.Write(Y2.Marshal())
	hash.Write(Y3.Marshal())
	hash.Write(Yu.Marshal())
	hash.Write(X_1_.Marshal())
	hash.Write(X_2_.Marshal())
	hash.Write(X_3_.Marshal())
	hash.Write(X_u_.Marshal())
	hash.Write(Y_1_.Marshal())
	hash.Write(Y_2_.Marshal())
	hash.Write(Y_3_.Marshal())
	hash.Write(Y_u_.Marshal())
	hOut_ := new(big.Int).SetBytes(hash.Sum(nil))
	if hOut_.Cmp(hOut) == 0 {
		fmt.Println("ZKP2 success!")
	}

	// 13. 金额解密
	var hm, hm2 twistededwards.PointAffine
	var p2Inv, puInv big.Int
	// // 交易接收方
	p2Inv.ModInverse(p2, &curve.Order)
	hm.ScalarMultiplication(&X2, new(big.Int).Neg(&p2Inv))
	hm.Add(&hm, &Y2)
	// // 监管方
	puInv.ModInverse(pu, &curve.Order)
	hm2.ScalarMultiplication(&Xu, new(big.Int).Neg(&puInv))
	hm2.Add(&hm2, &Yu)

	var hm2Comp twistededwards.PointAffine
	hm2Comp.ScalarMultiplication(&h, m2)

	if hm2Comp.Equal(&hm) && hm2Comp.Equal(&hm2) {
		fmt.Println("BalanceDec success!")
	}
}
