package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"math/big"
	"strconv"
	"time"
)

type User struct {
	sk big.Int
	pk twistededwards.PointAffine
}

//func mathMod(n, m int) int {
//	return ((n % m) + m) % m
//}

func mathMod(n, m *big.Int) *big.Int {
	result := new(big.Int).Mod(n, m)
	result.Add(result, m)
	result.Mod(result, m)
	return result
}

func getUser() (User, error) {
	curve := twistededwards.GetEdwardsCurve()
	sk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		return User{}, err
	}
	var pk twistededwards.PointAffine
	pk.ScalarMultiplication(&curve.Base, sk)
	return User{
		sk: *sk,
		pk: pk,
	}, err
}

func hashToScalar(msg []byte) big.Int {
	hash := sha256.New()
	hash.Write(msg)
	hOut := new(big.Int).SetBytes(hash.Sum(nil))
	return *hOut
}

func hashToPoint(msg []byte) twistededwards.PointAffine {
	res := hashToScalar(msg)
	var pt twistededwards.PointAffine
	curve := twistededwards.GetEdwardsCurve()
	pt.ScalarMultiplication(&curve.Base, &res)
	return pt
}

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

// 计算 x 的 n 次方
func pow(x big.Int, n int) big.Int {
	res := big.NewInt(1)
	for i := 0; i < n; i++ {
		res.Mul(res, &x)
	}
	return *res
}

// GetBit 从 i 的二进制左侧第 j 位（填充至 n 位）获取比特值
func getBit(i, n, j int) int {
	if i < 0 {
		panic("仅支持非负整数")
	}
	binStr := strconv.FormatInt(int64(i), 2)
	if len(binStr) < n {
		binStr = fmt.Sprintf("%0*s", n, binStr)
	}
	if j <= 0 || j > len(binStr) {
		return 0
	}
	if binStr[j-1] == '1' {
		return 1
	}
	return 0
}

// 生成随机 *big.Int 数组
func getRandomBigInts(count int) []*big.Int {
	res := make([]*big.Int, count)
	curve := twistededwards.GetEdwardsCurve()
	for i := 0; i < count; i++ {
		res[i], _ = rand.Int(rand.Reader, &curve.Order)
	}
	return res
}

//三个交互式零知识证明协议
//func main() {
//	curve := twistededwards.GetEdwardsCurve()
//
//	// 用户集合
//	N := 32
//	//n := int(math.Ceil(math.Log2(float64(N))))
//	n := 5
//	l := 12 //签名者在环中的下标
//	users := make([]User, N)
//	for i := 0; i < N; i++ {
//		users[i], _ = getUser()
//	}
//	// 监管方
//	rev, _ := getUser()
//	// 公共参数
//	h, _ := randomGenerator()
//	// 消息
//	msg := "test message"
//
//	fmt.Println("msg:	", msg)
//	fmt.Println("N:		", N)
//	fmt.Println("n:		", n)
//	fmt.Println("l:		", l)
//
//	// 1. 一次性标志和监管密文
//	var T, C1, C2 twistededwards.PointAffine
//	E := hashToPoint(users[l].pk.Marshal())
//	T.ScalarMultiplication(&E, &users[l].sk)
//
//	u, _ := rand.Int(rand.Reader, &curve.Order)
//	C1.ScalarMultiplication(&curve.Base, u)
//	C2.ScalarMultiplication(&rev.pk, u)
//	C2.Add(&C2, &users[l].pk)
//
//	// =====================================================================
//	// ============= Protocol 1 ============================================
//	// =====================================================================
//	// 2. 环签名生成
//	// 证明 1
//	// // P1 step 1
//	r := make([]*big.Int, n+1)
//	a := getRandomBigInts(n + 1)
//	s := make([]*big.Int, n+1)
//	t := make([]*big.Int, n+1)
//	rho := make([]*big.Int, n+1)
//	cl := make([]twistededwards.PointAffine, n+1)
//	ca := make([]twistededwards.PointAffine, n+1)
//	cb := make([]twistededwards.PointAffine, n+1)
//	cd := make([]twistededwards.PointAffine, n+1)
//
//	// 生成 pik
//	p := GetPik(N, n, l, a[1:])
//	var ind twistededwards.PointAffine
//
//	// 计算 cl, ca, cb, cd
//	for j := 1; j < n+1; j++ {
//		r[j], _ = rand.Int(rand.Reader, &curve.Order)
//		//a[j], _ = rand.Int(rand.Reader, &curve.Order)
//		s[j], _ = rand.Int(rand.Reader, &curve.Order)
//		t[j], _ = rand.Int(rand.Reader, &curve.Order)
//
//		cl[j].ScalarMultiplication(&curve.Base, r[j])
//		if getBit(l, n, j) == 1 {
//			cl[j].Add(&cl[j], &h)
//		}
//
//		ca[j].ScalarMultiplication(&h, a[j])
//		ind.ScalarMultiplication(&curve.Base, s[j])
//		ca[j].Add(&ca[j], &ind)
//
//		cb[j].ScalarMultiplication(&curve.Base, t[j])
//		if getBit(l, n, j) == 1 {
//			ind.ScalarMultiplication(&h, a[j])
//			cb[j].Add(&cb[j], &ind)
//		}
//
//		k := j - 1
//		rho[k], _ = rand.Int(rand.Reader, &curve.Order)
//		cd[k].ScalarMultiplication(&curve.Base, rho[k])
//
//		for i := 0; i < N; i++ {
//			ind.ScalarMultiplication(&users[i].pk, p[i][k])
//			cd[k].Add(&cd[k], &ind)
//		}
//
//	}
//	// // V1 step 1
//	x, _ := rand.Int(rand.Reader, &curve.Order)
//
//	// // P1 step 2
//	f := make([]big.Int, n+1)
//	za := make([]big.Int, n+1)
//	zb := make([]big.Int, n+1)
//	for j := 1; j < n+1; j++ {
//		if getBit(l, n, j) == 1 {
//			f[j].Add(&f[j], x)
//		}
//		f[j].Add(&f[j], a[j])
//
//		za[j].Mul(r[j], x)
//		za[j].Add(&za[j], s[j])
//
//		zb[j].Sub(x, &f[j])
//		zb[j].Mul(&zb[j], r[j])
//		zb[j].Add(&zb[j], t[j])
//	}
//
//	var zd big.Int
//	sum := big.NewInt(0)
//	for k := 0; k < n; k++ {
//		sumInd := pow(*x, k)
//		sumInd.Mul(&sumInd, rho[k])
//		sum.Add(sum, &sumInd)
//	}
//	xn := pow(*x, n)
//	zd.Mul(&users[l].sk, &xn)
//	zd.Sub(&zd, sum)
//
//	// // V1 step 2
//	for j := 1; j < n+1; j++ {
//		// 分别代表第一个和第二个等式 (0,1) 的左右 (0,1) 元素
//		var ck0_0, ck0_1, ck1_0, ck1_1 twistededwards.PointAffine
//
//		ck0_0.ScalarMultiplication(&cl[j], x)
//		ck0_0.Add(&ck0_0, &ca[j])
//
//		ck0_1.ScalarMultiplication(&h, &f[j])
//		ind.ScalarMultiplication(&curve.Base, &za[j])
//		ck0_1.Add(&ck0_1, &ind)
//
//		ck1_0.ScalarMultiplication(&cl[j], new(big.Int).Sub(x, &f[j]))
//		ck1_0.Add(&ck1_0, &cb[j])
//
//		ck1_1.ScalarMultiplication(&curve.Base, &zb[j])
//	}
//
//	ck2_N := twistededwards.PointAffine{
//		X: curve.Base.X,
//		Y: curve.Base.Y,
//	}
//	ck2_n := twistededwards.PointAffine{
//		X: curve.Base.X,
//		Y: curve.Base.Y,
//	}
//
//	for i := 0; i < N; i++ {
//		fjij := big.NewInt(1)
//		for j := 1; j < n+1; j++ {
//			if getBit(i, n, j) == 1 {
//				fjij.Mul(fjij, &f[j])
//			} else {
//				fjij.Mul(fjij, new(big.Int).Sub(x, &f[j]))
//			}
//		}
//		ind.ScalarMultiplication(&users[i].pk, fjij)
//		ck2_N.Add(&ck2_N, &ind)
//	}
//	for k := 0; k < n; k++ {
//		xk := pow(*x, k)
//		ind.ScalarMultiplication(&cd[k], new(big.Int).Neg(&xk))
//		ck2_n.Add(&ck2_n, &ind)
//	}
//	ind.ScalarMultiplication(&curve.Base, big.NewInt(-1))
//	ck2_N.Add(&ck2_N, &ind)
//	ck2_n.Add(&ck2_n, &ind)
//
//	var ck2_0, ck2_1 twistededwards.PointAffine
//	ck2_0.Add(&ck2_N, &ck2_n)
//	ck2_1.ScalarMultiplication(&curve.Base, &zd)
//	if !ck2_0.Equal(&ck2_1) {
//		fmt.Println("ck2_0 and ck2_1 do not match")
//	} else {
//		fmt.Println("ck2_0 and ck2_1 match")
//	}
//
//	// =====================================================================
//	// ============= Protocol 2 ============================================
//	// =====================================================================
//	// 3. 一次性可链接标志的私钥生成
//
//	// // cdk2 计算
//	cd2 := make([]twistededwards.PointAffine, n)
//	for k := 0; k < n; k++ {
//		cd2[k].ScalarMultiplication(&E, rho[k])
//		for i := 0; i < N; i++ {
//			ind.ScalarMultiplication(&T, p[i][k])
//			cd2[k].Add(&cd2[k], &ind)
//		}
//	}
//
//	// // cdk2 验证
//	cdk2_T := twistededwards.PointAffine{
//		X: curve.Base.X,
//		Y: curve.Base.Y,
//	}
//	cdk2_n := twistededwards.PointAffine{
//		X: curve.Base.X,
//		Y: curve.Base.Y,
//	}
//
//	for i := 0; i < N; i++ {
//		fjij := big.NewInt(1)
//
//		//test := big.NewInt(0)
//		for j := 1; j < n+1; j++ {
//			if getBit(i, n, j) == 1 {
//				fjij.Mul(fjij, &f[j])
//			} else {
//				fjij.Mul(fjij, new(big.Int).Sub(x, &f[j]))
//			}
//
//			var index big.Int
//			xj1 := pow(*x, j-1)
//			index.Mul(&xj1, p[i][j-1])
//		}
//
//		ind.ScalarMultiplication(&T, fjij)
//		cdk2_T.Add(&cdk2_T, &ind)
//	}
//	for k := 0; k < n; k++ {
//		xk := pow(*x, k)
//		ind.ScalarMultiplication(&cd2[k], new(big.Int).Neg(&xk))
//		cdk2_n.Add(&cdk2_n, &ind)
//	}
//
//	ind.ScalarMultiplication(&curve.Base, big.NewInt(-1))
//	cdk2_T.Add(&cdk2_T, &ind)
//	cdk2_n.Add(&cdk2_n, &ind)
//
//	var cdk2_0, cdk2_1 twistededwards.PointAffine
//	cdk2_0.Add(&cdk2_T, &cdk2_n)
//	cdk2_1.ScalarMultiplication(&E, &zd)
//	//fmt.Println("cdk2_0: ", cdk2_0)
//	//fmt.Println("cdk2_1: ", cdk2_1)
//	if !cdk2_0.Equal(&cdk2_1) {
//		fmt.Println("cdk2_0 and cdk2_1 do not match")
//	} else {
//		fmt.Println("cdk2_0 and cdk2_1 match")
//	}
//
//	// =====================================================================
//	// ============= Protocol 3 ============================================
//	// =====================================================================
//	// 4. 密文 C 的知识证明
//	// // 内容生成
//	// a, s, t, message
//	alpha, _ := rand.Int(rand.Reader, &curve.Order)
//	beta, _ := rand.Int(rand.Reader, &curve.Order)
//	gamma, _ := rand.Int(rand.Reader, &curve.Order)
//	m := big.NewInt(0)
//
//	var cAlpha, cBeta twistededwards.PointAffine
//	cAlpha.ScalarMultiplication(&h, alpha)
//	cAlpha.Add(&cAlpha, new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, beta))
//	cBeta.ScalarMultiplication(&h, new(big.Int).Mul(alpha, m))
//	cBeta.Add(&cBeta, new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, gamma))
//
//	var ff, zAlpha, zBeta big.Int
//	ff.Mul(x, m)
//	ff.Add(&ff, alpha)
//	zAlpha.Mul(x, u)
//	zAlpha.Add(&zAlpha, beta)
//	zBeta.Mul(new(big.Int).Sub(x, &ff), u)
//	zBeta.Add(&zBeta, gamma)
//
//	var zd3 big.Int
//	xn3 := pow(*x, n)
//	zd3.Mul(u, &xn3)
//	for k := 0; k < n; k++ {
//		xk := pow(*x, k)
//		zd3.Sub(&zd3, new(big.Int).Mul(rho[k], &xk))
//	}
//
//	// // cdk3 计算
//	c := make([]twistededwards.PointAffine, N)
//	for k := 0; k < N; k++ {
//		c[k].Add(&C2, new(twistededwards.PointAffine).ScalarMultiplication(&users[k].pk, big.NewInt(-1)))
//	}
//	cd3 := make([]twistededwards.PointAffine, n)
//	for k := 0; k < n; k++ {
//		cd3[k].ScalarMultiplication(&rev.pk, rho[k])
//		for i := 0; i < N; i++ {
//			ind.ScalarMultiplication(&c[i], p[i][k])
//			cd3[k].Add(&cd3[k], &ind)
//		}
//	}
//
//	// // 验证
//	var l0, l1, r0, r1 twistededwards.PointAffine
//	l0.ScalarMultiplication(&C1, x)
//	l0.Add(&l0, &cAlpha)
//	r0.ScalarMultiplication(&h, &ff)
//	r0.Add(&r0, new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, &zAlpha))
//
//	l1.ScalarMultiplication(&C1, new(big.Int).Sub(x, &ff))
//	l1.Add(&l1, &cBeta)
//	r1.ScalarMultiplication(&curve.Base, &zBeta)
//
//	if !l0.Equal(&r0) {
//		fmt.Println("l0 is not equal to r0")
//	} else {
//		fmt.Println("l0 is equal to r0")
//	}
//
//	if !l1.Equal(&r1) {
//		fmt.Println("l1 is not equal to r1")
//	} else {
//		fmt.Println("l1 is equal to r1")
//	}
//
//	ck3_N := twistededwards.PointAffine{
//		X: curve.Base.X,
//		Y: curve.Base.Y,
//	}
//	ck3_n := twistededwards.PointAffine{
//		X: curve.Base.X,
//		Y: curve.Base.Y,
//	}
//
//	for i := 0; i < N; i++ {
//		fjij := big.NewInt(1)
//		for j := 1; j < n+1; j++ {
//			if getBit(i, n, j) == 1 {
//				fjij.Mul(fjij, &f[j])
//			} else {
//				fjij.Mul(fjij, new(big.Int).Sub(x, &f[j]))
//			}
//		}
//		ind.ScalarMultiplication(&c[i], fjij)
//		ck3_N.Add(&ck3_N, &ind)
//	}
//	for k := 0; k < n; k++ {
//		xk := pow(*x, k)
//		ind.ScalarMultiplication(&cd3[k], new(big.Int).Neg(&xk))
//		ck3_n.Add(&ck3_n, &ind)
//	}
//	ind.ScalarMultiplication(&curve.Base, big.NewInt(-1))
//	ck3_N.Add(&ck3_N, &ind)
//	ck3_n.Add(&ck3_n, &ind)
//
//	var ck3_0, ck3_1 twistededwards.PointAffine
//	ck3_0.Add(&ck3_N, &ck3_n)
//	ck3_1.ScalarMultiplication(&rev.pk, &zd3)
//	if !ck3_0.Equal(&ck3_1) {
//		fmt.Println("ck3_0 and ck3_1 do not match")
//	} else {
//		fmt.Println("ck3_0 and ck3_1 match")
//	}
//}

// 结合fiat-shamir变换后最终的环签名算法
func main() {

	curve := twistededwards.GetEdwardsCurve()

	//用户集合
	N := 4
	//n := int(math.Ceil(math.Log2(float64(N))))
	n := 2
	l := 1 //签名者所在环中下标
	users := make([]User, N)
	for i := 0; i < N; i++ {
		users[i], _ = getUser()
	}
	// 监管方
	rev, _ := getUser()
	// 公共参数
	h, _ := randomGenerator()
	// 消息
	//msg := "test message"

	//fmt.Println("msg:	", msg)
	fmt.Println("N:		", N)
	fmt.Println("n:		", n)
	fmt.Println("l:		", l)

	// 1. 一次性标志和监管密文
	var T, C1, C2 twistededwards.PointAffine
	E := hashToPoint(users[l].pk.Marshal())
	T.ScalarMultiplication(&E, &users[l].sk)

	u, _ := rand.Int(rand.Reader, &curve.Order)
	fmt.Println("zk: ", &curve.Order)
	C1.ScalarMultiplication(&curve.Base, u)
	C2.ScalarMultiplication(&rev.pk, u)
	C2.Add(&C2, &users[l].pk)

	fmt.Println("环签名开始生成...")
	//2. 环签名生成
	//证明 1
	// P1 step 1
	start1 := time.Now()
	r := make([]*big.Int, n+1)
	a := getRandomBigInts(n + 1)
	s := make([]*big.Int, n+1)
	t := make([]*big.Int, n+1)
	rho := make([]*big.Int, n+1)
	cl := make([]twistededwards.PointAffine, n+1)
	ca := make([]twistededwards.PointAffine, n+1)
	cb := make([]twistededwards.PointAffine, n+1)
	cd := make([]twistededwards.PointAffine, n+1)

	// 生成 pik
	p := GetPik(N, n, l, a[1:])
	var ind twistededwards.PointAffine

	// 计算 cl, ca, cb, cd
	for j := 1; j < n+1; j++ {
		r[j], _ = rand.Int(rand.Reader, &curve.Order)
		//a[j], _ = rand.Int(rand.Reader, &curve.Order)
		s[j], _ = rand.Int(rand.Reader, &curve.Order)
		t[j], _ = rand.Int(rand.Reader, &curve.Order)

		cl[j].ScalarMultiplication(&curve.Base, r[j])
		if getBit(l, n, j) == 1 {
			cl[j].Add(&cl[j], &h)
		}

		ca[j].ScalarMultiplication(&h, a[j])
		ind.ScalarMultiplication(&curve.Base, s[j])
		ca[j].Add(&ca[j], &ind)

		cb[j].ScalarMultiplication(&curve.Base, t[j])
		if getBit(l, n, j) == 1 {
			ind.ScalarMultiplication(&h, a[j])
			cb[j].Add(&cb[j], &ind)
		}

		k := j - 1
		rho[k], _ = rand.Int(rand.Reader, &curve.Order)
		cd[k].ScalarMultiplication(&curve.Base, rho[k])
		for i := 0; i < N; i++ {
			ind.ScalarMultiplication(&users[i].pk, p[i][k])
			cd[k].Add(&cd[k], &ind)
		}
	}
	cd2 := make([]twistededwards.PointAffine, n)
	for k := 0; k < n; k++ {
		cd2[k].ScalarMultiplication(&E, rho[k])
		for i := 0; i < N; i++ {
			ind.ScalarMultiplication(&T, p[i][k])
			cd2[k].Add(&cd2[k], &ind)
		}
	}
	c := make([]twistededwards.PointAffine, N)
	for k := 0; k < N; k++ {
		c[k].Add(&C2, new(twistededwards.PointAffine).ScalarMultiplication(&users[k].pk, big.NewInt(-1)))
	}
	cd3 := make([]twistededwards.PointAffine, n)
	for k := 0; k < n; k++ {
		cd3[k].ScalarMultiplication(&rev.pk, rho[k])
		for i := 0; i < N; i++ {
			ind.ScalarMultiplication(&c[i], p[i][k])
			cd3[k].Add(&cd3[k], &ind)
		}
	}
	alpha, _ := rand.Int(rand.Reader, &curve.Order)
	beta, _ := rand.Int(rand.Reader, &curve.Order)
	gamma, _ := rand.Int(rand.Reader, &curve.Order)
	m := big.NewInt(0)

	var cAlpha, cBeta twistededwards.PointAffine
	cAlpha.ScalarMultiplication(&h, alpha)
	cAlpha.Add(&cAlpha, new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, beta))
	cBeta.ScalarMultiplication(&h, new(big.Int).Mul(alpha, m))
	cBeta.Add(&cBeta, new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, gamma))

	hash := sha256.New()
	hash.Reset()
	hash.Write(curve.Base.Marshal())
	hash.Write(T.Marshal())
	hash.Write(C1.Marshal())
	hash.Write(C2.Marshal())

	x := new(big.Int).SetBytes(hash.Sum(nil))

	// // V1 step 1
	//x, _ := rand.Int(rand.Reader, &curve.Order)

	// // P1 step 2
	f := make([]big.Int, n+1)
	za := make([]big.Int, n+1)
	zb := make([]big.Int, n+1)
	for j := 1; j < n+1; j++ {
		if getBit(l, n, j) == 1 {
			f[j].Add(&f[j], x)
		}
		f[j].Add(&f[j], a[j])

		za[j].Mul(r[j], x)
		za[j].Add(&za[j], s[j])

		zb[j].Sub(x, &f[j])
		zb[j].Mul(&zb[j], r[j])
		zb[j].Add(&zb[j], t[j])
	}

	var zd big.Int
	sum := big.NewInt(0)
	for k := 0; k < n; k++ {
		sumInd := pow(*x, k)
		sumInd.Mul(&sumInd, rho[k])
		sum.Add(sum, &sumInd)
	}
	xn := pow(*x, n)
	zd.Mul(&users[l].sk, &xn)
	zd.Sub(&zd, sum)

	var ff, zAlpha, zBeta big.Int
	ff.Mul(x, m)
	ff.Add(&ff, alpha)
	zAlpha.Mul(x, u)
	zAlpha.Add(&zAlpha, beta)
	zBeta.Mul(new(big.Int).Sub(x, &ff), u)
	zBeta.Add(&zBeta, gamma)

	var zd3 big.Int
	xn3 := pow(*x, n)
	zd3.Mul(u, &xn3)
	for k := 0; k < n; k++ {
		xk := pow(*x, k)
		zd3.Sub(&zd3, new(big.Int).Mul(rho[k], &xk))
	}

	fmt.Println("环签名生成成功...")
	cost := time.Since(start1)
	fmt.Printf("环签名生成时间: %s\n", cost)

	fmt.Println("开始验证环签名...")
	start2 := time.Now()
	count := true
	//验证
	// // V1 step 2
	for j := 1; j < n+1; j++ {
		// 分别代表第一个和第二个等式 (0,1) 的左右 (0,1) 元素
		var ck0_0, ck0_1, ck1_0, ck1_1 twistededwards.PointAffine

		ck0_0.ScalarMultiplication(&cl[j], x)
		ck0_0.Add(&ck0_0, &ca[j])

		ck0_1.ScalarMultiplication(&h, &f[j])
		ind.ScalarMultiplication(&curve.Base, &za[j])
		ck0_1.Add(&ck0_1, &ind)
		if !ck0_0.Equal(&ck0_1) {
			count = false
			fmt.Println("ck0_0 and ck0_1 do not match, j = ", j)
		} else {
			//fmt.Println("ck0_0 and ck0_1 match, j = ", j)
			count = true
		}

		ck1_0.ScalarMultiplication(&cl[j], new(big.Int).Sub(x, &f[j]))
		ck1_0.Add(&ck1_0, &cb[j])

		ck1_1.ScalarMultiplication(&curve.Base, &zb[j])
		if !ck1_0.Equal(&ck1_1) {
			count = false
			fmt.Println("ck1_0 and ck1_1 do not match, j = ", j)
		} else {
			count = true
			//fmt.Println("ck1_0 and ck1_1 match, j = ", j)
		}
	}

	ck2_N := twistededwards.PointAffine{
		X: curve.Base.X,
		Y: curve.Base.Y,
	}
	ck2_n := twistededwards.PointAffine{
		X: curve.Base.X,
		Y: curve.Base.Y,
	}

	for i := 0; i < N; i++ {
		fjij := big.NewInt(1)
		for j := 1; j < n+1; j++ {
			if getBit(i, n, j) == 1 {
				fjij.Mul(fjij, &f[j])
			} else {
				fjij.Mul(fjij, new(big.Int).Sub(x, &f[j]))
			}
		}
		ind.ScalarMultiplication(&users[i].pk, fjij)
		ck2_N.Add(&ck2_N, &ind)
	}
	for k := 0; k < n; k++ {
		xk := pow(*x, k)
		ind.ScalarMultiplication(&cd[k], new(big.Int).Neg(&xk))
		ck2_n.Add(&ck2_n, &ind)
	}
	ind.ScalarMultiplication(&curve.Base, big.NewInt(-1))
	ck2_N.Add(&ck2_N, &ind)
	ck2_n.Add(&ck2_n, &ind)

	var ck2_0, ck2_1 twistededwards.PointAffine
	ck2_0.Add(&ck2_N, &ck2_n)
	ck2_1.ScalarMultiplication(&curve.Base, &zd)
	if !ck2_0.Equal(&ck2_1) {
		count = false
		fmt.Println("ck2_0 and ck2_1 do not match")
	} else {
		count = true
		//fmt.Println("ck2_0 and ck2_1 match")

	}
	// // cdk2 验证
	cdk2_T := twistededwards.PointAffine{
		X: curve.Base.X,
		Y: curve.Base.Y,
	}
	cdk2_n := twistededwards.PointAffine{
		X: curve.Base.X,
		Y: curve.Base.Y,
	}
	for i := 0; i < N; i++ {
		fjij := big.NewInt(1)

		//test := big.NewInt(0)
		for j := 1; j < n+1; j++ {
			if getBit(i, n, j) == 1 {
				fjij.Mul(fjij, &f[j])
			} else {
				fjij.Mul(fjij, new(big.Int).Sub(x, &f[j]))
			}

			var index big.Int
			xj1 := pow(*x, j-1)
			index.Mul(&xj1, p[i][j-1])
		}

		ind.ScalarMultiplication(&T, fjij)
		cdk2_T.Add(&cdk2_T, &ind)
	}
	for k := 0; k < n; k++ {
		xk := pow(*x, k)
		ind.ScalarMultiplication(&cd2[k], new(big.Int).Neg(&xk))
		cdk2_n.Add(&cdk2_n, &ind)
	}

	ind.ScalarMultiplication(&curve.Base, big.NewInt(-1))
	cdk2_T.Add(&cdk2_T, &ind)
	cdk2_n.Add(&cdk2_n, &ind)

	var cdk2_0, cdk2_1 twistededwards.PointAffine
	cdk2_0.Add(&cdk2_T, &cdk2_n)
	cdk2_1.ScalarMultiplication(&E, &zd)
	//fmt.Println("cdk2_0: ", cdk2_0)
	//fmt.Println("cdk2_1: ", cdk2_1)
	if !cdk2_0.Equal(&cdk2_1) {
		count = false
		fmt.Println("cdk2_0 and cdk2_1 do not match")
	} else {
		count = true
		//fmt.Println("cdk2_0 and cdk2_1 match")
	}

	// // 验证
	var l0, l1, r0, r1 twistededwards.PointAffine
	l0.ScalarMultiplication(&C1, x)
	l0.Add(&l0, &cAlpha)
	r0.ScalarMultiplication(&h, &ff)
	r0.Add(&r0, new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, &zAlpha))

	l1.ScalarMultiplication(&C1, new(big.Int).Sub(x, &ff))
	l1.Add(&l1, &cBeta)
	r1.ScalarMultiplication(&curve.Base, &zBeta)

	if !l0.Equal(&r0) {
		count = false
		fmt.Println("l0 is not equal to r0")
	} else {
		count = true
		//fmt.Println("l0 is equal to r0")
	}

	if !l1.Equal(&r1) {
		count = false
		fmt.Println("l1 is not equal to r1")
	} else {
		count = true
		//fmt.Println("l1 is equal to r1")
	}

	ck3_N := twistededwards.PointAffine{
		X: curve.Base.X,
		Y: curve.Base.Y,
	}
	ck3_n := twistededwards.PointAffine{
		X: curve.Base.X,
		Y: curve.Base.Y,
	}

	for i := 0; i < N; i++ {
		fjij := big.NewInt(1)
		for j := 1; j < n+1; j++ {
			if getBit(i, n, j) == 1 {
				fjij.Mul(fjij, &f[j])
			} else {
				fjij.Mul(fjij, new(big.Int).Sub(x, &f[j]))
			}
		}
		ind.ScalarMultiplication(&c[i], fjij)
		ck3_N.Add(&ck3_N, &ind)
	}
	for k := 0; k < n; k++ {
		xk := pow(*x, k)
		ind.ScalarMultiplication(&cd3[k], new(big.Int).Neg(&xk))
		ck3_n.Add(&ck3_n, &ind)
	}
	ind.ScalarMultiplication(&curve.Base, big.NewInt(-1))
	ck3_N.Add(&ck3_N, &ind)
	ck3_n.Add(&ck3_n, &ind)

	var ck3_0, ck3_1 twistededwards.PointAffine
	ck3_0.Add(&ck3_N, &ck3_n)
	ck3_1.ScalarMultiplication(&rev.pk, &zd3)
	if !ck3_0.Equal(&ck3_1) {
		count = false
		fmt.Println("ck3_0 and ck3_1 do not match")
	} else {
		count = true
		//fmt.Println("ck3_0 and ck3_1 match")
	}
	if count {
		fmt.Println("验证成功")
	}
	cost2 := time.Since(start2)
	fmt.Printf("环签名验证时间: %s\n", cost2)
}
