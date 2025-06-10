package main

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// -------------------- 工具函数 ----------------------

// GetBit 从 i 的二进制左侧第 j 位（填充至 n 位）获取比特值
func GetBit(i, n, j int) int {
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

// truncateOrPadBig 将 []*big.Int 数组补齐或截断为指定长度
func truncateOrPadBig(arr []*big.Int, n int) []*big.Int {
	if len(arr) > n {
		return arr[:n]
	} else if len(arr) < n {
		padding := make([]*big.Int, n-len(arr))
		for i := range padding {
			padding[i] = big.NewInt(0)
		}
		return append(arr, padding...)
	}
	return arr
}

// ------------------ 多项式核心逻辑 ------------------

// parseTermBig 解析 "(x±a)" 或 "(-a)" 为 []*big.Int 升幂系数数组
func parseTermBig(term string) []*big.Int {
	term = strings.ReplaceAll(term, " ", "")
	if strings.HasPrefix(term, "(") && strings.HasSuffix(term, ")") {
		term = term[1 : len(term)-1]
	}

	if strings.HasPrefix(term, "x") {
		idx := strings.IndexAny(term[1:], "+-")
		if idx == -1 {
			panic("格式错误: " + term)
		}
		idx += 1
		sign := term[idx : idx+1]
		valStr := term[idx+1:]

		val := new(big.Int)
		val.SetString(valStr, 10)
		if sign == "-" {
			val.Neg(val)
		}
		return []*big.Int{val, big.NewInt(1)}
	} else {
		val := new(big.Int)
		val.SetString(term, 10)
		return []*big.Int{val}
	}
}

// multiplyPolysBig 执行 *big.Int 多项式乘法
func multiplyPolysBig(a, b []*big.Int) []*big.Int {
	result := make([]*big.Int, len(a)+len(b)-1)
	for i := range result {
		result[i] = big.NewInt(0)
	}
	for i := range a {
		for j := range b {
			temp := new(big.Int).Mul(a[i], b[j])
			result[i+j].Add(result[i+j], temp)
		}
	}
	return result
}

// parseAndMultiplyBig 将项数组解析并乘积
func parseAndMultiplyBig(terms []string) []*big.Int {
	result := []*big.Int{big.NewInt(1)}
	for _, term := range terms {
		poly := parseTermBig(term)
		result = multiplyPolysBig(result, poly)
	}
	return result
}

// ------------------ 主函数 ------------------

func GetPik(N, n, l int, aRands []*big.Int) [][]*big.Int {
	p := make([][]*big.Int, N)
	for i := 0; i < N; i++ {
		p[i] = make([]*big.Int, n)
	}
	for i := 0; i < N; i++ {
		xaStr := make([]string, n)
		for j := 0; j < n; j++ {
			i_j := GetBit(i, n, j+1)
			l_j := GetBit(l, n, j+1)
			if i_j == 1 {
				if l_j == 1 {
					xaStr[j] = fmt.Sprintf("(x+%s)", aRands[j].String())
				} else {
					xaStr[j] = fmt.Sprintf("(%s)", aRands[j].String())
				}
			} else {
				if l_j == 0 {
					xaStr[j] = fmt.Sprintf("(x-%s)", aRands[j].String())
				} else {
					xaStr[j] = fmt.Sprintf("(-%s)", aRands[j].String())
				}
			}
		}
		res := parseAndMultiplyBig(xaStr)
		res = truncateOrPadBig(res, n)
		for j := 0; j < n; j++ {
			p[i][j] = res[j]
		}
	}
	return p
}
