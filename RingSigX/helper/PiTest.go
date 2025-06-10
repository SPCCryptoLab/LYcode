package main

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

// -------------------- 工具函数 ----------------------

// GetBit 从 i 的二进制左侧第 j 位（填充至 n 位）获取比特值
func GetBit(i, n, j int) int {
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

// TruncateOrPad 将数组调整为 n 长度：过长则低位截断，过短则低位补 0
func TruncateOrPad(arr []int, n int) []int {
	if len(arr) > n {
		return arr[:n]
	} else if len(arr) < n {
		padding := make([]int, n-len(arr))
		return append(arr, padding...)
	}
	return arr
}

// 随机整数生成器
func getRandomInts(min, max, count int) []int {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	res := make([]int, count)
	for i := 0; i < count; i++ {
		res[i] = r.Intn(max-min) + min
	}
	return res
}

// ------------------ 多项式核心逻辑 ------------------

// parseTerm 将 "(x±a)" 或 "(-a)" 等表达式解析为升幂系数数组
func parseTerm(term string) []int {
	term = strings.ReplaceAll(term, " ", "")

	// 去除外层括号（如果有）
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
		val, err := strconv.Atoi(term[idx+1:])
		if err != nil {
			panic("无法转换数字: " + term)
		}
		if sign == "-" {
			val = -val
		}
		return []int{val, 1} // [常数项, x 系数]
	} else {
		val, err := strconv.Atoi(term)
		if err != nil {
			panic("无法转换常数项: " + term)
		}
		return []int{val} // 只有常数项
	}
}

// multiplyPolys 执行多项式乘法，输入输出均为升幂排列
func multiplyPolys(a, b []int) []int {
	result := make([]int, len(a)+len(b)-1)
	for i := range a {
		for j := range b {
			result[i+j] += a[i] * b[j]
		}
	}
	return result
}

// parseAndMultiply 解析项并乘积
func parseAndMultiply(terms []string) []int {
	result := []int{1}
	for _, term := range terms {
		poly := parseTerm(term)
		result = multiplyPolys(result, poly)
	}
	return result
}

// 打印多项式（升幂排列）
func printPolynomial(coeffs []int) {
	for i := len(coeffs) - 1; i >= 0; i-- {
		c := coeffs[i]
		if c == 0 {
			continue
		}
		if i < len(coeffs)-1 {
			if c > 0 {
				fmt.Print(" + ")
			} else {
				fmt.Print(" - ")
				c = -c
			}
		} else if c < 0 {
			fmt.Print("-")
			c = -c
		}
		if i == 0 {
			fmt.Print(c)
		} else if i == 1 {
			if c == 1 {
				fmt.Print("x")
			} else {
				fmt.Printf("%dx", c)
			}
		} else {
			if c == 1 {
				fmt.Printf("x^%d", i)
			} else {
				fmt.Printf("%dx^%d", c, i)
			}
		}
	}
	fmt.Println()
}

func GetPik(N, n, l int) [][]int {
	aRands := getRandomInts(1, 65536, n)
	p := make([][]int, N)
	for i := 0; i < N; i++ {
		p[i] = make([]int, n)
	}
	for i := 0; i < N; i++ {
		xaStr := make([]string, n)
		for j := 0; j < n; j++ {
			i_j := GetBit(i, n, j+1)
			l_j := GetBit(l, n, j+1)
			if i_j == 1 { // \delta x + a_j
				if l_j == 1 { // x + a_j
					xaStr[j] = fmt.Sprintf("(x+%d)", aRands[j])
				} else { // a_j
					xaStr[j] = fmt.Sprintf("(%d)", aRands[j])
				}
			} else { // \delta x - a_j
				if l_j == 0 { // x - a_j
					xaStr[j] = fmt.Sprintf("(x-%d)", aRands[j])
				} else { // -a_j
					xaStr[j] = fmt.Sprintf("(-%d)", aRands[j])
				}
			}
		}
		fmt.Println(xaStr)
		res := parseAndMultiply(xaStr)
		fmt.Println(res)
		res = TruncateOrPad(res, n)
		for j := 0; j < n; j++ {
			p[i][j] = res[j]
		}
	}
	return p
}

func main() {
	// Step 1: 生成 a1, a2, a3 (范围1 ~ 65535)
	rands := getRandomInts(1, 65536, 3)
	a1, a2, a3 := rands[0], rands[1], rands[2]

	// Step 2: 构建表达式
	terms := []string{
		fmt.Sprintf("x-%d", a1),
		fmt.Sprintf("-%d", a2),
		fmt.Sprintf("x+%d", a3),
	}

	fmt.Println("输入多项式项:", terms)

	// Step 3: 解析并计算
	result := parseAndMultiply(terms)

	// Step 4: 输出结果
	fmt.Println("结果系数（按降幂）:", result)

	fmt.Println(GetPik(4, 2, 1))
}
