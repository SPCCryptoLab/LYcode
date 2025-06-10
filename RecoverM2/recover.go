package main

import (
	"context"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

func main() {
	// 定义曲线参数
	curve := twistededwards.GetEdwardsCurve()

	// 定义基点 G
	G := curve.Base

	// 目标点 P（已知的公钥点），示例值
	var P twistededwards.PointAffine
	P.Set(&G).ScalarMultiplication(&G, big.NewInt(12345678)) // 模拟一个已知私钥 12345678 的点

	// 设置暴力搜索的最大值
	maxVal := int64(100000000) // 10^8

	// 获取 CPU 核心数
	numThreads := runtime.NumCPU()
	fmt.Printf("使用 %d 个 CPU 核心并行搜索\n", numThreads)

	// 开始暴力破解
	start := time.Now()
	privKey := parallelBruteForceFindPrivateKey(G, P, maxVal, numThreads)
	elapsed := time.Since(start)

	// 输出结果
	if privKey.Cmp(big.NewInt(0)) > 0 {
		fmt.Printf("找到私钥: %s\n", privKey.String())
		fmt.Printf("破解耗时: %s\n", elapsed)
	} else {
		fmt.Println("未找到私钥，请增加搜索范围或检查参数！")
	}
}

// parallelBruteForceFindPrivateKey 通过 goroutines 并行暴力破解
func parallelBruteForceFindPrivateKey(G twistededwards.PointAffine, P twistededwards.PointAffine, maxVal int64, numThreads int) *big.Int {
	var wg sync.WaitGroup
	results := make(chan *big.Int, 1) // 用于接收找到的私钥
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 计算每个线程的搜索区间
	chunkSize := maxVal / int64(numThreads)

	for i := 0; i < numThreads; i++ {
		wg.Add(1)
		start := int64(i)*chunkSize + 1
		end := start + chunkSize - 1

		// 处理最后一个 goroutine 的边界情况
		if i == numThreads-1 {
			end = maxVal
		}

		// 启动 goroutine 进行区间搜索
		go func(start, end int64) {
			defer wg.Done()
			findPrivateKeyInRange(ctx, G, P, start, end, results)
		}(start, end)
	}

	// 等待结果或超时
	go func() {
		wg.Wait()
		close(results)
	}()

	// 监听结果或超时
	select {
	case privKey := <-results:
		return privKey
	case <-ctx.Done():
		return big.NewInt(0)
	}
}

// findPrivateKeyInRange 在给定范围内搜索私钥
func findPrivateKeyInRange(ctx context.Context, G twistededwards.PointAffine, P twistededwards.PointAffine, start, end int64, results chan<- *big.Int) {
	var candidate twistededwards.PointAffine
	var k big.Int

	for i := start; i <= end; i++ {
		// 检查是否已经找到私钥，提前退出
		select {
		case <-ctx.Done():
			return
		default:
		}

		k.SetInt64(i)

		// 计算 i * G
		candidate.ScalarMultiplication(&G, &k)

		// 比较 candidate 和 P 是否相等
		if candidate.Equal(&P) {
			fmt.Printf("匹配成功，私钥为：%d\n", i)
			results <- new(big.Int).Set(&k)
			return
		}

		// 每 10^6 次输出一次进度
		if i%1000000 == 0 {
			fmt.Printf("线程 [%d - %d] 进行中，当前尝试: %d\n", start, end, i)
		}
	}
}
