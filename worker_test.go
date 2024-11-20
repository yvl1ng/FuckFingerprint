package main

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestStart(t *testing.T) {
	go Start()

	// 模拟下发任务
	for {
		startTime := time.Now()
		for i := 0; i < 3; i++ {
			bannerByte, _ := os.ReadFile(fmt.Sprintf("banner_test/banner_%d.txt", i))
			banner := string(bannerByte)
			AllocateTasks("http", banner, string(rune(i)))
		}
		fmt.Printf("指纹匹配用时: %s\n", time.Since(startTime))

		time.Sleep(5 * time.Second)
	}
}
