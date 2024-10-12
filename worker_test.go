package main

import (
	"os"
	"testing"
)

func TestStart(t *testing.T) {
	bannerByte, _ := os.ReadFile("banner.txt")
	banner := string(bannerByte)

	go Start()
	AllocateTasks("http", banner)

	// 模拟下发任务
	//for i := 0; i < 10; i++ {
	//	AllocateTasks("http", banner)
	//	time.Sleep(5 * time.Second)
	//}
}
