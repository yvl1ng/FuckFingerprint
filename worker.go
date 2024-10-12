package main

import (
	"fmt"
	"github.com/dlclark/regexp2"
	"runtime"
	"sync"
	"time"
)

type workerTask struct {
	ID     int
	Probe  string
	Banner string
	Finger Fingerprint
}

type workerResult struct {
	Task workerTask
	Hit  bool
}

var (
	bufferSize         = 4096
	workerNums         = runtime.NumCPU() * 4
	taskChan           = make(chan workerTask, bufferSize)
	resultChan         = make(chan workerResult, bufferSize)
	compiledRegexps    = make(map[string]*regexp2.Regexp)
	globalFingerprints []Fingerprint
)

func init() {
	var err error
	globalFingerprints, err = parseFingerprints("fingerprints.json")
	if err != nil {
		//panic(fmt.Sprintf("读取指纹文件错误：%+v\n", err))
		return
	}
	fmt.Printf("读取指纹文件成功，共 %d 条\n", len(globalFingerprints))

	// 正则类型的指纹先预编译缓存，避免每次编译的开销
	startTime := time.Now()
	for _, fingerprint := range globalFingerprints {
		for _, tcpProbe := range fingerprint.TCP_PROBE {
			for _, extractor := range tcpProbe.Extractors {
				if extractor.Type == "regex" {
					compiledRegexps[fingerprint.MD5] = regexp2.MustCompile(extractor.Regex[0], 1)
				}
			}
		}

		for _, httpProbe := range fingerprint.HTTP_PROBE {
			for _, matcher := range httpProbe.Matchers {
				if matcher.Type == "regex" {
					compiledRegexps[fingerprint.MD5] = regexp2.MustCompile(matcher.Regex[0], 1)
				}
			}
		}
	}
	elapsedTime := time.Since(startTime)
	fmt.Printf("正则预编译用时: %s\n", elapsedTime)
}

func work(id int, wg *sync.WaitGroup) {
	for task := range taskChan {
		// 处理任务
		result := process(task)

		// 返回结果
		if result.Hit {
			resultChan <- result
		}
	}
	wg.Done()
}

// 创建 worker 等待接收任务
func createWorkers(wg *sync.WaitGroup) {
	for id := 0; id < workerNums; id++ {
		wg.Add(1)
		go work(id, wg)
	}
}

// 收集结果
func collectResult() {
	count := 0
	for result := range resultChan {
		fmt.Printf("%d ==> %+v\n", count, result.Task.Finger)
		count += 1
	}
}

// AllocateTasks 下发任务，每个 worker 负责处理 1 个 banner 和 1 个 fingerprint
func AllocateTasks(probe, banner string) {
	for id, fingerprint := range globalFingerprints {
		taskChan <- workerTask{
			ID:     id,
			Probe:  probe,
			Banner: banner,
			Finger: fingerprint,
		}
	}

	//close(taskChan) // 一批任务下发完成后，不关闭 taskChan ，保持 worker 的活跃状态
}

func Start() {
	wg := &sync.WaitGroup{}

	go createWorkers(wg)
	go collectResult()

	wg.Wait()
}
