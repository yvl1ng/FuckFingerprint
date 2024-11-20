package main

import (
	"strings"
	"time"
)

// TIMEOUT 单个任务的超时时间（毫秒）
const TIMEOUT = 200

func process(task workerTask) {
	switch task.Probe {
	case "tcp":
		processTcpProbe(task)
		break
	case "http":
		processHttpProbe(task)
		break
	}
}

func processTcpProbe(task workerTask) {
	banner := task.Banner
	fingerHash := task.Finger.MD5

	for _, probe := range task.Finger.TCP_PROBE {
		for _, extractor := range probe.Extractors {
			if time.Since(task.StartTime).Milliseconds() > TIMEOUT {
				return
			}

			switch extractor.Type {
			case "word":
				if processWords(banner, extractor.Words, false) {
					ResultChan <- WorkerResult{Task: task}
				}
			case "regex":
				if processRegex(fingerHash, banner, extractor.Regex, false) {
					ResultChan <- WorkerResult{Task: task}
				}
			}
		}
	}
}

func processHttpProbe(task workerTask) {
	banner := task.Banner
	fingerHash := task.Finger.MD5

	for _, probe := range task.Finger.HTTP_PROBE {
		for _, matcher := range probe.Matchers {
			if time.Since(task.StartTime).Milliseconds() > TIMEOUT {
				return
			}

			var strict bool
			if matcher.Condition == "and" {
				strict = true
			} else {
				strict = false
			}

			switch matcher.Type {
			case "favicon":
				if processFavicon(banner, matcher.Hash) {
					ResultChan <- WorkerResult{Task: task}
				}
				break
			case "word":
				if processWords(banner, matcher.Words, strict) {
					ResultChan <- WorkerResult{Task: task}
				}
				break
			case "regex":
				if processRegex(fingerHash, banner, matcher.Regex, strict) {
					ResultChan <- WorkerResult{Task: task}
				}
				break
			}
		}
	}
}

func processFavicon(banner string, hashes []string) bool {
	for _, hash := range hashes {
		if banner == hash {
			return true
		}
	}

	return false
}

func processWords(banner string, words []string, strict bool) bool {
	if strict {
		for _, word := range words {
			if !strings.Contains(banner, strings.ToLower(word)) {
				return false
			}
		}
		return true
	} else {
		for _, word := range words {
			if strings.Contains(banner, strings.ToLower(word)) {
				return true
			}
		}
		return false
	}
}

func processRegex(fingerHash, banner string, regex []string, strict bool) bool {
	if strict {
		for _, re := range regex {
			match, _ := compiledRegexps[fingerHash].FindStringMatch(re)
			if match == nil {
				return false
			}
		}
		return true
	} else {
		for _, re := range regex {
			match, _ := compiledRegexps[fingerHash].FindStringMatch(re)
			if match != nil {
				return true
			}
		}
		return false
	}
}
