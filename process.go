package main

import "strings"

func process(task workerTask) workerResult {
	var hit bool

	switch task.Probe {
	case "tcp":
		hit = processTcpProbe(task)
		break
	case "http":
		hit = processHttpProbe(task)
		break
	}

	return workerResult{
		Task: task,
		Hit:  hit,
	}
}

func processTcpProbe(task workerTask) bool {
	banner := task.Banner
	fingerHash := task.Finger.MD5

	for _, probe := range task.Finger.TCP_PROBE {
		for _, extractor := range probe.Extractors {
			switch extractor.Type {
			case "word":
				if processWords(banner, extractor.Words) {
					return true
				}
			case "regex":
				if processRegex(fingerHash, banner, extractor.Regex) {
					return true
				}
			}
		}
	}

	return false
}

func processHttpProbe(task workerTask) bool {
	banner := task.Banner
	fingerHash := task.Finger.MD5

	for _, probe := range task.Finger.HTTP_PROBE {
		for _, matcher := range probe.Matchers {
			switch matcher.Type {
			case "favicon":
				if processFavicon(banner, matcher.Hash) {
					return true
				}
			case "word":
				if processWords(banner, matcher.Words) {
					return true
				}
			case "regex":
				if processRegex(fingerHash, banner, matcher.Regex) {
					return true
				}
			}
		}
	}

	return false
}

func processFavicon(banner string, hashes []string) bool {
	for _, hash := range hashes {
		if banner == hash {
			return true
		}
	}

	return false
}

func processWords(banner string, words []string) bool {
	_banner := strings.ToLower(banner)
	for _, word := range words {
		if !strings.Contains(_banner, strings.ToLower(word)) {
			return false
		}
	}

	return true
}

func processRegex(fingerHash, banner string, regex []string) bool {
	for _, re := range regex {
		match, _ := compiledRegexps[fingerHash].FindStringMatch(re)
		if match == nil {
			return false
		}
	}

	return true
}
