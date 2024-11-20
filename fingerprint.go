package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// Fingerprint 指纹
type Fingerprint struct {
	ID         string      `json:"id"`
	MD5        string      `json:"md5"`
	INFO       Info        `json:"info"`
	TCP_PROBE  []TcpProbe  `json:"tcp"`
	HTTP_PROBE []HttpProbe `json:"http"`
}

// Info 指纹基本信息
type Info struct {
	Name     string   `json:"name"`
	Author   string   `json:"author"`
	Tags     string   `json:"tags"`
	Metadata MetaData `json:"metadata"`
}

// MetaData 指纹元数据，用于关联CPE
type MetaData struct {
	RawCPE  string `json:"raw_cpe"`
	Product string `json:"product"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
	OS      string `json:"operating_system"`
}

// TcpProbe TCP 探针结果匹配
type TcpProbe struct {
	Extractors []Extractor `json:"extractors"`
}

type Extractor struct {
	Type  string   `json:"type"` // word -> words, regex -> regex
	Words []string `json:"words"`
	Regex []string `json:"regex"`
}

// HttpProbe HTTP 探针结果匹配
type HttpProbe struct {
	Matchers []Matcher `json:"matchers"`
}

type Matcher struct {
	Type      string   `json:"type"` // favicon -> hash, word -> words, regex -> regex
	Hash      []string `json:"hash"`
	Words     []string `json:"words"`
	Regex     []string `json:"regex"`
	Condition string   `json:"condition"`
}

func calculateMd5(jsonData any) string {
	data, _ := json.Marshal(jsonData)

	hash := md5.New()
	hash.Write(data)
	md5Hash := hash.Sum(nil)
	md5HashHex := hex.EncodeToString(md5Hash)

	return md5HashHex
}

// 解析更新的指纹到本地（来源：FingerprintHub）
func parseFingerprintsFromFingerprintHub(paths []string) ([]Fingerprint, error) {
	var fingerprints []Fingerprint

	for _, path := range paths {
		var temp []Fingerprint
		rawData, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(rawData, &temp)
		if err != nil {
			return nil, err
		}

		fingerprints = append(fingerprints, temp...)
	}

	for index, fingerprint := range fingerprints {
		fingerprints[index].MD5 = calculateMd5(fingerprint)

		var vendor, product, version string
		if fingerprint.INFO.Metadata.Vendor != "" && fingerprint.INFO.Metadata.Vendor != "00_unknown" {
			vendor = fingerprint.INFO.Metadata.Vendor
		} else {
			vendor = "*"
		}
		if fingerprint.INFO.Metadata.Product != "" && fingerprint.INFO.Metadata.Product != "00_unknown" {
			product = fingerprint.INFO.Metadata.Product
		} else {
			product = "*"
		}
		if fingerprint.INFO.Metadata.Version != "" && fingerprint.INFO.Metadata.Version != "*" {
			version = fingerprint.INFO.Metadata.Version
		} else {
			version = "*"
		}

		fingerprints[index].INFO.Metadata.RawCPE = fmt.Sprintf("cpe:/*:%s:%s:%s:*:*:*", vendor, product, version)
	}

	data, _ := json.Marshal(fingerprints)
	file, _ := os.Create("fingerprints.json")
	_, _ = file.Write(data)

	return fingerprints, nil
}

func parseFingerprints(path string) ([]Fingerprint, error) {
	var fingerprints []Fingerprint
	rawData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(rawData, &fingerprints)
	if err != nil {
		return nil, err
	}

	return fingerprints, nil
}
