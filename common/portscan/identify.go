package portscan

import (
	"regexp"
	"strings"
)

func identifyHttp(reply [][]byte) bool {
	for _, rep := range reply {
		check, _ := regexp.Match("^HTTP/\\d.\\d \\d*", rep)
		if check {
			return true
		}
	}
	return false
}

func checkHeaders(respHeader, headerFinger string) bool {
	var result bool
	if headerFinger != "" {
		if strings.Contains(headerFinger, "|") {
			headers := strings.Split(headerFinger, "|")
			for _, header := range headers {
				if strings.Contains(respHeader, header) {
					result = true
				} else {
					result = false
					break
				}
			}
		} else {
			if strings.Contains(respHeader, headerFinger) {
				result = true
			} else {
				result = false
			}
		}
	}
	return result
}

func checkBody(respBody, bodyFinger string) bool {
	var result bool
	if bodyFinger != "" {
		if strings.Contains(bodyFinger, "|") {
			keywords := strings.Split(bodyFinger, "|")
			for _, keyword := range keywords {
				if strings.Contains(respBody, keyword) {
					result = true
				} else {
					result = false
					break
				}
			}
		} else {
			if strings.Contains(respBody, bodyFinger) {
				result = true
			} else {
				result = false
			}
		}
	}
	return result
}

func identifyService(pattern string, reply [][]byte) bool {
	for _, rep := range reply {
		check, _ := regexp.Match(pattern, rep)
		if check {
			return true
		}
	}
	return false
}
