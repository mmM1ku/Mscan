package portscan

import (
	"Mscan/common/util"
	"fmt"
	"github.com/kpango/glg"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

func (s *Scan) identifyFinger() {
	var wg = &sync.WaitGroup{}
	for target := range s.targetChan {
		wg.Add(1)
		target := target
		ip := strings.Split(target, ":")[0]
		go func() {
			if strings.Contains(target, ":80") {
				url := "http://" + target
				s.lock.Lock()
				if s.Result[ip].WebInfo[url] == nil {
					s.Result[ip].WebInfo[url] = &util.WebResult{}
				}
				s.Result[ip].WebInfo[url].Finger = make([]string, 0)
				s.lock.Unlock()
				title, status, err := s.defaultClient(ip, url)
				if err == nil {
					s.lock.Lock()
					s.Result[ip].WebInfo[url].Title = title
					s.Result[ip].WebInfo[url].StatusCode = status
					s.lock.Unlock()
				}
			} else if strings.Contains(target, ":443") {
				url := "https://" + target
				s.lock.Lock()
				if s.Result[ip].WebInfo[url] == nil {
					s.Result[ip].WebInfo[url] = &util.WebResult{}
				}
				s.Result[ip].WebInfo[url].Finger = make([]string, 0)
				s.lock.Unlock()
				title, status, err := s.defaultClient(ip, url)
				if err == nil {
					s.lock.Lock()
					s.Result[ip].WebInfo[url].Title = title
					s.Result[ip].WebInfo[url].StatusCode = status
					s.lock.Unlock()
				}
			} else {
				url1 := "http://" + target
				s.lock.Lock()
				if s.Result[ip].WebInfo[url1] == nil {
					s.Result[ip].WebInfo[url1] = &util.WebResult{}
				}
				s.Result[ip].WebInfo[url1].Finger = make([]string, 0)
				s.lock.Unlock()
				title1, status1, err := s.defaultClient(ip, url1)
				if err == nil {
					s.lock.Lock()
					s.Result[ip].WebInfo[url1].Title = title1
					s.Result[ip].WebInfo[url1].StatusCode = status1
					s.lock.Unlock()
				}
				url2 := "https://" + target
				s.lock.Lock()
				if s.Result[ip].WebInfo[url2] == nil {
					s.Result[ip].WebInfo[url2] = &util.WebResult{}
				}
				s.Result[ip].WebInfo[url2].Finger = make([]string, 0)
				s.lock.Unlock()
				title2, status2, err := s.defaultClient(ip, url2)
				if err == nil {
					s.lock.Lock()
					s.Result[ip].WebInfo[url2].Title = title2
					s.Result[ip].WebInfo[url2].StatusCode = status2
					s.lock.Unlock()
				}
			}
			wg.Done()
		}()
	}
	wg.Wait()
	close(s.respData)
}

func (s *Scan) defaultClient(ip, url string) (string, string, error) {
	var respTitle string
	var headers []string
	var respHeaders string
	//var redirectUrl string
	client := util.Client()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	//get statusCode
	respStatusCode := strconv.Itoa(resp.StatusCode)
	//get respBody
	body, _ := ioutil.ReadAll(resp.Body)
	respBody := string(body)
	//get respTitle
	re := regexp.MustCompile("<title>(.*)</title>")
	if len(re.FindStringSubmatch(respBody)) != 0 {
		if re.FindStringSubmatch(respBody)[1] != "" {
			respTitle = re.FindStringSubmatch(respBody)[1]
		} else {
			respTitle = "None"
		}
	} else {
		respTitle = "None"
	}
	//get respHeaders
	for header, values := range resp.Header {
		for _, value := range values {
			headers = append(headers, fmt.Sprintf("%s:%s", header, value))
		}
	}

	for _, header := range headers {
		respHeaders += header + ","
	}
	var res = &util.HttpRes{Target: ip, Url: url, RespTitle: respTitle, RespStatusCode: respStatusCode, RespHeader: respHeaders, RespBody: respBody}
	s.respData <- res
	return respTitle, respStatusCode, nil
}

func (s *Scan) checkFinger() {
	var wg = &sync.WaitGroup{}
	for res := range s.respData {
		wg.Add(1)
		res := res
		go func() {
			for _, finger := range s.defaultFinger {
				//判断header
				if checkHeaders(res.RespHeader, finger.Headers) {
					s.lock.Lock()
					if s.Result[res.Target].WebInfo[res.Url].Finger == nil {
						glg.Error(res.Url, "slice nil")
					} else {
						s.Result[res.Target].WebInfo[res.Url].Finger = append(s.Result[res.Target].WebInfo[res.Url].Finger, finger.Name)
					}
					s.lock.Unlock()
					continue
				}
				if checkBody(res.RespBody, finger.Keyword) {
					s.lock.Lock()
					if s.Result[res.Target].WebInfo[res.Url].Finger == nil {
						glg.Error(res.Url, "slice nil")
					} else {
						s.Result[res.Target].WebInfo[res.Url].Finger = append(s.Result[res.Target].WebInfo[res.Url].Finger, finger.Name)
					}
					s.lock.Unlock()
				}
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
