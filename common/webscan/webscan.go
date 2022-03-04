package webscan

import (
	"Mscan/common/util"
	"bytes"
	jsonvalue "github.com/Andrew-M-C/go.jsonvalue"
	"github.com/PuerkitoBio/goquery"
	"github.com/kpango/glg"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

type Web struct {
	addr               []string
	wg                 *sync.WaitGroup
	lock               *sync.Mutex
	workerChan         chan struct{}
	result             map[string]map[string]interface{}
	webResult          []map[string]interface{}
	fingerResult       map[string]map[string]int
	fingerTask         chan string
	fingerDefaultSlice []util.Finger
	fingerCostumSlice  []util.Finger
}

func NewWebScan(addr []string, wg *sync.WaitGroup, lock *sync.Mutex) *Web {
	return &Web{
		addr: addr,
		wg:   wg,
		lock: lock,
	}
}

func (w *Web) webScanWorker() {
	for _, addr := range w.addr {
		w.wg.Add(2)
		addr := addr
		w.workerChan <- struct{}{}
		go func() {
			if err := w.defaultClient("http", addr); err == nil {

			}
			for _, finger := range w.fingerCostumSlice {
				if err := w.customClient("http", addr, finger); err == nil {
					//
				}
			}
			glg.Logf("[+]%s已完成指纹扫描", "http://"+addr)
			<-w.workerChan
			w.wg.Done()
		}()
		w.workerChan <- struct{}{}
		go func() {
			if err := w.defaultClient("https", addr); err == nil {

			}
			for _, finger := range w.fingerCostumSlice {
				if err := w.customClient("https", addr, finger); err == nil {
					//
				}
			}
			glg.Logf("[+]%s已完成指纹扫描", "https://"+addr)
			<-w.workerChan
			w.wg.Done()
		}()

	}
	w.wg.Wait()
}

func (w *Web) WebScanPool() []map[string]interface{} {
	//初始化协程控制channel
	w.fingerResult = make(map[string]map[string]int)
	w.result = make(map[string]map[string]interface{})
	w.workerChan = make(chan struct{}, 10)
	//获取指纹切片，写入相应slice
	w.getFinger()
	//开始工作
	w.webScanWorker()
	for addr, _ := range w.result {
		w.result[addr]["finger"] = w.fingerResult[addr]
	}
	for addr, value := range w.result {
		var fingerSlice []string
		for finger, _ := range w.result[addr]["finger"].(map[string]int) {
			fingerSlice = append(fingerSlice, finger)
		}
		glg.Infof("[+]Addr: %v, Status: %v, Title: %v, Finger: %v", addr, value["status"], value["title"], fingerSlice)
	}

	return w.webResult
}

//获取指纹
func (w *Web) getFinger() {
	jsonContent := jsonvalue.MustUnmarshalString(WebFinger)
	jsonContent.RangeArray(func(i int, v *jsonvalue.V) bool {
		var fingerCostum, fingerDefault util.Finger
		fingerCostum.ReqHeaders = make(map[string]string)
		fingerCostum.RespHeaders = make(map[string]string)
		fingerDefault.ReqHeaders = make(map[string]string)
		fingerDefault.RespHeaders = make(map[string]string)
		name, _ := v.Get("name")
		path, _ := v.Get("path")
		method, _ := v.Get("request_method")
		reqHeaders, _ := v.Get("request_headers")
		reqData, _ := v.Get("request_data")
		statusCode, _ := v.Get("status_code")
		respHeaders, _ := v.Get("headers")
		keyword, _ := v.Get("keyword")
		faviconHash, _ := v.Get("favicon_hash")
		if path.String() != "/" || method.String() != "get" || reqHeaders.String() != "{}" || reqData.String() != "" {
			//fmt.Printf("name: %s, path:%s\n", name.String(), path.String())
			fingerCostum.Path = path.String()
			fingerCostum.Method = method.String()
			reqHeaders.RangeObjects(func(k string, v *jsonvalue.V) bool {
				fingerCostum.ReqHeaders[k] = v.String()
				return true
			})
			fingerCostum.ReqData = reqData.String()
			fingerCostum.StatusCode = statusCode.Int()
			respHeaders.RangeObjects(func(k string, v *jsonvalue.V) bool {
				fingerCostum.RespHeaders[k] = v.String()
				return true
			})
			keyword.RangeArray(func(i int, v *jsonvalue.V) bool {
				fingerCostum.Keyword = append(fingerCostum.Keyword, v.String())
				return true
			})
			faviconHash.RangeArray(func(i int, v *jsonvalue.V) bool {
				fingerCostum.FaviconHash = append(fingerCostum.FaviconHash, v.String())
				return true
			})
			fingerCostum.Name = name.String()
			w.fingerCostumSlice = append(w.fingerCostumSlice, fingerCostum)
		}
		if path.String() == "/" && method.String() == "get" && reqHeaders.String() == "{}" && reqData.String() == "" {
			fingerDefault.Path = path.String()
			fingerDefault.Method = method.String()
			reqHeaders.RangeObjects(func(k string, v *jsonvalue.V) bool {
				fingerDefault.ReqHeaders[k] = v.String()
				return true
			})
			fingerDefault.ReqData = reqData.String()
			fingerDefault.StatusCode = statusCode.Int()
			respHeaders.RangeObjects(func(k string, v *jsonvalue.V) bool {
				fingerDefault.RespHeaders[k] = v.String()
				return true
			})
			keyword.RangeArray(func(i int, v *jsonvalue.V) bool {
				fingerDefault.Keyword = append(fingerDefault.Keyword, v.String())
				return true
			})
			faviconHash.RangeArray(func(i int, v *jsonvalue.V) bool {
				fingerDefault.FaviconHash = append(fingerDefault.FaviconHash, v.String())
				return true
			})
			fingerDefault.Name = name.String()
			w.fingerDefaultSlice = append(w.fingerDefaultSlice, fingerDefault)
		}
		return true
	})
	glg.Info("[+]指纹资源已加载")
}

//defaultClient
func (w *Web) defaultClient(protocol, addr string) error {
	//var result util.WebResult
	fingerMap := make(map[string]int)
	infoMap := make(map[string]interface{})
	client := util.Client()
	var url = protocol + "://" + addr
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	//req.Header.Set("User-Agent", ua.Random())
	req.Header.Set("Accept", "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resbody := ioutil.NopCloser(bytes.NewReader(body))
	doc, err := goquery.NewDocumentFromReader(resbody)
	if err != nil {
		return err
	}
	bodystr := string(body)
	title := doc.Find("title").Text()
	/*result.Url = url
	result.StatusCode = resp.StatusCode
	result.Title = title*/
	for _, finger := range w.fingerDefaultSlice {
		//w.wg.Add(1)
		finger := finger
		//glg.Infof("[+]开始匹配%s指纹信息", finger.Name)
		go func() {
			statusFlag := false
			var htmlFlag bool
			//判断状态码是否匹配
			if finger.StatusCode != 0 && resp.StatusCode != finger.StatusCode {
				statusFlag = false
			} else {
				statusFlag = true
			}

			//判断返回头是否匹配
			if len(finger.RespHeaders) != 0 {
				for k, v := range finger.RespHeaders {
					if strings.Contains(strings.ToLower(resp.Header.Get(k)), strings.ToLower(v)) {
						htmlFlag = true
						continue
					} else {
						htmlFlag = false
						break
					}
				}

				if statusFlag && htmlFlag {
					w.lock.Lock()
					fingerMap[finger.Name] = 1
					infoMap["url"] = protocol + "://" + addr
					infoMap["status"] = resp.Status
					infoMap["title"] = title
					//result.Finger = append(result.Finger, finger.Name)
					w.lock.Unlock()
					return
				}
			}
			//判断body匹配
			if len(finger.Keyword) != 0 {
				for _, v := range finger.Keyword {
					if strings.Contains(strings.ToLower(bodystr), strings.ToLower(v)) {
						htmlFlag = true
						continue
					} else {
						htmlFlag = false
						break
					}
				}
			}
			//判断favicon的hash是否匹配

			//返回指纹名称
			if statusFlag && htmlFlag {
				w.lock.Lock()
				fingerMap[finger.Name] = 1
				//fmt.Println(infoMap)
				//result.Finger = append(result.Finger, finger.Name)
				w.lock.Unlock()
				return
			}
			//w.wg.Done()
		}()
	}
	w.lock.Lock()
	if len(w.fingerResult[addr]) == 0 {
		w.fingerResult[addr] = fingerMap
	} else {
		for k, v := range fingerMap {
			w.fingerResult[addr][k] = v
		}
	}
	infoMap["url"] = protocol + "://" + addr
	infoMap["status"] = strconv.Itoa(resp.StatusCode)
	infoMap["title"] = title
	if len(w.result[addr]) == 0 {
		w.result[addr] = infoMap
	} else {
		for k, v := range infoMap {
			if v.(string) == "200" {
				continue
			}
			if v.(string) != "" {
				continue
			}
			w.result[addr][k] = v.(string)
		}
	}

	w.lock.Unlock()
	return nil
}

//customClient
func (w *Web) customClient(protocol, addr string, finger util.Finger) error {
	//var result util.WebResult
	fingerMap := make(map[string]int)
	infoMap := make(map[string]interface{})
	//自定义路径
	var url = protocol + "://" + addr + finger.Path
	//fmt.Println(url)
	client := util.Client()
	//自定义方法，请求数据
	req, _ := http.NewRequest(strings.ToUpper(finger.Method), url, nil)
	req.Header.Set("Accept", "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8")
	if len(finger.ReqHeaders) != 0 {
		for k, v := range finger.ReqHeaders {
			req.Header.Set(k, v)
		}
	}
	//发包
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resbody := ioutil.NopCloser(bytes.NewReader(body))
	doc, err := goquery.NewDocumentFromReader(resbody)
	if err != nil {
		return err
	}
	bodystr := string(body)
	title := doc.Find("title").Text()
	/*result.Url = url
	result.StatusCode = resp.StatusCode
	result.Title = title*/
	//开始指纹匹配
	statusFlag := false
	var htmlFlag bool
	//判断状态码是否匹配
	if finger.StatusCode != 0 && resp.StatusCode != finger.StatusCode {
		statusFlag = false
	} else {
		statusFlag = true
	}

	//判断返回头是否匹配
	if len(finger.RespHeaders) != 0 {
		for k, v := range finger.RespHeaders {
			if strings.Contains(strings.ToLower(resp.Header.Get(k)), strings.ToLower(v)) {
				htmlFlag = true
				continue
			} else {
				htmlFlag = false
				break
			}
		}

		if statusFlag && htmlFlag {
			w.lock.Lock()
			fingerMap[finger.Name] = 1
			w.lock.Unlock()

			return nil
		}
	}
	//判断body匹配
	if len(finger.Keyword) != 0 {
		for _, v := range finger.Keyword {
			if strings.Contains(strings.ToLower(bodystr), strings.ToLower(v)) {
				htmlFlag = true
				continue
			} else {
				htmlFlag = false
				break
			}
		}
	}
	if statusFlag && htmlFlag {
		w.lock.Lock()
		fingerMap[finger.Name] = 1
		w.lock.Unlock()

		//return nil
	}
	w.lock.Lock()
	if len(w.fingerResult[addr]) == 0 {
		w.fingerResult[addr] = fingerMap
	} else {
		for k, v := range fingerMap {
			w.fingerResult[addr][k] = v
		}
	}
	infoMap["url"] = protocol + "://" + addr
	infoMap["status"] = strconv.Itoa(resp.StatusCode)
	infoMap["title"] = title

	if len(w.result[addr]) == 0 {
		w.result[addr] = infoMap
	} else {
		for k, v := range infoMap {
			if v.(string) == "200" {
				continue
			}
			if v.(string) != "" {
				continue
			}
			w.result[addr][k] = v.(string)
		}
	}

	w.lock.Unlock()
	return nil
}
