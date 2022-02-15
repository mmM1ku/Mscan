package brute

import (
	"Mscan/common/util"
	"github.com/gomodule/redigo/redis"
	"github.com/kpango/glg"
	"sync"
	"sync/atomic"
	"time"
)

type Redis struct {
	addr        []string
	thread      int
	wg          *sync.WaitGroup
	Result      util.Result
	ResultSlice []util.Result
	lock        *sync.Mutex
	workerChan  chan struct{}
	Finish      int64
	total       int64
}

func NewRedis(addr []string, thread int, group *sync.WaitGroup, mutex *sync.Mutex) *Redis {
	return &Redis{
		addr:   addr,
		thread: thread,
		wg:     group,
		lock:   mutex,
		Finish: 0,
		total:  int64(len(addr)),
	}
}

func redisCon(addr string) error {
	client, err := redis.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer client.Close()
	return nil
}

func (r *Redis) bruteRedisWorker() {
	r.workerChan = make(chan struct{}, r.thread)
	for _, addr := range r.addr {
		r.wg.Add(1)
		r.workerChan <- struct{}{}
		addr := addr
		go func() {
			if err := redisCon(addr); err == nil {
				r.lock.Lock()
				r.Result.Addr = &addr
				r.Result.User = "空"
				r.Result.Pass = "空"
				r.ResultSlice = append(r.ResultSlice, r.Result)
				r.lock.Unlock()
				glg.Warnf("[+]发现Redis未授权访问：%s", addr)

			} else if err != nil {
				//fmt.Println(err)
			}
			<-r.workerChan
			atomic.AddInt64(&r.Finish, 1)
			r.wg.Done()
		}()
	}
}

func (r *Redis) BruteRedisPool() []util.Result {
	r.wg.Add(2)
	go func() {
		r.bruteRedisWorker()
		r.wg.Done()
	}()
	go func() {
		for {
			if atomic.LoadInt64(&r.Finish) == r.total {
				util.GetProgress(atomic.LoadInt64(&r.Finish), r.total)
				break
			} else {
				util.GetProgress(atomic.LoadInt64(&r.Finish), r.total)
				time.Sleep(1 * time.Second)
			}
		}
		r.wg.Done()
	}()
	r.wg.Wait()
	return r.ResultSlice
}
