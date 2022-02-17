package brute

import (
	"Mscan/common/util"
	"context"
	"fmt"
	"github.com/kpango/glg"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"sync"
	"sync/atomic"
	"time"
)

type Mongo struct {
	addr        []string
	thread      int
	wg          *sync.WaitGroup
	Result      util.Result
	ResultSlice []util.Result
	lock        *sync.Mutex
	workerChan  chan struct{}
	Finish      int64
	total       int64
	dicchan     *chan string
	userdic     *[]string
	passdic     *[]string
}

func NewMongo(addr []string, thread int, group *sync.WaitGroup, mutex *sync.Mutex, userdic, passdic *[]string, dicchan *chan string) *Mongo {
	return &Mongo{
		addr:    addr,
		thread:  thread,
		wg:      group,
		lock:    mutex,
		Finish:  0,
		total:   int64(len(addr)),
		userdic: userdic,
		passdic: passdic,
		dicchan: dicchan,
	}
}

func MongoUnauthCon(addr string) error {
	dataSource := fmt.Sprintf("mongodb://%v", addr)
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(dataSource))
	if err != nil {
		return err
	}
	defer func() {
		if err = client.Disconnect(context.TODO()); err != nil {
			glg.Error(err)
		}
	}()
	if err := client.Ping(context.TODO(), readpref.Primary()); err != nil {
		return err
	}
	return nil
}

func (m *Mongo) bruteMongoWorker() {
	m.workerChan = make(chan struct{}, m.thread)
	for _, addr := range m.addr {
		m.wg.Add(1)
		m.workerChan <- struct{}{}
		addr := addr
		go func() {
			if err := MongoUnauthCon(addr); err == nil {
				glg.Warnf("[+]发现弱口令：%v/%v, %s", "空", "空", addr)
				m.lock.Lock()
				m.Result.Addr = &addr
				m.Result.User = "空"
				m.Result.Pass = "空"
				m.ResultSlice = append(m.ResultSlice, m.Result)
				m.lock.Unlock()
			}
			atomic.AddInt64(&m.Finish, 1)
			m.wg.Done()
			<-m.workerChan
		}()
	}

}

func (m *Mongo) BruteMongoPool() []util.Result {
	m.wg.Add(3)
	go func() {
		MakeDic(m.userdic, m.passdic, m.dicchan)
		m.wg.Done()
	}()
	go func() {
		m.bruteMongoWorker()
		m.wg.Done()
	}()
	go func() {
		for {
			if atomic.LoadInt64(&m.Finish) == m.total {
				util.GetProgress(atomic.LoadInt64(&m.Finish), m.total)
				break
			} else {
				util.GetProgress(atomic.LoadInt64(&m.Finish), m.total)
				time.Sleep(1 * time.Second)
			}
		}
		m.wg.Done()
	}()
	m.wg.Wait()
	return m.ResultSlice
}
