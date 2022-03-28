package brute

import (
	"context"
	"fmt"
	"github.com/kpango/glg"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

func MongoUnauthCon(addr string) bool {
	dataSource := fmt.Sprintf("mongodb://%v", addr)
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(dataSource))
	if err != nil {
		//glg.Error(err)
		return false
	}
	defer func() {
		if err = client.Disconnect(context.TODO()); err != nil {
			glg.Error(err)
		}
	}()
	if err := client.Ping(context.TODO(), readpref.Primary()); err != nil {
		//glg.Error(err)
		return false
	}
	return true
}

func (b *Brute) mongoBrute(target string) {
	if MongoUnauthCon(target) {
		glg.Warnf("[!]%s 存在mongodb未授权漏洞", target)
		b.BruteResult.Store(target, "mongodb未授权访问")
	}
}
