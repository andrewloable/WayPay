package main

import (
	"flag"
	"time"

	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"

	session "github.com/ScottHuangZL/gin-jwt-session"
	"github.com/golang/glog"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"loable.tech/WayPay/apicontrollers"
	"loable.tech/WayPay/models"
	"loable.tech/WayPay/viewcontrollers"
)

func main() {
	flag.Parse()
	flag.Lookup("logtostderr").Value.Set("true")

	config := models.Config{}
	config.ReadConfig()

	db, err := gorm.Open("sqlite3", "db/main.db")
	if err != nil {
		glog.Fatalln(time.Now(), "Database Initialization Error", err)
	}
	defer db.Close()
	router := gin.Default()
	models.Initialize(db)
	viewcontrollers.Initialize(config, router, db)
	apicontrollers.Initialize(config, router, db)

	session.SecretKey = config.CookieSecretKey
	session.JwtTokenName = "__app__"
	session.DefaultSessionName = "__session__"
	session.NewStore()

	router.Use(gzip.Gzip(gzip.BestCompression))
	router.Static("/assets", "./static")

	glog.Flush()
	router.Run(":8080")
}
