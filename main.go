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
	"loable.tech/WayPay/utils"
	"loable.tech/WayPay/viewcontrollers"
)

func setInitalAccessSettings() {
	utils.DropForwardPackets("wlan0", "eth0")
	time.Sleep(500 * time.Millisecond)
	utils.PostMasquerade("eth0")
	time.Sleep(500 * time.Millisecond)
	utils.RedirectAllToLocalServer()
	time.Sleep(500 * time.Millisecond)
	utils.StartTrafficShaping("wlan0")
	time.Sleep(500 * time.Millisecond)
	utils.LoadIPTables()
}

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
	httpsRouter := gin.Default()
	httpRouter := gin.Default()
	models.Initialize(db)
	viewcontrollers.Initialize(config, httpRouter, db)
	apicontrollers.Initialize(config, httpRouter, db)

	session.SecretKey = config.CookieSecretKey
	session.JwtTokenName = "__app__"
	session.DefaultSessionName = "__session__"
	session.NewStore()

	httpRouter.Use(gzip.Gzip(gzip.BestCompression))
	httpRouter.Static("/assets", "./static")

	glog.Flush()

	httpsRouter.GET("/", func(c *gin.Context) {
		c.Redirect(302, "http://10.1.1.1/login")
	})

	setInitalAccessSettings()

	go httpsRouter.Run(":443")
	httpRouter.Run(":80")
}
