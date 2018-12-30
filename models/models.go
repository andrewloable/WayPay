package models

import (
	"encoding/json"
	"io/ioutil"
	"time"

	"github.com/golang/glog"
	"github.com/jinzhu/gorm"
)

// Config ...
type Config struct {
	AdminUserName   string
	AdminPassword   string // Hash password using https://www.xorbin.com/tools/sha256-hash-calculator
	DeviceSerial    string
	CookieSecretKey string
}

// ReadConfig ...
func (c *Config) ReadConfig() {
	file, err := ioutil.ReadFile("config.json")
	if err != nil {
		glog.Errorln(time.Now(), "Config Read Error")
	} else {
		glog.Infoln(time.Now(), "Config File Read Success")
	}
	json.Unmarshal(file, c)
}

// User ...
type User struct {
	gorm.Model
	Username string
	Password string
}

// Access ...
type Access struct {
	gorm.Model
	UserID     uint
	User       User `gorm:"-"`
	AccessType string
}

// Initialize ...
func Initialize(db *gorm.DB) {
	db.AutoMigrate(&User{})
	db.AutoMigrate(&Access{})
}
