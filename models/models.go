package models

import (
	"encoding/json"
	"io/ioutil"
	"time"

	"github.com/shopspring/decimal"

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

// MenuItem ...
type MenuItem struct {
	Name string
	Path string
}

// Voucher ...
type Voucher struct {
	gorm.Model
	Code           string
	DateCreated    time.Time
	DateClaimed    time.Time
	Credits        decimal.Decimal `sql:"type:decimal(20,8);"`
	IsUsed         bool
	UsedByDeviceID string
	DeviceSerial   string
}

// Rate ...
type Rate struct {
	gorm.Model
	DeviceID    string
	CreditRate  decimal.Decimal `sql:"type:decimal(20,8);"`
	ClassID     string
	NetworkRate string
}

// NetworkUsage ...
type NetworkUsage struct {
	gorm.Model
	DeviceID     string
	Credits      decimal.Decimal `sql:"type:decimal(20,8);"`
	IsStopped    bool
	DeviceSerial string
	DeviceType   string
	RateID       uint
	Rate         Rate `gorm:"-"`
}

// Sales ...
type Sales struct {
	gorm.Model
	DeviceSerial string
	DeviceID     string
	Amount       decimal.Decimal `sql:"type:decimal(20,8);"`
	Minutes      decimal.Decimal `sql:"type:decimal(20, 8);"`
}

// Initialize ...
func Initialize(db *gorm.DB) {
	db.AutoMigrate(&User{})
	db.AutoMigrate(&Access{})
	db.AutoMigrate(&Voucher{})
	db.AutoMigrate(&Sales{})
	db.AutoMigrate(&Rate{})
	db.AutoMigrate(&NetworkUsage{})
}
