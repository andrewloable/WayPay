package apicontrollers

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strconv"
	"time"

	session "github.com/ScottHuangZL/gin-jwt-session"
	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
	"github.com/jinzhu/gorm"
	"loable.tech/WayPay/models"
)

var config models.Config
var router *gin.Engine
var db *gorm.DB
var api *gin.RouterGroup

// Initialize ...
func Initialize(state models.Config, r *gin.Engine, d *gorm.DB) {
	config = state
	router = r
	db = d
	api = r.Group("/api/v1")
	// users
	api.GET("/users", usersList)
	api.DELETE("/users/:ID", deleteUser)
	api.POST("/users", addUser)
	// access
	api.GET("/access", accessList)
	api.DELETE("/access/:ID", deleteAccess)
	api.POST("/access", addAccess)
	// vouchers
	api.GET("/vouchers", voucherList)
	api.DELETE("/vouchers/:ID", deleteVoucher)
	api.POST("/vouchers", addVoucher)
	api.PUT("/vouchers", updateVoucher)
	// rates
	api.GET("/rates", rateList)
	api.DELETE("/rates/:ID", deleteRate)
	api.POST("/rates", addRate)
	api.PUT("/rates", updateRate)
	// network usage
	api.GET("/netuse", networkUsageList)
	api.DELETE("/netuse/:ID", deleteNetworkUsage)
	api.POST("/netuse", addNetworkUsage)
	api.PUT("/netuse", updateNetworkUsage)
	// test
	api.GET("/test", activateAccess)
}

func activateAccess(c *gin.Context) {
	// ipaddress := utils.GetIPAdress(c.Request)
	// macaddress := utils.GetMACAddress(ipaddress)
	// utils.AllowForwardMAC(macaddress, "wlan0", "eth0")
	// time.Sleep(500 * time.Millisecond)
	// utils.ExemptIPRoute(ipaddress)
	// time.Sleep(500 * time.Millisecond)
	// rate := models.Rate{
	// 	ClassID:     utils.RandomStringGenerate(4),
	// 	NetworkRate: "1mbit",
	// }
	// glog.Infoln("Rate", rate)
	// utils.SetTrafficClassRate("wlan0", rate)
	// time.Sleep(500 * time.Millisecond)
	// utils.SetIPTrafficClass("wlan0", rate, ipaddress)
	// time.Sleep(500 * time.Millisecond)
	// utils.LoadIPTables()
	c.JSON(http.StatusOK, "OK")
}

func isValidSession(c *gin.Context) bool {
	username, err := session.ValidateJWTToken(c)
	if err == nil && username != "" {
		return true
	}
	c.Redirect(http.StatusSeeOther, "/login")
	return false
}

func getUserID(c *gin.Context) uint {
	sID, _ := session.GetString(c, "ID")
	ID, _ := strconv.ParseUint(sID, 10, 64)
	return uint(ID)
}

func hashPassword(password string) string {
	h := sha256.New()
	h.Write([]byte(password))

	b := h.Sum(nil)
	return fmt.Sprintf("%x", b)
}

func addUser(c *gin.Context) {
	username, err := session.ValidateJWTToken(c)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	var obj models.User
	// get form data
	if err := c.ShouldBind(&obj); err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	obj.Password = hashPassword(obj.Password)
	db.Create(&obj)
	glog.Infoln("Add User", obj, username)
	c.JSON(http.StatusOK, "OK")
}

func usersList(c *gin.Context) {
	if isValidSession(c) {
		var obj []models.User
		db.Find(&obj)
		c.JSON(http.StatusOK, obj)
	} else {
		glog.Errorln(time.Now(), "Invalid Session", c)
		c.JSON(http.StatusUnauthorized, "Invalid Session")
	}
}

func deleteUser(c *gin.Context) {
	id := c.Param("ID")

	username, err := session.ValidateJWTToken(c)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	var obj models.User
	tempID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	glog.Warningln("Delete User", id, username)
	obj.ID = uint(tempID)
	db.Delete(&obj)
	c.JSON(http.StatusOK, "OK")
}

func addAccess(c *gin.Context) {
	username, err := session.ValidateJWTToken(c)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	var obj models.Access
	// get form data
	if err := c.ShouldBind(&obj); err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	db.Create(&obj)
	glog.Infoln("Add Access", obj, username)
	c.JSON(http.StatusOK, "OK")
}

func accessList(c *gin.Context) {
	if isValidSession(c) {
		var obj []models.Access
		db.Find(&obj)
		for i := 0; i < len(obj); i++ {
			var o1 models.User
			db.Find(&o1, obj[i].UserID)
			obj[i].User = o1
		}
		c.JSON(http.StatusOK, obj)
	} else {
		glog.Errorln(time.Now(), "Invalid Session", c)
		c.JSON(http.StatusUnauthorized, "Invalid Session")
	}
}

func deleteAccess(c *gin.Context) {
	id := c.Param("ID")

	username, err := session.ValidateJWTToken(c)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	var obj models.Access
	tempID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	glog.Warningln("Delete Access", id, username)
	obj.ID = uint(tempID)
	db.Delete(&obj)
	c.JSON(http.StatusOK, "OK")
}

func addVoucher(c *gin.Context) {
	username, err := session.ValidateJWTToken(c)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	var obj models.Voucher
	// get form data
	if err := c.ShouldBind(&obj); err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	db.Create(&obj)
	glog.Infoln("Add Voucher", obj, username)
	c.JSON(http.StatusOK, "OK")
}

func updateVoucher(c *gin.Context) {
	username, err := session.ValidateJWTToken(c)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	var obj models.Voucher
	// get form data
	if err := c.ShouldBind(&obj); err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	db.Save(&obj)
	glog.Infoln("Update Voucher", obj, username)
	c.JSON(http.StatusOK, "OK")
}

func voucherList(c *gin.Context) {
	if isValidSession(c) {
		var obj []models.Voucher
		db.Find(&obj)
		c.JSON(http.StatusOK, obj)
	} else {
		glog.Errorln(time.Now(), "Invalid Session", c)
		c.JSON(http.StatusUnauthorized, "Invalid Session")
	}
}

func deleteVoucher(c *gin.Context) {
	id := c.Param("ID")

	username, err := session.ValidateJWTToken(c)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	var obj models.Voucher
	tempID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	glog.Warningln("Delete Voucher", id, username)
	obj.ID = uint(tempID)
	db.Delete(&obj)
	c.JSON(http.StatusOK, "OK")
}

func addRate(c *gin.Context) {
	username, err := session.ValidateJWTToken(c)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	var obj models.Rate
	// get form data
	if err := c.ShouldBind(&obj); err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	db.Create(&obj)
	glog.Infoln("Add Rate", obj, username)
	c.JSON(http.StatusOK, "OK")
}

func updateRate(c *gin.Context) {
	username, err := session.ValidateJWTToken(c)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	var obj models.Rate
	// get form data
	if err := c.ShouldBind(&obj); err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	db.Save(&obj)
	glog.Infoln("Update Rate", obj, username)
	c.JSON(http.StatusOK, "OK")
}

func rateList(c *gin.Context) {
	if isValidSession(c) {
		var obj []models.Rate
		db.Find(&obj)
		c.JSON(http.StatusOK, obj)
	} else {
		glog.Errorln(time.Now(), "Invalid Session", c)
		c.JSON(http.StatusUnauthorized, "Invalid Session")
	}
}

func deleteRate(c *gin.Context) {
	id := c.Param("ID")

	username, err := session.ValidateJWTToken(c)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	var obj models.Rate
	tempID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	glog.Warningln("Delete Rate", id, username)
	obj.ID = uint(tempID)
	db.Delete(&obj)
	c.JSON(http.StatusOK, "OK")
}

func addNetworkUsage(c *gin.Context) {
	username, err := session.ValidateJWTToken(c)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	var obj models.NetworkUsage
	// get form data
	if err := c.ShouldBind(&obj); err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	db.Create(&obj)
	glog.Infoln("Add Network Usage", obj, username)
	c.JSON(http.StatusOK, "OK")
}

func updateNetworkUsage(c *gin.Context) {
	username, err := session.ValidateJWTToken(c)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	var obj models.NetworkUsage
	// get form data
	if err := c.ShouldBind(&obj); err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	db.Save(&obj)
	glog.Infoln("Update Network Usage", obj, username)
	c.JSON(http.StatusOK, "OK")
}

func networkUsageList(c *gin.Context) {
	if isValidSession(c) {
		var obj []models.NetworkUsage
		db.Find(&obj)
		c.JSON(http.StatusOK, obj)
	} else {
		glog.Errorln(time.Now(), "Invalid Session", c)
		c.JSON(http.StatusUnauthorized, "Invalid Session")
	}
}

func deleteNetworkUsage(c *gin.Context) {
	id := c.Param("ID")

	username, err := session.ValidateJWTToken(c)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	var obj models.NetworkUsage
	tempID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	glog.Warningln("Delete Network Usage", id, username)
	obj.ID = uint(tempID)
	db.Delete(&obj)
	c.JSON(http.StatusOK, "OK")
}

func addSales(c *gin.Context) {
	username, err := session.ValidateJWTToken(c)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	var obj models.Sales
	// get form data
	if err := c.ShouldBind(&obj); err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	db.Create(&obj)
	glog.Infoln("Add Sales", obj, username)
	c.JSON(http.StatusOK, "OK")
}

func updateSales(c *gin.Context) {
	username, err := session.ValidateJWTToken(c)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	var obj models.Sales
	// get form data
	if err := c.ShouldBind(&obj); err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	db.Save(&obj)
	glog.Infoln("Update Sales", obj, username)
	c.JSON(http.StatusOK, "OK")
}

func salesList(c *gin.Context) {
	if isValidSession(c) {
		var obj []models.Sales
		db.Find(&obj)
		c.JSON(http.StatusOK, obj)
	} else {
		glog.Errorln(time.Now(), "Invalid Session", c)
		c.JSON(http.StatusUnauthorized, "Invalid Session")
	}
}

func deleteSales(c *gin.Context) {
	id := c.Param("ID")

	username, err := session.ValidateJWTToken(c)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	var obj models.Sales
	tempID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	glog.Warningln("Delete Sales", id, username)
	obj.ID = uint(tempID)
	db.Delete(&obj)
	c.JSON(http.StatusOK, "OK")
}
