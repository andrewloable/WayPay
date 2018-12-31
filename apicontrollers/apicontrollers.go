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
