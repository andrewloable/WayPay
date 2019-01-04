package viewcontrollers

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	session "github.com/ScottHuangZL/gin-jwt-session"
	"github.com/gin-contrib/multitemplate"
	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
	"github.com/jinzhu/gorm"
	"loable.tech/WayPay/models"
	"loable.tech/WayPay/utils"
)

var config models.Config
var router *gin.Engine
var db *gorm.DB
var r multitemplate.Renderer

// Initialize ...
func Initialize(c models.Config, eng *gin.Engine, d *gorm.DB) {
	config = c
	router = eng
	db = d
	initRoutes()
}

func loadTemplates(r multitemplate.Renderer) multitemplate.Renderer {
	// Load Not Secure Views
	glog.Infoln("Load Not Secure Views")
	nonSecureLogin := []string{
		"views/layouts/login.html",
		"views/templates/header_not_secure.html",
		"views/templates/footer_not_secure.html",
	}

	nonSecurePublic := []string{
		"views/layouts/public.html",
		"views/templates/header_not_secure.html",
		"views/templates/footer_not_secure.html",
	}
	r.AddFromFiles("login", nonSecureLogin...)
	r.AddFromFiles("public", nonSecurePublic...)
	glog.Infoln("Load Secure Views")
	secureTemplates := []string{
		"views/templates/header_secure.html",
		"views/templates/footer_secure.html",
	}

	var layouts []string
	err := filepath.Walk("views/layouts", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			glog.Errorln(time.Now(), err)
			return err
		}

		if strings.Contains(path, ".html") && !strings.Contains(path, "login.html") && !strings.Contains(path, "public.html") {
			layouts = append(layouts, path)
		}
		return nil
	})
	if err != nil {
		glog.Errorln(time.Now(), err)
	}
	glog.Infoln("Load Layouts")
	for _, layout := range layouts {
		files := append([]string{layout}, secureTemplates...)
		// remove view layout dir and remove .html
		name := strings.Replace(strings.Replace(layout, "views/layouts/", "", -1), ".html", "", -1)
		glog.Infoln("Secure Layout", name)
		r.AddFromFiles(name, files...)
	}
	return r
}

func redirectIndex(c *gin.Context) {
	c.Redirect(302, "http://10.1.1.1/public")
}

func initRoutes() {
	fmt.Println("HASH 123", hashPassword("123"))
	r = multitemplate.NewRenderer()
	router.HTMLRender = r
	r = loadTemplates(r)
	// root hotspot detect
	router.GET("/", redirectIndex)
	// ios hotspot detect
	// http://captive.apple.com/hotspot-detect.html
	router.GET("/hotspot-detect.html", redirectIndex)
	router.GET("/bag", redirectIndex)
	// android hotspot detect
	// http://google.com/generate_204
	router.GET("/generate_204", redirectIndex)
	// windows 10 hotspot detect
	// http://www.msftconnecttest.com/connecttest.txt.
	router.GET("/connecttest.txt", redirectIndex)
	router.GET("/redirect", redirectIndex)
	// windows mobile hotspot detect
	// www.msftncsi.com/ncsi.txt
	router.GET("/ncsi.txt", redirectIndex)
	router.GET("/ppcrlcheck.srf", redirectIndex)
	// client index
	router.GET("/public", public)
	// admin
	router.GET("/login", login)
	router.POST("/login", validateLogin)
	router.GET("/godmode", dashboard)
	router.GET("/users", usersList)
	router.GET("/add_edit_user", addEditUser)
	router.GET("/access", accessList)
	router.GET("/add_edit_access", addEditAccess)
}

func public(c *gin.Context) {
	session.DeleteAllSession(c)
	ipaddress := utils.GetIPAdress(c.Request)
	macaddress := utils.GetMACAddress(ipaddress)

	c.HTML(200, "public", gin.H{
		"ipaddress":  ipaddress,
		"macaddress": macaddress,
	})
}

func isValidSession(c *gin.Context) bool {
	username, err := session.ValidateJWTToken(c)
	if err == nil && username != "" {
		sID, _ := session.GetString(c, "ID")
		ID, _ := strconv.ParseUint(sID, 10, 64)
		if ID == 0 {
			c.Redirect(http.StatusSeeOther, "/login")
			return false
		}
		return true
	}
	c.Redirect(http.StatusSeeOther, "/login")
	return false
}

func canAccess(userID uint, access string) bool {
	ac := models.Access{}
	db.Where("user_id=? AND access_type=?", userID, access).First(&ac)
	if userID == 999999 || ac.ID > 0 {
		return true
	}
	return false
}

func getUserID(c *gin.Context) uint {
	sID, _ := session.GetString(c, "ID")
	ID, _ := strconv.ParseUint(sID, 10, 64)
	return uint(ID)
}

func getUserByID(ID uint) models.User {
	var obj models.User
	db.Where("ID=?", ID).First(&obj)
	if ID == 999999 {
		obj.Username = "root"
		obj.ID = 999999
	}
	return obj
}

func generateMenu(user models.User) []models.MenuItem {
	var menu []models.MenuItem
	if user.Username == config.AdminUserName || canAccess(user.ID, "Users") {
		m := models.MenuItem{
			Name: "Users",
			Path: "/users",
		}
		menu = append(menu, m)
	}

	if user.Username == config.AdminUserName || canAccess(user.ID, "User Access") {
		m := models.MenuItem{
			Name: "Access",
			Path: "/access",
		}
		menu = append(menu, m)
	}

	if user.Username == config.AdminUserName || canAccess(user.ID, "Network Usage") {
		m := models.MenuItem{
			Name: "Network Usage",
			Path: "/networkusage",
		}
		menu = append(menu, m)
	}

	if user.Username == config.AdminUserName || canAccess(user.ID, "Vouchers") {
		m := models.MenuItem{
			Name: "Vouchers",
			Path: "/vouchers",
		}
		menu = append(menu, m)
	}

	if user.Username == config.AdminUserName || canAccess(user.ID, "Sales") {
		m := models.MenuItem{
			Name: "Sales",
			Path: "/sales",
		}
		menu = append(menu, m)
	}

	if user.Username == config.AdminUserName || canAccess(user.ID, "Settings") {
		m := models.MenuItem{
			Name: "Settings",
			Path: "/settings",
		}
		menu = append(menu, m)
	}
	return menu
}

func getTemplateObjects(c *gin.Context) gin.H {
	sID, _ := session.GetString(c, "ID")
	ID, _ := strconv.ParseUint(sID, 10, 64)
	user := getUserByID(uint(ID))
	menu := generateMenu(user)
	if len(menu) > 0 {
		retval := gin.H{
			"user": user,
			"menu": menu,
		}
		return retval
	}
	retval := gin.H{
		"user": user,
	}
	return retval
}

func getTemplateObjectsWithMessage(c *gin.Context, msg string) gin.H {
	sID, _ := session.GetString(c, "ID")
	ID, _ := strconv.ParseUint(sID, 10, 64)
	user := getUserByID(uint(ID))
	menu := generateMenu(user)
	if len(menu) > 0 {
		retval := gin.H{
			"hasError": true,
			"message":  msg,
			"user":     user,
			"menu":     menu,
		}
		return retval
	}
	retval := gin.H{
		"hasError": true,
		"message":  msg,
		"user":     user,
	}
	return retval
}

func login(c *gin.Context) {
	session.DeleteAllSession(c)
	c.HTML(200, "login", gin.H{})
}

func hashPassword(password string) string {
	h := sha256.New()
	h.Write([]byte(password))

	b := h.Sum(nil)
	return fmt.Sprintf("%x", b)
}

func validateUser(c models.User) bool {
	var auth models.User
	db.Where("username=? AND password=?", c.Username, hashPassword(c.Password)).First(&auth)
	if auth.ID > 0 {
		glog.Infoln(time.Now(), "User Validated", c)
		return true
	}
	if c.Username == config.AdminUserName && hashPassword(c.Password) == config.AdminPassword {
		glog.Infoln(time.Now(), "Admin Login Detected")
		return true
	}
	glog.Errorln(time.Now(), "User Not Valid", c)
	return false
}

func getUserByUserName(username string) (models.User, error) {
	var user = models.User{}
	db.First(&user, "username=?", username)

	if username == config.AdminUserName {
		user.Username = config.AdminUserName
		user.ID = 999999
		return user, nil
	}

	return user, errors.New("User Not Found")
}

func validateLogin(c *gin.Context) {
	var user models.User
	// get form data
	if err := c.ShouldBind(&user); err != nil {
		glog.Errorln(time.Now(), "Invalid Form Data", err)
		c.HTML(200, "login", gin.H{
			"hasError": true,
			"message":  "Invalid Login Data",
		})
		return
	}

	// check user in db
	if !validateUser(user) {
		glog.Errorln(time.Now(), "Invalid Account")
		c.HTML(200, "login", gin.H{
			"hasError": true,
			"message":  "Invalid Account",
		})
		return
	}

	authUser, _ := getUserByUserName(user.Username)

	// generate token for 4 hours
	tokenString, err := session.GenerateJWTToken(authUser.Username, time.Hour*time.Duration(4))
	if err != nil {
		glog.Errorln(time.Now(), "Server Error", err)
		c.HTML(200, "login", gin.H{
			"hasError": true,
			"message":  "Server Error. Please Contact Administrator.",
		})
		return
	}

	// add token to session
	err = session.SetTokenString(c, tokenString, 60*60*4)
	if err != nil {
		glog.Errorln(time.Now(), "Server Error", err)
		c.HTML(200, "login", gin.H{
			"hasError": true,
			"message":  "Server Error. Please Contact Administrator.",
		})
		return
	}

	session.Set(c, "ID", strconv.FormatUint(uint64(authUser.ID), 10))
	session.Set(c, "Username", authUser.Username)
	fmt.Printf("%+v\n-------------------------\n", user)
	Username, _ := session.GetString(c, "Username")
	fmt.Println("Username: ", Username)
	ID, _ := session.GetString(c, "ID")
	fmt.Println("ID: ", ID)

	// redirect to home screen
	c.Redirect(http.StatusSeeOther, "/")
	return
}

func dashboard(c *gin.Context) {
	if isValidSession(c) {
		c.HTML(200, "dashboard", getTemplateObjects(c))
		return
	}
	c.HTML(http.StatusTemporaryRedirect, "login", nil)
	return
}

func usersList(c *gin.Context) {
	if isValidSession(c) {
		ID := getUserID(c)
		if canAccess(ID, "Users") {
			c.HTML(200, "users", getTemplateObjects(c))
		} else {
			c.HTML(200, "dashboard", getTemplateObjectsWithMessage(c, "Access Not Allowed"))
		}
	} else {
		glog.Errorln(time.Now(), "Invalid Session", c)
	}
}

func addEditUser(c *gin.Context) {
	if isValidSession(c) {
		ID := getUserID(c)
		if canAccess(ID, "Users") {
			c.HTML(200, "add_edit_user", getTemplateObjects(c))
		} else {
			c.HTML(200, "dashboard", getTemplateObjectsWithMessage(c, "Access Not Allowed"))
		}
	} else {
		glog.Errorln(time.Now(), "Invalid Session", c)
	}
}

func accessList(c *gin.Context) {
	if isValidSession(c) {
		ID := getUserID(c)
		if canAccess(ID, "User Access") {
			c.HTML(200, "access", getTemplateObjects(c))
		} else {
			c.HTML(200, "dashboard", getTemplateObjectsWithMessage(c, "Access Not Allowed"))
		}
	} else {
		glog.Errorln(time.Now(), "Invalid Session", c)
	}
}

func addEditAccess(c *gin.Context) {
	if isValidSession(c) {
		ID := getUserID(c)
		if canAccess(ID, "User Access") {
			c.HTML(200, "add_edit_access", getTemplateObjects(c))
		} else {
			c.HTML(200, "dashboard", getTemplateObjectsWithMessage(c, "Access Not Allowed"))
		}
	} else {
		glog.Errorln(time.Now(), "Invalid Session", c)
	}
}
