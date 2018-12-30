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
	nonSecureViews := []string{
		"views/layouts/login.html",
		"views/templates/header_not_secure.html",
		"views/templates/footer_not_secure.html",
	}

	r.AddFromFiles("login", nonSecureViews...)
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

		if strings.Contains(path, ".html") && !strings.Contains(path, "login.html") {
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
		glog.Infoln(name)
		r.AddFromFiles(name, files...)
	}
	return r
}

func initRoutes() {
	fmt.Println("HASH 123", hashPassword("123"))
	r = multitemplate.NewRenderer()
	router.HTMLRender = r
	r = loadTemplates(r)
	router.GET("/login", login)
	router.POST("/login", validateLogin)
	router.GET("/", dashboard)
}

func isValidSession(c *gin.Context) bool {
	username, err := session.ValidateJWTToken(c)
	if err == nil && username != "" {
		return true
	}
	c.Redirect(http.StatusSeeOther, "/login")
	return false
}

func canAccess(userID uint, access string) bool {
	ac := models.Access{}
	db.Where("user_id=? AND access_type=?", userID, ac).First(&access)

	return false
}

func getUserByID(ID uint) models.User {
	var obj models.User
	db.Where("ID=?", ID).First(&obj)
	return obj
}

func getTemplateObjects(c *gin.Context) gin.H {
	sID, _ := session.GetString(c, "ID")
	ID, _ := strconv.ParseUint(sID, 10, 64)
	user := getUserByID(uint(ID))
	retval := gin.H{
		"user": user,
	}
	return retval
}

func getTemplateObjectsWithMessage(c *gin.Context, msg string) gin.H {
	sID, _ := session.GetString(c, "ID")
	ID, _ := strconv.ParseUint(sID, 10, 64)
	user := getUserByID(uint(ID))
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
	db.Where("username=? AND password=?", c.Username, c.Password).First(&auth)
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
		user.ID = 0
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

	// redirect to home screen
	c.Redirect(http.StatusSeeOther, "/")
	return
}

func dashboard(c *gin.Context) {
	if isValidSession(c) {
		c.HTML(200, "dashboard", getTemplateObjects(c))
		return
	}
}
