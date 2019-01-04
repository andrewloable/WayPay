package utils

import (
	mth "math/rand"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/golang/glog"
	"loable.tech/WayPay/models"
)

const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	letterBytes   = "0123456789abcdef"
)

var src = mth.NewSource(time.Now().UnixNano())

// RandomStringGenerate :
func RandomStringGenerate(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

// LoadIPTables ...
func LoadIPTables() error {
	out, err := exec.Command("/sbin/iptables", "-L", "-vt", "nat").CombinedOutput()
	if err != nil {
		glog.Errorln("LoadIPTables ERROR", err, string(out))
		return err
	}
	glog.Infoln(time.Now(), "LoadIPTables", string(out))
	return nil
}

// StartTrafficShaping ...
func StartTrafficShaping(devInput string) error {
	out, err := exec.Command("/sbin/tc", "qdisc", "add", "dev", devInput, "root", "handle", "1:", "htb").CombinedOutput()
	if err != nil {
		glog.Errorln("StartTrafficShaping ERROR", err, string(out))
		return err
	}
	glog.Infoln(time.Now(), "StartTrafficShaping", string(out))
	return nil
}

// SetTrafficClassRate ...
func SetTrafficClassRate(devInput string, rate models.Rate) error {
	out, err := exec.Command("/sbin/tc", "class", "add", "dev", devInput, "parent", "1:", "classid", "1:"+rate.ClassID, "htb", "rate", rate.NetworkRate).CombinedOutput()
	if err != nil {
		glog.Errorln("SetTrafficClassRate ERROR", err, string(out))
		return err
	}
	glog.Infoln(time.Now(), "SetTrafficClassRate", string(out))
	return nil
}

// SetIPTrafficClass ...
func SetIPTrafficClass(devInput string, rate models.Rate, ipaddress string) error {
	out, err := exec.Command("/sbin/tc", "filter", "add", "dev", devInput, "parent", "1:0", "protocol", "ip", "prio", "1", "u32", "match", "ip", "dst", ipaddress, "flowid", "1:"+rate.ClassID).CombinedOutput()
	if err != nil {
		glog.Errorln("SetIPTrafficClass ERROR", err, string(out))
		return err
	}
	glog.Infoln(time.Now(), "SetIPTrafficClass", string(out))
	return nil
}

// RemoveIPTrafficClass ...
func RemoveIPTrafficClass(devInput string) error {
	out, err := exec.Command("/sbin/tc", "filter", "del", "dev", devInput, "parent", "1:0", "protocol", "ip", "prio", "1").CombinedOutput()
	if err != nil {
		glog.Errorln("RemoveIPTrafficClass ERROR", err, string(out))
		return err
	}
	glog.Infoln(time.Now(), "RemoveIPTrafficClass", string(out))
	return nil
}

// DropForwardPackets ...
func DropForwardPackets(devInput string, devOutput string) error {
	out, err := exec.Command("/sbin/iptables", "-A", "FORWARD", "-i", devInput, "-o", devOutput, "-j", "DROP").CombinedOutput()
	if err != nil {
		glog.Errorln("DropForwardPackets ERROR", err, string(out))
		return err
	}
	glog.Infoln(time.Now(), "DropForwardPackets", string(out))
	return nil
}

// PostMasquerade ...
func PostMasquerade(devOutput string) error {
	out, err := exec.Command("/sbin/iptables", "-t", "nat", "-A", "POSTROUTING", "-o", devOutput, "-j", "MASQUERADE").CombinedOutput()
	if err != nil {
		glog.Errorln("PostMasquerade ERROR", err)
		return err
	}
	glog.Infoln(time.Now(), "PostMasquerade", string(out))
	return nil
}

// RedirectAllToLocalServer ...
func RedirectAllToLocalServer() error {
	out, err := exec.Command("/sbin/iptables", "-t", "nat", "-I", "PREROUTING", "-s", "10.0.0.0/8", "-p", "tcp", "--dport", "1:65535", "-j", "DNAT", "--to-destination", "10.1.1.1:80").CombinedOutput()
	if err != nil {
		glog.Errorln("RedirectAllToLocalServer ERROR", err)
		return err
	}
	glog.Infoln(time.Now(), "RedirectAllToLocalServer", string(out))
	return nil
}

// GetIPAdress ...
func GetIPAdress(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		glog.Errorln("IP Address Error", err)
		return "Error"
	}
	glog.Infoln("IP ADDRESS", ip)
	return ip
}

// GetMACAddress ...
func GetMACAddress(ipaddress string) string {
	out, err := exec.Command("/bin/ip", "neighbor").CombinedOutput()
	if err != nil {
		glog.Errorln("MAC ADDR", err)
		return ""
	}
	glog.Infoln(string(out))
	lines := strings.Split(string(out), "\n")
	for i := 0; i < len(lines); i++ {
		tok := strings.Split(lines[i], " ")
		if tok[0] == ipaddress {
			glog.Infoln("IP NEIGHBOR", ipaddress, tok[4])
			return tok[4]
		}
	}

	return "NOTFOUND"
}

// ExemptIPRoute ...
func ExemptIPRoute(ipaddress string) error {
	out, err := exec.Command("/sbin/iptables", "-t", "nat", "-I", "PREROUTING", "-p", "tcp", "-s", ipaddress, "-j", "RETURN").CombinedOutput()
	if err != nil {
		glog.Errorln("ExemptIPRoute ERROR", err)
		return err
	}
	glog.Infoln(time.Now(), "ExemptIPRoute", ipaddress, string(out))
	return nil
}

// RemoveExemptIPRoute ...
func RemoveExemptIPRoute(ipaddress string) error {
	out, err := exec.Command("/sbin/iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-s", ipaddress, "-j", "RETURN").CombinedOutput()
	if err != nil {
		glog.Errorln("RemoveExemptIPRoute ERROR", err)
		return err
	}
	glog.Infoln(time.Now(), "RemoveExemptIPRoute", ipaddress, string(out))
	return nil
}

// AllowForwardMAC ...
func AllowForwardMAC(macaddress string, devInput string, devOutput string) error {
	out, err := exec.Command("/sbin/iptables", "-I", "FORWARD", "-i", devInput, "-o", devOutput, "-m", "mac", "--mac-source", macaddress, "-j", "ACCEPT").CombinedOutput()
	if err != nil {
		glog.Errorln("AllowForwarMAC ERROR", err)
		return err
	}
	glog.Infoln(time.Now(), "AllowForwarMAC", macaddress, string(out))
	return nil
}
