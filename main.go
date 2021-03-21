package main

import (
	"SolusVMNAT/zlog"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var Setting CSafeRule
var version string

var ConfigFile string
var LogFile string

type CSafeRule struct {
	Config Config
	Rules  sync.RWMutex
}

type Config struct {
	UpdateInfoCycle int
	EnableAPI       bool
	APIPort         string
	Eth             string
	Listen          map[string]Listen
	Rules           map[string]Rule
}

type Listen struct {
	Enable bool
	Port   string
}

type Rule struct {
	Status               string
	Protocol             string
	Listen               string
	Forward              string
	ProxyProtocolVersion int
}

type APIConfig struct {
	APIAddr  string
	APIToken string
	NodeID   int
}

var apic APIConfig

func main() {
	{
		flag.StringVar(&ConfigFile, "config", "config.json", "The config file location.")
		flag.StringVar(&LogFile, "log", "run.log", "The log file location.")
		help := flag.Bool("h", false, "Show help")
		flag.Parse()

		if *help {
			flag.PrintDefaults()
			os.Exit(0)
		}
	}

	os.Remove(LogFile)
	logfile_writer, err := os.OpenFile(LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		zlog.SetOutput(logfile_writer)
		zlog.Info("Log file location: ", LogFile)
	}

	zlog.Info("Node Version: ", version)
	zlog.Info("Clean up iptables table")
	shell_exec("iptables -t nat -F")

	apif, err := ioutil.ReadFile(ConfigFile)
	if err != nil {
		zlog.Fatal("Cannot read the config file. (io Error) " + err.Error())
	}

	err = json.Unmarshal(apif, &apic)
	if err != nil {
		zlog.Fatal("Cannot read the config file. (Parse Error) " + err.Error())
	}

	zlog.Info("API URL: ", apic.APIAddr)
	getConfig()

	go func() {
		if Setting.Config.EnableAPI == true {
			zlog.Info("[HTTP API] Listening ", Setting.Config.APIPort, " Path: /", md5_encode(apic.APIToken), " Method:POST")
			route := http.NewServeMux()
			route.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(404)
				io.WriteString(w, Page404)
				return
			})
			route.HandleFunc("/"+md5_encode(apic.APIToken), NewAPIConnect)
			err := http.ListenAndServe(":"+Setting.Config.APIPort, route)
			if err != nil {
				zlog.Error("[HTTP API] ", err)
			}
		}
	}()

	go func() {
		for {
			saveInterval := time.Duration(Setting.Config.UpdateInfoCycle) * time.Second
			time.Sleep(saveInterval)
			updateConfig()
		}
	}()

	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		done <- true
	}()
	<-done
	zlog.PrintText("Exiting")
}

func NewAPIConnect(w http.ResponseWriter, r *http.Request) {
	var NewConfig Config
	if r.Method != "POST" {
		w.WriteHeader(403)
		io.WriteString(w, "Unsupport Method.")
		return
	}
	postdata, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(postdata, &NewConfig)
	if err != nil {
		w.WriteHeader(400)
		io.WriteString(w, fmt.Sprintln(err))
		return
	}

	w.WriteHeader(200)
	io.WriteString(w, "Success")

	go func() {
		if Setting.Config.Rules == nil {
			Setting.Config.Rules = make(map[string]Rule)
		}

		Setting.Rules.Lock()
		for index, _ := range NewConfig.Rules {
			if NewConfig.Rules[index].Status == "Deleted" {
				go DeleteRules(index)
				continue
			} else if NewConfig.Rules[index].Status == "Created" {
				Setting.Config.Rules[index] = NewConfig.Rules[index]
				go LoadNewRules(index)
				continue
			} else {
				Setting.Config.Rules[index] = NewConfig.Rules[index]
				continue
			}
		}
		Setting.Rules.Unlock()
	}()
	return
}

func LoadListen() {
	for name, value := range Setting.Config.Listen {
		if value.Enable {
			switch name {
			case "Http":
				go HttpInit()
			case "Https":
				go HttpsInit()
			}
		}
	}
}

func DeleteRules(i string) {
	if _, ok := Setting.Config.Rules[i]; !ok {
		return
	}

	Protocol := Setting.Config.Rules[i].Protocol
	switch Protocol {
	case "tcp":
		DeleteTCPRules(i)
	case "udp":
		DeleteUDPRules(i)
	case "http":
		DeleteHttpRules(i)
	case "https":
		DeleteHttpsRules(i)
	}
}

func LoadNewRules(i string) {
	Protocol := Setting.Config.Rules[i].Protocol

	switch Protocol {
	case "tcp":
		LoadTCPRules(i)
	case "udp":
		LoadUDPRules(i)
	case "http":
		LoadHttpRules(i)
	case "https":
		LoadHttpsRules(i)
	}
}

func updateConfig() {
	var NewConfig Config

	jsonData, _ := json.Marshal(map[string]interface{}{
		"Action":  "UpdateInfo",
		"NodeID":  apic.NodeID,
		"Token":   md5_encode(apic.APIToken),
		"Version": version,
	})

	status, confF, err := sendRequest(apic.APIAddr, bytes.NewReader(jsonData), nil, "POST")
	if status == 503 {
		zlog.Error("Scheduled task update error,The remote server returned an error message: ", string(confF))
		return
	}
	if err != nil {
		zlog.Error("Scheduled task update: ", err)
		return
	}

	err = json.Unmarshal(confF, &NewConfig)
	if err != nil {
		zlog.Error("Cannot read the port forward config file. (Parse Error) " + err.Error())
		return
	}

	Setting.Rules.Lock()
	Setting.Config = NewConfig
	Setting.Rules.Unlock()

	for index, rule := range Setting.Config.Rules {
		if rule.Status == "Deleted" {
			go DeleteRules(index)
			continue
		} else if rule.Status == "Created" {
			go LoadNewRules(index)
			continue
		}
	}
	zlog.Success("Scheduled task update Completed")
}

func getConfig() {
	var NewConfig Config
	jsonData, _ := json.Marshal(map[string]interface{}{
		"Action":  "GetConfig",
		"NodeID":  apic.NodeID,
		"Token":   md5_encode(apic.APIToken),
		"Version": version,
	})
	status, confF, err := sendRequest(apic.APIAddr, bytes.NewReader(jsonData), nil, "POST")
	if status == 503 {
		zlog.Error("The remote server returned an error message: ", string(confF))
		return
	}

	if err != nil {
		zlog.Fatal("Cannot read the online config file. (NetWork Error) " + err.Error())
		return
	}

	err = json.Unmarshal(confF, &NewConfig)
	if err != nil {
		zlog.Fatal("Cannot read the port forward config file. (Parse Error) " + err.Error())
		return
	}
	Setting.Config = NewConfig
	shell_exec("iptables -t nat -A POSTROUTING -o " + Setting.Config.Eth + " -j MASQUERADE")
	shell_exec("NAT Forward To Ethernet:" + Setting.Config.Eth)
	zlog.Info("Update Cycle: ", Setting.Config.UpdateInfoCycle, " seconds")
	LoadListen()

	for index, _ := range NewConfig.Rules {
		go LoadNewRules(index)
	}
}

func sendRequest(url string, body io.Reader, addHeaders map[string]string, method string) (statuscode int, resp []byte, err error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36")

	if len(addHeaders) > 0 {
		for k, v := range addHeaders {
			req.Header.Add(k, v)
		}
	}

	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return
	}
	defer response.Body.Close()

	statuscode = response.StatusCode
	resp, err = ioutil.ReadAll(response.Body)
	return
}

func md5_encode(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

func copyIO(src, dest net.Conn) {
	defer src.Close()
	defer dest.Close()
	io.Copy(dest, src)
}

func shell_exec(command string) string {
	// 执行系统命令
	// 第一个参数是命令名称
	// 后面参数可以有多个，命令参数
	cmd := exec.Command("/bin/bash", "-c", command)
	// 获取输出对象，可以从该对象中读取输出结果
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return ""
	}
	// 保证关闭输出流
	defer stdout.Close()
	// 运行命令
	if err := cmd.Start(); err != nil {
		return ""
	}
	// 读取输出结果
	opBytes, err := ioutil.ReadAll(stdout)
	if err != nil {
		return ""
	}
	return string(opBytes)
}
