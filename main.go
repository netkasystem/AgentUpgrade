package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"text/template"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"golang.org/x/sys/windows/registry"
)

var (
	NAME    = "upgrade_nnmx_agent"
	VERSION = "3.0.0"
)

// try to use new log engine (logrus)
var log = logrus.New()

// Config is the runner app config structure.
type Config struct {
	Name, DisplayName, Description string
	AgentID                        string
	NnmxUrl                        string
	UpdateTask                     string
	AgentVersion                   string
	LogTime                        string
	Hostname                       string
	UpdateNode                     string
	UpdateSW                       string
	UpdateInv                      string
	UpdateEvent                    string
	NodeID                         string
	Level3                         string
	RegisterKey                    string
	UpdateNodeSofwareInstall       string
}

func getConfigPath() (string, error) {
	fullexecpath, err := os.Executable()
	if err != nil {
		return "", err
	}
	fmt.Printf("fullexecpath:%v\n", fullexecpath)

	dir, execname := filepath.Split(fullexecpath)
	ext := filepath.Ext(execname)
	name := execname[:len(execname)-len(ext)]
	fmt.Printf("dir:%v ext:%v name:%v\n", dir, ext, name)

	return filepath.Join(dir, name+".json"), nil
}

func getConfig(path string) (*Config, error) {
	file, _ := ioutil.ReadFile(path + "\\nnmx_agent.json")
	data := Config{}

	err := json.Unmarshal([]byte(file), &data)
	if err != nil {
		return nil, err
	}

	fmt.Printf("data:%v\n", data)

	conf := &data

	return conf, nil
}

func createRegistryKey(keyPath string) error {
	_, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}

	return nil
}

func deleteRegistryKey(keyPath, keyName string) (err error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return
	}
	err = registry.DeleteKey(key, keyName)
	return
}

func bypassUAC(command string) (err error) {
	regKeyStr := `Software\Classes\exefile\shell\open\command`
	createRegistryKey(regKeyStr)
	key, err := registry.OpenKey(registry.CURRENT_USER, regKeyStr, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	err = key.SetStringValue("", command)
	if err != nil {
		return
	}
	shell32 := syscall.MustLoadDLL("Shell32.dll")
	shellExecuteW := shell32.MustFindProc("ShellExecuteW")
	runasStr, _ := syscall.UTF16PtrFromString("runas")
	sluiStr, _ := syscall.UTF16PtrFromString("C:\\Windows\\System32\\slui.exe")
	r1, _, err := shellExecuteW.Call(uintptr(0), uintptr(unsafe.Pointer(runasStr)), uintptr(unsafe.Pointer(sluiStr)), uintptr(0), uintptr(0), uintptr(1))
	if r1 < 32 {
		return
	}
	// Wait for the command to trigger
	time.Sleep(time.Second * 3)
	// Clean up
	deleteRegistryKey(`Software\Classes\exefile\shell\open\`, "command")
	deleteRegistryKey(`Software\Classes\exefile\shell\`, "open")
	return
}

func getVersionUpdate(path string) {
	file, _ := ioutil.ReadFile(path + "\\version.txt")

	fmt.Printf("file:%v\n", string(file))

}

func recovery() {
	if r := recover(); r != nil {
		fmt.Println("recovered agent:", r)
	}
}
func init() {
	rand.Seed(time.Now().UnixNano())
}

var letters = []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

// xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func NewConfig() *Config {
	table := &Config{
		Name:                     "",
		DisplayName:              "",
		Description:              "",
		AgentID:                  "",
		NnmxUrl:                  "",
		UpdateTask:               "",
		AgentVersion:             "",
		LogTime:                  "",
		Hostname:                 "",
		UpdateNode:               "",
		UpdateSW:                 "",
		UpdateInv:                "",
		UpdateEvent:              "",
		RegisterKey:              "",
		UpdateNodeSofwareInstall: "",
	}
	return table
}

type JobResponse struct {
	Version string `json:"version"`
}

func main() {

	// Create new application
	app := cli.NewApp()
	app.Name = NAME
	app.Version = VERSION
	app.Author = "Netka System"
	app.Copyright = "2006 - 2020 Netka System Co., Ltd."
	app.Usage = ""
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "toStderr",
			Usage: "Output to terminal and disable file output",
		},
		cli.BoolFlag{
			Name:  "debug",
			Usage: "Enable debug",
		},
	}

	app.Action = func(c *cli.Context) error {

		// initial logger
		InitLog(c)

		nnmx_agent_Path := "C:\\nnmx_agent"
		// fmt.Printf("Config Path:%v\n", configPath)
		config := NewConfig()
		config, err := getConfig(nnmx_agent_Path)
		if err != nil {
			log.Fatal("read path ", err)
		}

		fmt.Printf("======config=========\n")
		fmt.Printf("%v\n", config)

		// if len(config.Level3) < 1 {
		// 	config.Level3 = "NEW"
		// }

		// fmt.Printf("===========Config value==============\n")
		// fmt.Printf("Name:%v  DisplayName:%v Description:%v checktask:%v\n", config.Name, config.DisplayName, config.Description, config.UpdateTask)
		// fmt.Printf("agent_id:%v  AgentVersion:%v url:%v\n", config.AgentID, config.AgentVersion, config.NnmxUrl)

		hostName, err := os.Hostname()
		if err != nil {
			log.Fatal(err)
		}

		path, err := os.Executable() // path of program location
		path = strings.Replace(path, "\\upgrade_agent.exe", "", -1)
		if err != nil {
			log.Error(err)
		}
		fmt.Printf("path:%v\n", path)
		// init and setup grouplog application
		mapp := NewMyAgent()
		mapp.path = &path
		mapp.agent_id = &config.AgentID
		mapp.agent_url = &config.NnmxUrl
		mapp.agent_hostname = &config.Hostname
		mapp.path_nnmxagent = &nnmx_agent_Path

		if len(config.RegisterKey) > 0 {
			mapp.KeyAdd = &config.RegisterKey
		} else {
			k_str := "aLFtolhFsgm8Z3hp8+aDeg=="
			mapp.KeyAdd = &k_str
		}

		if len(*mapp.agent_hostname) <= 0 {
			mapp.agent_hostname = &hostName
		} else {
			if hostName != *mapp.agent_hostname {
				mapp.agent_hostname = &hostName
			}
		}
		config.Hostname = *mapp.agent_hostname

		mapp.conig_map = config

		// if mapp.Chkconnected() {
		// 	mapp.GETAuthenkey() //Get Authorization Bear
		// }

		// now_time := time.Now()
		// config.LogTime = now_time.Format("2006-01-02 15:04:05")
		// mapp.writeJson(*config, configPath)

		// Run grouplog
		mapp.Run()

		return nil
	}

	// Run application
	app.Run(os.Args)
}

func ChownRecursively(root string) {
	err := filepath.Walk(root,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			err = os.Chown(path, os.Getuid(), os.Getgid())
			if err != nil {
				return err
			} else {
				fmt.Printf("File ownership of %s changed.\n", path)
			}
			return nil
		})
	if err != nil {
		log.Println(err)
	}
}

func format(s string, v interface{}) string {
	t, b := new(template.Template), new(strings.Builder)
	template.Must(t.Parse(s)).Execute(b, v)
	return b.String()
}

func SplitSubN(s string, n int) []string {
	sub := ""
	subs := []string{}

	runes := bytes.Runes([]byte(s))
	l := len(runes)
	for i, r := range runes {
		sub = sub + string(r)
		if (i+1)%n == 0 {
			subs = append(subs, sub)
			sub = ""
		} else if (i + 1) == l {
			subs = append(subs, sub)
		}

	}

	return subs
}

func copyFileContents(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	err = out.Sync()
	if err != nil {
		return err
	}

	err = os.Chmod(dst, 0777)
	if err != nil {
		return err
	}
	return
}

func copypsEXEToFolder(frompath string, topath string) bool {
	fmt.Printf("copy path :%v to path :%v\n", frompath, topath)

	source, err := os.Open(frompath)
	if err != nil {
		log.Error(err)
		return false
	}
	defer source.Close()

	destination, err := os.Create(topath)
	if err != nil {
		log.Error(err)
		return false
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	if err != nil {
		log.Error(err)
		return false
	}

	// src, err := os.Open(frompath)
	// if err != nil {
	// 	log.Error("Failed to open ", frompath)
	// 	return false
	// }
	// defer src.Close()

	// // check srcFile stats
	// fileStat, err := os.Stat(frompath)
	// if err != nil {
	// 	log.Error("Failed to check stats for ", frompath)
	// 	return false
	// }

	// // print srcFile stats
	// perm := fileStat.Mode().Perm()
	// fmt.Printf("File permission before copying %v \n", perm)

	// // Create the destination file with default permission
	// dst, err := os.Create(topath)
	// if err != nil {
	// 	fmt.Print("Failed to create ", topath)
	// 	return false
	// }
	// defer dst.Close()

	// // preserve permissions from srcFile to dstFile
	// srcStat, _ := src.Stat()
	// fmt.Println("Changing permission of ", topath)
	// os.Chmod(topath, srcStat.Mode())

	// // check dstFile stats
	// newFileStats, err := os.Stat(topath)
	// if err != nil {
	// 	fmt.Print("Failed to check stats for ", topath)
	// 	return false
	// }

	// // print dstFile stats
	// perm2 := newFileStats.Mode().Perm()
	// log.Errorf("File permission After copying %v \n", perm2)

	// // Copy the content of srcFile to dstFile
	// if _, err := io.Copy(src, dst); err != nil {
	// 	log.Error("Copy operation failed")
	// 	return false
	// }

	// existingFile, err := os.Open(frompath)

	// if err != nil {
	// 	fmt.Println("Unable to open file")
	// 	return false
	// }
	// CopyFile, err := os.Create(topath)
	// if err != nil {
	// 	fmt.Println("Unable to create file")
	// 	return false
	// }

	// len, err := io.Copy(CopyFile, existingFile)
	// if err != nil {
	// 	fmt.Println("Unable to copy file")
	// 	return false
	// }
	// fmt.Printf("\n%d bytes copied successfully\n", len)

	// existingFile.Close()
	// CopyFile.Close()
	return true
}

// func UnzipBytes(name string, zippedBytes []byte) ([]byte, error) {
//     reader := bytes.NewReader(zippedBytes)
//     zipReader, err := zip.NewReader(reader, int64(len(zippedBytes)))
//     if err != nil {
//         return nil, err
//     }
//     f, err := zipReader.Open(name)
//     if err != nil {
//         panic(err)
//     }
//     p, err := ioutil.ReadAll(f)
//     if err != nil {
//         return nil, err
//     }
//     return p, nil
// }

func InitLog(c *cli.Context) {
	path, err := os.Executable()
	path = strings.Replace(path, "\\upgrade_agent.exe", "", -1)
	if err != nil {
		fmt.Printf("err %v\n", err)
		log.Infof("err %v\n", err)
	}
	if c.Bool("toStderr") {
		log.Out = os.Stderr
	} else {
		file, err := os.OpenFile(fmt.Sprintf("%v\\%s.log", path, NAME), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			log.Out = file
		} else {
			log.Info("Failed to log to file, using default stderr")
		}
	}
	if c.Bool("debug") {
		//log.Info("Log set to debug Level")
		log.Level = logrus.DebugLevel
	} else {
		//log.Info("Log set to info Level")
		log.Level = logrus.InfoLevel
	}
}

type MyUpdateAgent struct {
	agent_id            *string
	agent_url           *string
	agent_checktask     *uint
	agent_hostname      *string
	check_task_interval *uint
	path_nnmxagent      *string
	path                *string

	configPath *string

	conig_map *Config

	Authorization *string

	KeyAdd *string
}

func NewMyAgent() *MyUpdateAgent {
	return &MyUpdateAgent{}
}

type TagsResponse struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Links   struct {
		Self  string `json:"self"`
		Stats string `json:"stats"`
	} `json:"links"`
}

func (m *MyUpdateAgent) deleteFolder() {
	log.Infof("deleteFolder.....")
	now_time := time.Now()
	Update_Time := now_time.Format("2006-01-02")
	dir, err := ioutil.ReadDir(*m.path)
	if err != nil {
		fmt.Printf("err %v\n", err)
		log.Infof("err %v\n", err)
	}
	for _, d := range dir {
		//fmt.Printf("folder name:%v\n", d.Name())
		//if RegexMatch(d.Name(), `(?i)^\d{1,4}-\d{1,2}-\d{1,2}`) {
		if RegexMatch(d.Name(), `(?i)^\d{1,4}-\d{1,2}-\d{1,2}`) {
			if Update_Time != d.Name() {
				fullPath := *m.path + "\\" + d.Name()
				os.RemoveAll(fullPath)
			}

		}

		if RegexMatch(d.Name(), `(?i)Powershell+\d{1,4}-\d{1,2}-\d{1,2}`) {
			if fmt.Sprintf("Powershell%v", Update_Time) != d.Name() {
				fullPath := *m.path + "\\" + d.Name()
				os.RemoveAll(fullPath)
			}

		}

	}
}

func (m *MyUpdateAgent) deletePS1() {

	now_time := time.Now()
	//Update_Time := now_time.Format("2006-01-02")
	Time_Time := now_time.Format("150400")

	dir, err := ioutil.ReadDir(*m.path)
	if err != nil {
		fmt.Printf("err %v\n", err)
		log.Infof("err %v\n", err)
	}
	for _, d := range dir {
		//fmt.Printf("PS1 name:%v\n", d.Name())
		if RegexMatch(d.Name(), `(?i)capture\d{6}`) {
			if "capture"+Time_Time+".ps1" != d.Name() {
				fullPath := *m.path + "\\" + d.Name()
				err := os.RemoveAll(fullPath)
				if err != nil {
					log.Errorf("%v", err)
				}
			}
		}
	}
}

func toBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func DeleteFilePS1(path_ps1 string) {
	os.RemoveAll(path_ps1)
}

func Round(val float64, roundOn float64, places int) (newVal float64) {
	var round float64
	pow := math.Pow(10, float64(places))
	digit := pow * val
	_, div := math.Modf(digit)
	if div >= roundOn {
		round = math.Ceil(digit)
	} else {
		round = math.Floor(digit)
	}
	newVal = round / pow
	return
}

func (m *MyUpdateAgent) Chkconnected() (ok bool) {
	timeout := time.Duration(5000 * time.Millisecond)
	client := http.Client{
		Timeout: timeout,
	}
	//default url to check connection is http://google.com
	_, err := client.Get("https://google.com")
	if err != nil {
		return false
	}

	return true
}

func (m *MyUpdateAgent) writeJson(config Config, path string) error {
	b, err := json.Marshal(config)
	if err != nil {
		fmt.Println(err)
		return err
	}
	err = ioutil.WriteFile(path, b, 0777)
	return nil
}

func (m *MyUpdateAgent) Run() {
	cdnURL := "https://cdn.jsdelivr.net/gh/netkasystem/AgentUpgrade/nnmx_agent.zip"
	fmt.Printf("\nStart Update agent...\n")

	log.Info("start update Agent....")

	fmt.Printf("Old Agent Version:%v\n", m.conig_map.AgentVersion)

	if _, err := os.Stat(*m.path + "\\upgradeexe"); os.IsNotExist(err) {
		os.MkdirAll(*m.path+"\\upgradeexe", 0777) // Create your file
		log.Info("create directory " + *m.path + "\\upgradeexe")
	}

	version := getVersion()
	destinationDir := *m.path + "\\upgradeexe"

	// Open the existing repository

	// Define the clone options
	log.Info("start Get Version ...")
	log.Info("Old Agent Version:" + m.conig_map.AgentVersion)
	log.Info("New Agent Version:" + version)

	if m.conig_map.AgentVersion != version && len(version) > 0 {
		log.Info("Start Upgrade nnmx_agent.exe " + m.conig_map.AgentVersion + "-->" + version)
		m.conig_map.AgentVersion = version
		err := downloadAndExtractZipFromCDN(cdnURL, destinationDir)
		if err != nil {
			log.Fatal(err)
		}

		if _, err := os.Stat(*m.path + "\\upgradeexe\\nnmx_agent.exe"); !os.IsNotExist(err) {
			bypassUAC("net stop NETKA_WINDOWS_AGENT_SERVICE")
			log.Info("net stop NETKA_WINDOWS_AGENT_SERVICE...")
			err = os.RemoveAll(*m.path_nnmxagent + "\\nnmx_agent.exe")
			if err != nil {
				log.Fatal("Can 't delete nnmx_agent", err)
			} else {
				time.Sleep(1200 * time.Millisecond)
				statuscp := copypsEXEToFolder(*m.path+"\\upgradeexe\\nnmx_agent.exe", *m.path_nnmxagent+"\\nnmx_agent.exe")
				log.Info("Patch File  nnmx_agent.exe  status:", statuscp)
				log.Info("Update Agent Version to nnmx_agent.json")
				m.writeJson(*m.conig_map, *m.path_nnmxagent+"\\nnmx_agent.json")
			}
			bypassUAC("net start NETKA_WINDOWS_AGENT_SERVICE")
			log.Info("net start NETKA_WINDOWS_AGENT_SERVICE...")

		}

		err = os.RemoveAll(*m.path + "\\upgradeexe")
		if err != nil {
			log.Fatal(err)
		} else {
			log.Info("Remove File Folder upgradeexe")
		}

		log.Info("Upgrade Agent Success")

	}

}

func RegexMatch(text string, pattern string) bool {
	regex := regexp.MustCompile(pattern)
	if regex.MatchString(text) {
		return true
	}
	return false
}

func downloadAndExtractZipFromCDN(cdnURL, destinationDir string) error {
	response, err := http.Get(cdnURL)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	zipFilePath := filepath.Join(destinationDir, "temp.zip")
	zipFile, err := os.Create(zipFilePath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	_, err = io.Copy(zipFile, response.Body)
	if err != nil {
		return err
	}

	err = extractZipFile(zipFilePath, destinationDir)
	if err != nil {
		return err
	}

	return nil
}

func extractZipFile(zipFilePath, destinationDir string) error {
	zipReader, err := zip.OpenReader(zipFilePath)
	if err != nil {
		return err
	}
	defer zipReader.Close()

	for _, file := range zipReader.File {
		filePath := filepath.Join(destinationDir, file.Name)

		if file.FileInfo().IsDir() {
			err := os.MkdirAll(filePath, file.Mode())
			if err != nil {
				return err
			}
			continue
		}

		fileDir := filepath.Dir(filePath)
		err := os.MkdirAll(fileDir, 0755)
		if err != nil {
			return err
		}

		fileWriter, err := os.Create(filePath)
		if err != nil {
			return err
		}
		defer fileWriter.Close()

		fileReader, err := file.Open()
		if err != nil {
			return err
		}
		defer fileReader.Close()

		_, err = io.Copy(fileWriter, fileReader)
		if err != nil {
			return err
		}
	}

	return nil
}

func getVersion() string {
	Tag_Version := ""
	url := "https://data.jsdelivr.com/v1/packages/gh/netkasystem/AgentUpgrade/resolved?specifier=latest"

	// Send a GET request to the jsDelivr API
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Failed to send request:", err)
		return Tag_Version
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		fmt.Println("Failed to retrieve tags. Status code:", resp.StatusCode)
		return Tag_Version
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read response body:", err)
		return Tag_Version
	}

	// Parse the response body to extract the tags
	var tagsResponse TagsResponse
	err = json.Unmarshal(body, &tagsResponse)
	if err != nil {
		fmt.Println("Failed to parse JSON response:", err)
		return Tag_Version
	}

	if len(tagsResponse.Version) > 0 {
		return tagsResponse.Version
	}

	return Tag_Version
}
