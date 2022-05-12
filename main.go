package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var TYPE_SHORT = 1
var TYPE_INT = 2
var TYPE_STR = 3

var SUPPORTED_VERSIONS = []int{3, 4}

var u = flag.String("u", "", "This can be a url (if started with http/s)")
var f = flag.String("f", "", "This can be a file path (if started with http/s)")
var o = flag.String("o", "", "out file")
var t = flag.Int("t", 30, "timeouts. default:20")
var br = flag.Int("br", 1, "thread,import file valid. default:1")

func main() {
	flag.Parse()
	if flag.NFlag() == 0 {
		flag.Usage()
		os.Exit(1)
	}
	if *f != "" && *u == "" {
		var wg sync.WaitGroup
		var ChanUrlList chan string
		var num = 0
		var mutex sync.Mutex
		var urllist []string
		filepath := *f
		file, err := os.OpenFile(filepath, os.O_RDWR, 0666)
		if err != nil {
			fmt.Println("Open file error!", err)
			return
		}
		defer file.Close()

		buf := bufio.NewReader(file)
		for {
			line, err := buf.ReadString('\n')
			line = strings.TrimSpace(line)
			if line != "" {
				urllist = append(urllist, line)
			}
			if err != nil {
				if err == io.EOF {
					break
				} else {
					return
				}
			}
		}
		ChanUrlList = make(chan string, len(urllist))
		for filelen := 0; filelen < len(urllist); filelen++ {
			ChanUrlList <- urllist[filelen]
		}
		for i := 0; i < *br; i++ {
			wg.Add(1)
			go BeaconInitThread(&wg, &num, &mutex, ChanUrlList, *o)
		}

		close(ChanUrlList)
		wg.Wait()
	} else {
		if *o == "" {
			beaconinit(*u, "")
		} else {
			beaconinit(*u, *o)
		}
	}
}

func BeaconInitThread(wg *sync.WaitGroup, num *int, mutex *sync.Mutex, ChanUrlList chan string, filename string) {
	defer wg.Done()
	for one := range ChanUrlList {
		go incrNum(num, mutex)
		host := one
		beaconinit(host, filename)
	}
}

func incrNum(num *int, mutex *sync.Mutex) {
	mutex.Lock()
	*num = *num + 1
	mutex.Unlock()
}

func beaconinit(host string, filename string) {
	var resp_x64 *http.Response
	var err_x64 error
	var resp *http.Response
	var err error
	var is_x86 bool = true
	var is_x64 bool = true
	var bodyMap map[string]string = make(map[string]string)
	var tr *http.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	var client *http.Client = &http.Client{
		Timeout:   time.Duration(*t) * time.Second,
		Transport: tr,
	}
	var host_x86 string = host + "/" + MSFURI()
	var host_x64 string = host + "/" + MSFURI_X64()
	resp, err = client.Get(host_x86)
	resp_x64, err_x64 = client.Get(host_x64)

	if err != nil || resp.StatusCode != 200 {
		is_x86 = false
		if filename == "" {
			fmt.Println("error:", err, "beacon stager x86 not found")
		} else {
			fmt.Println("error:", err, "beacon stager x86 not found")
			bodyMap["URL"] = host
			if err != nil {
				bodyMap["error"] = err.Error() + "beacon stager x86 not found"
			} else {
				bodyMap["error"] = "beacon stager x86 not found"
			}
			var bodyerror string = MapToJson(bodyMap)
			JsonFileWrite(filename, bodyerror)
		}
	}
	if err_x64 != nil || resp_x64.StatusCode != 200 {
		is_x64 = false
		if filename == "" {
			fmt.Println("error:", err_x64, "beacon stager x64 not found")
		} else {
			fmt.Println("error", err_x64, "beacon stager x64 not found")
			bodyMap["URL"] = host
			if err_x64 != nil {
				bodyMap["error"] = err_x64.Error() + "beacon stager x64 not found"
			} else {
				bodyMap["error"] = "beacon stager x64 not found"
			}
			var bodyerror string = MapToJson(bodyMap)
			JsonFileWrite(filename, bodyerror)
		}
	}

	var body []byte
	if is_x86 != false {
		defer resp.Body.Close()
		body, _ = ioutil.ReadAll(resp.Body)
	}
	if is_x64 != false {
		defer resp_x64.Body.Close()
		body, _ = ioutil.ReadAll(resp_x64.Body)
	}
	if is_x64 == false && is_x86 == false {
		return
	}

	var buf []byte
	if bytes.Index(body, []byte("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")) == -1 {
		buf = decrypt_beacon(body)
	} else {
		fmt.Println("trial version")
		return
	}
	for _, value := range SUPPORTED_VERSIONS {
		if value == 3 {
			var offset int
			var offset1 int
			var offset2 int
			offset = bytes.Index(buf, []byte("\x69\x68\x69\x68\x69\x6b")) //3的兼容
			if offset != -1 {
				offset1 = bytes.Index(buf[offset:bytes.Count(buf, nil)-1], []byte("\x69\x6b\x69\x68\x69\x6b"))
				if offset1 != -1 {
					offset2 = bytes.Index(buf[offset : bytes.Count(buf, nil)-1][offset1:bytes.Count(buf[offset:bytes.Count(buf, nil)-1], nil)-1], []byte("\x69\x6a"))
					if offset2 != -1 {
						bodyMap = BeaconSettings(decode_config(buf[offset:bytes.Count(buf, nil)-1], value))
					}
				}
			}
		} else if value == 4 {
			var offset int
			var offset1 int
			var offset2 int
			offset = bytes.Index(buf, []byte("\x2e\x2f\x2e\x2f\x2e\x2c")) //4的兼容
			if offset != -1 {
				offset1 = bytes.Index(buf[offset:bytes.Count(buf, nil)-1], []byte("\x2e\x2c\x2e\x2f\x2e\x2c"))
				if offset1 != -1 {
					offset2 = bytes.Index(buf[offset : bytes.Count(buf, nil)-1][offset1:bytes.Count(buf[offset:bytes.Count(buf, nil)-1], nil)-1], []byte("\x2e"))
					if offset2 != -1 {
						bodyMap = BeaconSettings(decode_config(buf[offset:bytes.Count(buf, nil)-1], value))
					}
				}
			}
		}
	}
	bodyMap["URL"] = host
	var bodyText string = MapToJson(bodyMap)
	if filename == "" {
		fmt.Println(bodyText)
	} else {
		fmt.Println(host)
		JsonFileWrite(filename, bodyText)
	}
}

func JsonFileWrite(filename string, bodyText string) {
	var f *os.File
	var err1 error
	if checkFileIsExist(filename) { //如果文件存在
		f, err1 = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0666) //打开文件
		if err1 != nil {
			panic(err1)
		}
	} else {
		f, err1 = os.Create(filename) //创建文件
		if err1 != nil {
			panic(err1)
		}
	}
	defer f.Close()
	_, err1 = f.WriteString(bodyText)
	if err1 != nil {
		panic(err1)
	}
}

func checkFileIsExist(filename string) bool {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return false
	}
	return true
}

func checksum8(uri string, n int) bool {
	var sum8 int
	if len(uri) < 4 {
		return false
	} else {
		for i := 0; i < len(uri); i++ {
			sum8 += int(uri[i])
		}
		if (sum8 % 256) == n {
			return true
		}
	}
	return false
}

func MSFURI() string {
	var uri string
	var az19 string = "abcdefhijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567899"
	for {
		uri = string(az19[rand.Intn(len(az19))]) + string(az19[rand.Intn(len(az19))]) + string(az19[rand.Intn(len(az19))]) + string(az19[rand.Intn(len(az19))])
		if checksum8(uri, 92) {
			break
		}
	}
	return uri
}

func MSFURI_X64() string {
	var uri string
	var az19 string = "abcdefhijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567899"
	for {
		uri = string(az19[rand.Intn(len(az19))]) + string(az19[rand.Intn(len(az19))]) + string(az19[rand.Intn(len(az19))]) + string(az19[rand.Intn(len(az19))])
		if checksum8(uri, 93) {
			break
		}
	}
	return uri
}

//转换函数
func IntToBytes(n int, b int) []byte {
	switch b {
	case 1:
		var tmp int8 = int8(n)
		var bytesBuffer *bytes.Buffer = bytes.NewBuffer([]byte{})
		binary.Write(bytesBuffer, binary.BigEndian, &tmp)
		return bytesBuffer.Bytes()
	case 2:
		var tmp int16 = int16(n)
		var bytesBuffer *bytes.Buffer = bytes.NewBuffer([]byte{})
		binary.Write(bytesBuffer, binary.BigEndian, &tmp)
		return bytesBuffer.Bytes()
	case 3, 4:
		var tmp int32 = int32(n)
		var bytesBuffer *bytes.Buffer = bytes.NewBuffer([]byte{})
		binary.Write(bytesBuffer, binary.BigEndian, &tmp)
		return bytesBuffer.Bytes()
	}
	return nil
}

type packedSetting_init_type struct {
	pos                   int
	datatype              int
	length                int
	isBlob                bool
	isHeaders             bool
	isIpAddress           bool
	isBool                bool
	isDate                bool
	isMalleableStream     bool
	boolFalseValue        int
	isProcInjectTransform bool
	hashBlob              bool
	enum                  map[byte]string
	mask                  map[byte]string
	transform_get         string
	transform_post        string
}

type packedSetting_init_typeOptions func(*packedSetting_init_type)

func Writepos(pos int) packedSetting_init_typeOptions {
	return func(p *packedSetting_init_type) {
		p.pos = pos
	}
}

func Writedatatype(datatype int) packedSetting_init_typeOptions {
	return func(p *packedSetting_init_type) {
		p.datatype = datatype
	}
}

func Writelength(length int) packedSetting_init_typeOptions {
	return func(p *packedSetting_init_type) {
		p.length = length
	}
}

func WriteisBlob(isBlob bool) packedSetting_init_typeOptions {
	return func(p *packedSetting_init_type) {
		p.isBlob = isBlob
	}
}
func WriteisHeaders(isHeaders bool) packedSetting_init_typeOptions {
	return func(p *packedSetting_init_type) {
		p.isHeaders = isHeaders
	}
}
func WriteisIpAddress(isIpAddress bool) packedSetting_init_typeOptions {
	return func(p *packedSetting_init_type) {
		p.isIpAddress = isIpAddress
	}
}
func WriteisBool(isBool bool) packedSetting_init_typeOptions {
	return func(p *packedSetting_init_type) {
		p.isBool = isBool
	}
}

func WriteisDate(isDate bool) packedSetting_init_typeOptions {
	return func(p *packedSetting_init_type) {
		p.isDate = isDate
	}
}

func WriteisMalleableStream(isMalleableStream bool) packedSetting_init_typeOptions {
	return func(p *packedSetting_init_type) {
		p.isMalleableStream = isMalleableStream
	}
}

func WriteboolFalseValue(boolFalseValue int) packedSetting_init_typeOptions {
	return func(p *packedSetting_init_type) {
		p.boolFalseValue = boolFalseValue
	}
}

func WriteisProcInjectTransform(isProcInjectTransform bool) packedSetting_init_typeOptions {
	return func(p *packedSetting_init_type) {
		p.isProcInjectTransform = isProcInjectTransform
	}
}

func WritehashBlob(hashBlob bool) packedSetting_init_typeOptions {
	return func(p *packedSetting_init_type) {
		p.hashBlob = hashBlob
	}
}
func Writeenum(enum map[byte]string) packedSetting_init_typeOptions {
	return func(p *packedSetting_init_type) {
		p.enum = enum
	}
}
func Writemask(mask map[byte]string) packedSetting_init_typeOptions {
	return func(p *packedSetting_init_type) {
		p.mask = mask
	}
}

func DefaultpackedSetting_init_type(p *packedSetting_init_type) *packedSetting_init_type {
	p.isBlob = false
	p.isHeaders = false
	p.isIpAddress = false
	p.isBool = false
	p.isDate = false
	p.isMalleableStream = false
	p.boolFalseValue = 0
	p.isProcInjectTransform = false
	p.hashBlob = false
	p.enum = make(map[byte]string)
	p.mask = make(map[byte]string)
	p.transform_get = ""
	p.transform_post = ""
	return p
}

func packedSettinginit(pos, datatype, length int, options ...packedSetting_init_typeOptions) *packedSetting_init_type {
	var p *packedSetting_init_type = &packedSetting_init_type{
		pos:      pos,
		datatype: datatype,
		length:   length,
	}
	p = DefaultpackedSetting_init_type(p)
	var op packedSetting_init_typeOptions
	for _, op = range options {
		// 遍历调用函数，进行数据修改
		op(p)
	}
	if datatype == TYPE_STR && length == 0 { //这里没处理TYPE_STR
		fmt.Println("if datatype is TYPE_STR then length must not be 0")
		os.Exit(1)
		//返回一个错误
	}
	if datatype == TYPE_SHORT {
		p.length = 2
	} else if datatype == TYPE_INT {
		p.length = 4
	}
	return p
}

func binary_repr(p *packedSetting_init_type) []byte {
	var self_repr []byte = make([]byte, 6)
	self_repr = append(self_repr[:1], IntToBytes(p.pos, 1)...)
	self_repr = append(self_repr[:3], IntToBytes(p.datatype, 1)...)
	self_repr = append(self_repr[:4], IntToBytes(p.length, 2)...)
	return self_repr
}

func BeaconSettings(full_config_data []byte) map[string]string {
	var BEACON_TYPE map[byte]string = map[byte]string{
		0x0:  "HTTP",
		0x1:  "Hybrid HTTP DNS",
		0x2:  "SMB",
		0x4:  "TCP",
		0x8:  "HTTPS",
		0x10: "Bind TCP",
	}
	var ACCESS_TYPE map[byte]string = map[byte]string{
		0x0: "Use proxy server (manual)",
		0x1: "Use direct connection",
		0x2: "Use IE settings",
		0x4: "Use proxy server (credentials)",
	}
	var EXECUTE_TYPE map[byte]string = map[byte]string{
		0x1: "CreateThread",
		0x2: "SetThreadContext",
		0x3: "CreateRemoteThread",
		0x4: "RtlCreateUserThread",
		0x5: "NtQueueApcThread",
		0x6: "None",
		0x7: "None",
		0x8: "NtQueueApcThread-s",
	}
	var ALLOCATION_FUNCTIONS map[byte]string = map[byte]string{
		0: "VirtualAllocEx",
		1: "NtMapViewOfSection",
	}
	var ROTATE_STRATEGY map[byte]string = map[byte]string{
		1:  "round-robin",
		2:  "random",
		3:  "failover",
		4:  "failover-5x",
		5:  "failover-50x",
		6:  "failover-100x",
		7:  "failover-1m",
		8:  "failover-5m",
		9:  "failover-15m",
		10: "failover-30m",
		11: "failover-1h",
		12: "failover-3h",
		13: "failover-6h",
		14: "failover-12h",
		16: "failover-1d",
		17: "rotate-1m",
		18: "rotate-5m",
		19: "rotate-15m",
		20: "rotate-30m",
		21: "rotate-1h",
		22: "rotate-3h",
		23: "rotate-6h",
		24: "rotate-12h",
		25: "rotate-1d",
	}
	var BeaconConfig map[string]string = make(map[string]string)
	BeaconConfig["BeaconType"] = pretty_repr(full_config_data, packedSettinginit(1, 1, 0, Writemask(BEACON_TYPE)))
	BeaconConfig["Port"] = pretty_repr(full_config_data, packedSettinginit(2, 1, 0))
	BeaconConfig["SleepTime"] = pretty_repr(full_config_data, packedSettinginit(3, 2, 0))
	BeaconConfig["MaxGetSize"] = pretty_repr(full_config_data, packedSettinginit(4, 2, 0))
	BeaconConfig["Jitter"] = pretty_repr(full_config_data, packedSettinginit(5, 1, 0))
	BeaconConfig["MaxDNS"] = pretty_repr(full_config_data, packedSettinginit(6, 1, 0))
	//BeaconConfig["PublicKey"] = pretty_repr(full_config_data, packedSettinginit(7, 3, 256, WriteisBlob(true)))
	BeaconConfig["PublicKey_MD5"] = pretty_repr(full_config_data, packedSettinginit(7, 3, 256, WriteisBlob(true), WritehashBlob(true)))
	BeaconConfig["C2Server"] = pretty_repr(full_config_data, packedSettinginit(8, 3, 256))
	BeaconConfig["UserAgent"] = pretty_repr(full_config_data, packedSettinginit(9, 3, 128))
	BeaconConfig["HttpPostUri"] = pretty_repr(full_config_data, packedSettinginit(10, 3, 64))
	BeaconConfig["Malleable_C2_Instructions"] = pretty_repr(full_config_data, packedSettinginit(11, 3, 256, WriteisBlob(true), WriteisMalleableStream(true)))
	BeaconConfig["HttpGet_Metadata"] = pretty_repr(full_config_data, packedSettinginit(12, 3, 256, WriteisHeaders(true)))
	BeaconConfig["HttpPost_Metadata"] = pretty_repr(full_config_data, packedSettinginit(13, 3, 256, WriteisHeaders(true)))
	//BeaconConfig["SpawnTo"] = pretty_repr(full_config_data, packedSettinginit(14, 3, 16, WriteisBlob(true)))
	BeaconConfig["PipeName"] = pretty_repr(full_config_data, packedSettinginit(15, 3, 128))
	BeaconConfig["DNS_Idle"] = pretty_repr(full_config_data, packedSettinginit(19, 2, 0, WriteisIpAddress(true)))
	BeaconConfig["DNS_Sleep"] = pretty_repr(full_config_data, packedSettinginit(20, 2, 0))
	BeaconConfig["SSH_Host"] = pretty_repr(full_config_data, packedSettinginit(21, 2, 0))
	BeaconConfig["SSH_Port"] = pretty_repr(full_config_data, packedSettinginit(22, 1, 0))
	BeaconConfig["SSH_Username"] = pretty_repr(full_config_data, packedSettinginit(23, 3, 128))
	BeaconConfig["SSH_Password_Plaintext"] = pretty_repr(full_config_data, packedSettinginit(24, 3, 128))
	BeaconConfig["SSH_Password_Pubkey"] = pretty_repr(full_config_data, packedSettinginit(25, 3, 6144))
	BeaconConfig["SSH_Banner"] = pretty_repr(full_config_data, packedSettinginit(54, 3, 128))
	BeaconConfig["HttpGet_Verb"] = pretty_repr(full_config_data, packedSettinginit(26, 3, 16))
	BeaconConfig["HttpPost_Verb"] = pretty_repr(full_config_data, packedSettinginit(27, 3, 16))
	BeaconConfig["HttpPostChunk"] = pretty_repr(full_config_data, packedSettinginit(28, 2, 0))
	BeaconConfig["Spawnto_x86"] = pretty_repr(full_config_data, packedSettinginit(29, 3, 64))
	BeaconConfig["Spawnto_x64"] = pretty_repr(full_config_data, packedSettinginit(30, 3, 64))
	BeaconConfig["CryptoScheme"] = pretty_repr(full_config_data, packedSettinginit(31, 1, 0))
	BeaconConfig["Proxy_Config"] = pretty_repr(full_config_data, packedSettinginit(32, 3, 128))
	BeaconConfig["Proxy_User"] = pretty_repr(full_config_data, packedSettinginit(33, 3, 64))
	BeaconConfig["Proxy_Password"] = pretty_repr(full_config_data, packedSettinginit(34, 3, 64))
	BeaconConfig["Proxy_Behavior"] = pretty_repr(full_config_data, packedSettinginit(35, 1, 64, Writeenum(ACCESS_TYPE)))
	BeaconConfig["Watermark_Hash"] = pretty_repr(full_config_data, packedSettinginit(36, 3, 32))
	BeaconConfig["Watermark"] = pretty_repr(full_config_data, packedSettinginit(37, 2, 0))
	BeaconConfig["bStageCleanup"] = pretty_repr(full_config_data, packedSettinginit(38, 1, 0, WriteisBool(true)))
	BeaconConfig["bCFGCaution"] = pretty_repr(full_config_data, packedSettinginit(39, 1, 0, WriteisBool(true)))
	BeaconConfig["KillDate"] = pretty_repr(full_config_data, packedSettinginit(40, 2, 0, WriteisDate(true)))
	BeaconConfig["bProcInject_StartRWX"] = pretty_repr(full_config_data, packedSettinginit(43, 1, 0, WriteisBool(true), WriteboolFalseValue(4)))
	BeaconConfig["bProcInject_UseRWX"] = pretty_repr(full_config_data, packedSettinginit(44, 1, 0, WriteisBool(true), WriteboolFalseValue(32)))
	BeaconConfig["bProcInject_MinAllocSize"] = pretty_repr(full_config_data, packedSettinginit(45, 2, 0))
	BeaconConfig["ProcInject_PrependAppend_x86"] = pretty_repr(full_config_data, packedSettinginit(46, 3, 256, WriteisBlob(true), WriteisProcInjectTransform(true)))
	BeaconConfig["ProcInject_PrependAppend_x64"] = pretty_repr(full_config_data, packedSettinginit(47, 3, 256, WriteisBlob(true), WriteisProcInjectTransform(true)))
	BeaconConfig["ProcInject_Execute"] = pretty_repr(full_config_data, packedSettinginit(51, 3, 128, WriteisBlob(true), Writeenum(EXECUTE_TYPE)))
	BeaconConfig["ProcInject_AllocationMethod"] = pretty_repr(full_config_data, packedSettinginit(52, 1, 0, Writeenum(ALLOCATION_FUNCTIONS)))
	//BeaconConfig["ProcInject_Stub"] = pretty_repr(full_config_data, packedSettinginit(53, 3, 16, WriteisBlob(true)))
	BeaconConfig["bUsesCookies"] = pretty_repr(full_config_data, packedSettinginit(50, 1, 0, WriteisBool(true)))
	BeaconConfig["HostHeader"] = pretty_repr(full_config_data, packedSettinginit(54, 3, 128))
	//BeaconConfig["smbFrameHeader"] = pretty_repr(full_config_data, packedSettinginit(57, 3, 128, WritehashBlob(true)))
	//BeaconConfig["tcpFrameHeader"] = pretty_repr(full_config_data, packedSettinginit(58, 3, 128, WritehashBlob(true)))
	BeaconConfig["headersToRemove"] = pretty_repr(full_config_data, packedSettinginit(59, 3, 64))
	BeaconConfig["DNS_Beaconing"] = pretty_repr(full_config_data, packedSettinginit(60, 3, 33))
	BeaconConfig["DNS_get_TypeA"] = pretty_repr(full_config_data, packedSettinginit(61, 3, 33))
	BeaconConfig["DNS_get_TypeAAAA"] = pretty_repr(full_config_data, packedSettinginit(62, 3, 33))
	BeaconConfig["DNS_get_TypeTXT"] = pretty_repr(full_config_data, packedSettinginit(63, 3, 33))
	BeaconConfig["DNS_put_metadata"] = pretty_repr(full_config_data, packedSettinginit(64, 3, 33))
	BeaconConfig["DNS_put_output"] = pretty_repr(full_config_data, packedSettinginit(65, 3, 33))
	BeaconConfig["DNS_resolver"] = pretty_repr(full_config_data, packedSettinginit(66, 3, 15))
	BeaconConfig["DNS_strategy"] = pretty_repr(full_config_data, packedSettinginit(67, 1, 0, Writeenum(ROTATE_STRATEGY)))
	BeaconConfig["DNS_strategy_rotate_seconds"] = pretty_repr(full_config_data, packedSettinginit(68, 2, 0))
	BeaconConfig["DNS_strategy_fail_x"] = pretty_repr(full_config_data, packedSettinginit(69, 2, 0))
	BeaconConfig["DNS_strategy_fail_seconds"] = pretty_repr(full_config_data, packedSettinginit(70, 2, 0))
	BeaconConfig["Retry_Max_Attempts"] = pretty_repr(full_config_data, packedSettinginit(71, 2, 0))
	BeaconConfig["Retry_Increase_Attempts"] = pretty_repr(full_config_data, packedSettinginit(72, 2, 0))
	BeaconConfig["Retry_Increase_Attempts"] = pretty_repr(full_config_data, packedSettinginit(73, 2, 0))
	return BeaconConfig
}

//方法，接受4个值，给s赋值

func InetNtoA(ip []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func BytesToInt(bys []byte) int {
	var bytebuff *bytes.Buffer = bytes.NewBuffer(bys)
	var data int64
	binary.Read(bytebuff, binary.BigEndian, &data)
	return int(data)
}

func pretty_repr(data []byte, p *packedSetting_init_type) string {
	var data_offset int = bytes.Index(data, binary_repr(p))
	if data_offset < 0 && p.datatype == TYPE_STR { //这里用的是confConsts.TYPE_STR
		p.length = 16
		for {
			if p.length < 2048 {
				p.length = p.length * 2
				data_offset = bytes.Index(data, binary_repr(p))
			}
			if data_offset > 0 {
				break
			}
			if p.length >= 2048 {
				break
			}
		}
	}
	if data_offset < 0 {
		return "Not Found"
	}
	var repr_len int = len(binary_repr(p))
	var conf_data []byte = data[data_offset+repr_len : data_offset+repr_len+p.length]
	if p.datatype == TYPE_SHORT { //confConsts.TYPE_SHORT:
		var conf_data uint16 = binary.BigEndian.Uint16(conf_data)
		if p.isBool {
			if conf_data == uint16(p.boolFalseValue) {
				var ret string = "false"
				return ret
			} else {
				var ret string = "true"
				return ret
			}
		} else if len(p.enum) > 0 {
			return p.enum[byte(conf_data)]
		} else if len(p.mask) > 0 {
			var ret_arr string
			var v string
			var k byte
			for k, v = range p.mask {
				if k == 0 && k == byte(conf_data) {
					ret_arr = ret_arr + " " + v
				}
				if (k & byte(conf_data)) != 0 {
					ret_arr = ret_arr + " " + v
				}
			}
			return ret_arr
		} else {
			return fmt.Sprint(conf_data)
		}
	} else if p.datatype == TYPE_INT { // confConsts.TYPE_INT
		if p.isIpAddress {
			return InetNtoA(conf_data)
		} else {
			var conf_data uint32 = binary.BigEndian.Uint32(conf_data)
			if p.isDate && (conf_data != 0) {
				var year string = fmt.Sprint(conf_data)[0:4]
				var mouth string = fmt.Sprint(conf_data)[4:6]
				var day string = fmt.Sprint(conf_data)[6:]
				return fmt.Sprintf("%v-%v-%v", year, mouth, day)
			}
			return fmt.Sprint(conf_data)
		}
	}
	if p.isBlob {
		if len(p.enum) > 0 {
			var i int = 0
			var ret_arr string
			for {
				if i > len(conf_data) {
					break
				}
				var v byte = conf_data[i]
				if v == 0 {
					return ret_arr
				}
				var ret_arr_tmp string = p.enum[v]
				if ret_arr_tmp != "None" {
					ret_arr = ret_arr + " " + ret_arr_tmp
					i++
				} else {
					var ProcInject_Execute_tmp_byte1 []byte
					var ProcInject_Execute_tmp_byte2 []byte
					var j int = i + 3
					for j < len(conf_data) {
						if conf_data[j] > 20 {
							ProcInject_Execute_tmp_byte1 = append(ProcInject_Execute_tmp_byte1, conf_data[j])
							j++
						} else {
							j++
						}
						if len(ProcInject_Execute_tmp_byte1) > 1 && conf_data[j] == 0x00 {
							break
						}
					}
					for j < len(conf_data) {
						if conf_data[j] > 20 {
							ProcInject_Execute_tmp_byte2 = append(ProcInject_Execute_tmp_byte2, conf_data[j])
							j++
						} else {
							j++
						}
						if len(ProcInject_Execute_tmp_byte2) > 1 && conf_data[j] == 0x00 {
							break
						}
					}
					ret_arr = fmt.Sprintln(string(ProcInject_Execute_tmp_byte1) + ":" + string(ProcInject_Execute_tmp_byte2))
					i = j + 1
				}
			}
		}
	}
	if p.isProcInjectTransform {
		var conf_data_tmp []byte = make([]byte, len(conf_data))
		if bytes.Compare(conf_data_tmp, conf_data) == 0 {
			return "Empty"
		}
		var ret_arr string
		var prepend_length uint32 = binary.BigEndian.Uint32(conf_data[0:4])
		var prepend []byte = conf_data[4 : 4+prepend_length]
		var append_length_offset uint32 = 4 + prepend_length
		var append_length uint32 = binary.BigEndian.Uint32(conf_data[append_length_offset : append_length_offset+4])
		var append []byte = conf_data[append_length_offset+4 : append_length_offset+4+append_length]
		for i := 0; i < len(prepend); i++ {
			ret_arr = ret_arr + fmt.Sprintf("\\x%x", prepend[i])
		}
		var append_length_byte []byte = make([]byte, 4)
		binary.BigEndian.PutUint32(append_length_byte, append_length)
		if append_length < 256 && bytes.Compare(append_length_byte, append) == 0 {
			ret_arr = ret_arr + " " + fmt.Sprintln(append)
		} else {
			ret_arr = ret_arr + " " + "Empty"
		}
		return ret_arr
	}
	if p.isMalleableStream {
		var prog string = ""
		var buf *bytes.Buffer = bytes.NewBuffer(conf_data)
		for {
			var op int = read_dword_be(buf, 4)
			if op == 0 {
				break
			} else if op == 1 {
				var l int = read_dword_be(buf, 4)
				prog = prog + " " + fmt.Sprintf("Remove %v bytes from the end", l)
			} else if op == 2 {
				var l int = read_dword_be(buf, 4)
				prog = prog + " " + fmt.Sprintf("Remove %v bytes from the beginning", l)
			} else if op == 3 {
				prog = prog + " " + fmt.Sprintf("Base64 decode")
			} else if op == 8 {
				prog = prog + " " + fmt.Sprintf("NetBIOS decode 'a'")
			} else if op == 11 {
				prog = prog + " " + fmt.Sprintf("NetBIOS decode 'A'")
			} else if op == 13 {
				prog = prog + " " + fmt.Sprintf("Base64 URL-safe decode")
			} else if op == 15 {
				prog = prog + " " + fmt.Sprintf("XOR mask w/ random key")
			}
		}
		return prog
	}
	if p.hashBlob {
		var x string = fmt.Sprintf("%x", md5.Sum(bytes.TrimRight(conf_data, "\x00")))
		return x
	}
	if p.isHeaders {
		var current_category string
		var trans map[string]string = map[string]string{
			"ConstHeaders": "",
			"ConstParams":  "",
			"Metadata":     "",
			"SessionId":    "",
			"Output":       "",
		}
		var TSTEPS map[int]string = map[int]string{
			1:  "append ",
			2:  "prepend ",
			3:  "base64 ",
			4:  "print ",
			5:  "parameter ",
			6:  "header ",
			7:  "build ",
			8:  "netbios ",
			9:  "const_parameter ",
			10: "const_header ",
			11: "netbiosu ",
			12: "uri_append ",
			13: "base64url ",
			14: "strrep ",
			15: "mask ",
			16: "const_host_header ",
		}
		var buf *bytes.Buffer = bytes.NewBuffer(conf_data)
		current_category = "Constants"
		var intarr []int = []int{1, 2, 5, 6}
		var intarr2 []int = []int{10, 16, 9}
		var intarr3 []int = []int{3, 4, 13, 8, 11, 12, 15}
		for {
			var tstep int = read_dword_be(buf, 4)
			if tstep == 7 {
				var name int = read_dword_be(buf, 4)
				if p.pos == 12 {
					current_category = "Metadata"
				} else {
					if name == 0 {
						current_category = "SessionId"
					} else {
						current_category = "Output"
					}
				}
			} else if IsContain(intarr, tstep) {
				var length int = read_dword_be(buf, 4)
				var c []byte = make([]byte, length)
				buf.Read(c)
				step_data := string(c)
				trans[current_category] = trans[current_category] + TSTEPS[tstep] + " \"" + step_data + "\""
			} else if IsContain(intarr2, tstep) {
				var length int = read_dword_be(buf, 4)
				var c []byte = make([]byte, length)
				buf.Read(c)
				var step_data string = string(c)
				if tstep == 9 {
					trans["ConstParams"] = trans["ConstParams"] + " " + step_data
				} else {
					trans["ConstHeaders"] = trans["ConstHeaders"] + " " + step_data
				}
			} else if IsContain(intarr3, tstep) {
				trans[current_category] = trans[current_category] + TSTEPS[tstep]
			} else {
				break
			}
		}
		if p.pos == 12 {
			p.transform_get = MapToJson(trans)
		} else {
			p.transform_post = MapToJson(trans)
		}
		return MapToJson(trans)
	}
	var conf_data_tmp []byte = bytes.TrimRight(conf_data, "\x00")
	return string(conf_data_tmp)
}

func MapToJson(param map[string]string) string {
	dataType, _ := json.Marshal(param)
	dataString := string(dataType) + "\r\n"
	return dataString
}

func read_dword_be(data *bytes.Buffer, length int) int {
	var c []byte = make([]byte, length)
	data.Read(c)
	return int(binary.BigEndian.Uint32(c))
}

func IsContain(items []int, item int) bool {
	var eachItem int
	for _, eachItem = range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

func decode_config(data_buf []byte, version int) []byte {
	var XORBYTES byte
	if version == 3 {
		XORBYTES = 0x69
	} else if version == 4 {
		XORBYTES = 0x2e
	}
	var data_decode_buf []byte
	for i := 0; i < len(data_buf); i++ {
		data_decode_buf = append(data_decode_buf, data_buf[i]^XORBYTES) //0x2e是4版本的key 这里还没写兼容3的key
	}
	return data_decode_buf
}

func decrypt_beacon(buf []byte) []byte {
	var offset int = bytes.Index(buf, []byte("\xff\xff\xff"))
	if offset == -1 {
		return nil
	}

	offset += 3

	var key uint32 = binary.LittleEndian.Uint32(buf[offset : offset+4])
	//fmt.Println("key", key)

	//size := binary.LittleEndian.Uint32(buf[offset+4:offset+8]) ^ key
	//fmt.Println("size", size)

	var head_enc uint32 = binary.LittleEndian.Uint32(buf[offset+8:offset+12]) ^ key
	//fmt.Println("head_enc", head_enc)

	var head uint32 = head_enc & 0xffff
	//fmt.Println("head", head)

	if head == 0x5a4d || head == 0x9090 {

		var decoded_data []byte
		for i := offset/4 + 2; i <= len(buf)/4-4; i++ {
			var a uint32 = binary.LittleEndian.Uint32(buf[i*4 : i*4+4])
			//fmt.Println("a", a)

			var b uint32 = binary.LittleEndian.Uint32(buf[i*4+4 : i*4+8])
			//fmt.Println("b", b)

			var c uint32 = a ^ b
			//fmt.Println("c", c)

			var tmp []byte = make([]byte, 4)
			binary.LittleEndian.PutUint32(tmp, c)
			decoded_data = append(decoded_data, tmp...)

			//fmt.Println("decoded_data", decoded_data)
			// if i == 21 {
			// 	return decoded_data
			// }
		}
		return decoded_data
		//fmt.Println(confConsts)
	}

	return nil
}
