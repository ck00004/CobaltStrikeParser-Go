# CobaltStrikeParser-go
Golang parser for CobaltStrike Beacon's configuration, reference CobaltStrikeParser project

CobaltStrike Beacon 配置解析器，参考CobaltStrikeParser项目进行开发

# 使用

```
go build -o CobaltStrikeParser.exe main.go

CobaltStrikeParser.exe -u http://127.0.0.1 -o c2configflie.txt -t 10
CobaltStrikeParser.exe -f c2urlflie -o c2configflie.txt -t 10 -br 5

-u   This can be a url (if started with http/s)
-f   This can be a file path (if started with http/s)
-o   out file
-t   timeout
-br  thread,import file valid. default:1
```

# 使用作为函数调用

不要调用 beaconscan.BeaconInitThread 这是多线程模式启动

beaconscan.Beaconinit(url, fliename, timeout)

当flienmae 为""时返回数据返回json格式的数据和错误信息

当fliename 不为""时会将json数据写入flienmae中


```
url := "https://www.google.com"
timeout : = 5
beaconinfo, err := beaconscan.Beaconinit(url, "", timeout)
if err != nil {
    fmt.Println(err)
} else {
    if beaconinfo.IsCobaltStrike {
        fmt.Println(beaconscan.StructToJson(beaconinfo))
    } else if beaconinfo.Confidence > 0 {
        fmt.Println(url + beaconinfo.ConfidenceInfo)
    } else {
        fmt.Println(url + "Not CobaltStrike")
    }
}
```
