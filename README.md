# CobaltStrikeParser-go
Golang parser for CobaltStrike Beacon's configuration, reference CobaltStrikeParser project

CobaltStrike Beacon 配置解析器，参考CobaltStrikeParser项目进行开发

# 使用

```
go build -o CobaltStrikeParser.exe main.go

CobaltStrikeParser.exe -u http://127.0.0.1 -o c2configflie.txt -t 10
CobaltStrikeParser.exe -f c2urlflie -o c2configflie.txt -t 10
```