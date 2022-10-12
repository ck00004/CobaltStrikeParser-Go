package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/ck00004/CobaltStrikeParser-Go/beaconscan"
)

var u = flag.String("u", "", "This can be a url (if started with http/s)")
var f = flag.String("f", "", "This can be a file path (if started with http/s)")
var o = flag.String("o", "", "out file")
var t = flag.Int("t", 30, "timeout. default:20")
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
			go beaconscan.BeaconInitThread(&wg, &num, &mutex, ChanUrlList, *o, *t)
		}

		close(ChanUrlList)
		wg.Wait()
	} else {
		if *o == "" {
			beaconinfo, err := beaconscan.Beaconinit(*u, "", *t)
			if err != nil {
				fmt.Println(err)
			} else {
				if beaconinfo.IsCobaltStrike {
					fmt.Println(beaconscan.StructToJson(beaconinfo))
				} else if beaconinfo.Confidence > 0 {
					fmt.Println(*u + beaconinfo.ConfidenceInfo)
				} else {
					fmt.Println(*u + "Not CobaltStrike")
				}
			}
		} else {
			beaconscan.Beaconinit(*u, *o, *t)
		}
	}
}
