package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/nlnwa/jhove-warc-report-parser/jhove"
	"os"
)

func main() {
	var verbose bool
	var output string

	flag.StringVar(&output, "output", "json", "json or text")
	flag.BoolVar(&verbose, "verbose", false, "output all non-compliant records")
	flag.Parse()

	if len(flag.Args()) == 0 {
		flag.Usage()
		return
	}
	path := flag.Arg(0)

	var err error
	var result *jhove.Report
	if result, err = jhove.ParseReport(path, verbose); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if output == "json" {
		var bytes []byte
		if bytes, err = json.Marshal(*result); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(string(bytes))
	} else {
		fmt.Println(result)
	}

}
