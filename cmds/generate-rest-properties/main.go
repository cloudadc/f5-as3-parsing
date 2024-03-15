package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"gitee.com/zongzw/f5-as3-parsing/as3parsing"
	"github.com/f5devcentral/f5-bigip-rest-go/utils"
)

func main() {
	var in, out string

	flag.StringVar(&in, "in", "", "the input file containing as3 properities, \n  the file can get "+
		"from installed /var/config/rest/iapps/f5-appsvcs/lib/properties.json \n  or "+
		"https://github.com/F5Networks/f5-appsvcs-extension/blob/main/src/lib/properties.json")
	flag.StringVar(&out, "out", "", "the output file containing rest properties, \n  the file will be "+
		"embedded in as3parsing package, see as3parsing/rest.properties.json")

	flag.Parse()

	if in == "" || out == "" {
		flag.Usage()
		os.Exit(1)
	}
	slog := utils.LogFromContext(context.TODO())
	slog.Infof("in : %s", in)
	slog.Infof("out: %s", out)

	if _, err := os.Stat(out); err == nil {
		slog.Warnf("%s already exists", out)
		r := bufio.NewReader(os.Stdin)
		fmt.Fprintf(os.Stdout, "Overwrite anyway(Y/n): ")
		yn, _ := r.ReadString('\n')
		slog.Infof("input: %s", yn)
		yn = strings.Trim(yn, "\n")
		if !(yn == "" || yn == "Y" || yn == "y") {
			slog.Infof("not overwrite, quit.")
			os.Exit(0)
		}
	}
	if err := as3parsing.AS3ToRestProperties(in, out); err != nil {
		slog.Errorf("failed to generate rest properties json file: %s", err.Error())
		os.Exit(1)
	} else {
		slog.Infof("done of generating: %s", out)
	}
}
