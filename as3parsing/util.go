package as3parsing

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/f5devcentral/f5-bigip-rest-go/utils"
)

func refers(obj interface{}) string {
	t := reflect.TypeOf(obj).Kind().String()
	switch t {
	case "map":
		mobj := obj.(map[string]interface{})
		if use, f := mobj["use"]; f {
			return use.(string)
		} else if bigip, f := mobj["bigip"]; f {
			return bigip.(string)
		}
	case "string":
		return obj.(string)
	}

	return ""
}

func tlsRefers(name, pf string, obj interface{}) string {
	if t := reflect.TypeOf(obj).Kind().String(); t == "string" {
		return fmt.Sprintf("%s/%s", pf, name)
	} else {
		mobj := obj.(map[string]interface{})
		if value, f := mobj["bigip"]; f {
			return value.(string)
		} else if value, f := mobj["use"]; f {
			return fmt.Sprintf("%s/%s", pf, value)
		}
	}
	return ""
}

func restname(kind, as3name string) string {
	if k, f := properties[kind]; f {
		if n, f := k[as3name]; f {
			return n.RestName
		}
	}
	return as3name
}

func typeString(v interface{}) bool {
	return reflect.TypeOf(v).Kind().String() == "string"
}

// func typeMap(v interface{}) bool {
// 	return reflect.TypeOf(v).Kind().String() == "map"
// }

func renamePersist(t string) string {
	var rt string
	switch t {
	case "destination-address":
		rt = "dest_addr"
	case "tls-session-id":
		rt = "ssl"
	case "sip-info":
		rt = "sip_info"
	case "source-address":
		rt = "source_addr"
	default:
		rt = t
	}
	return rt
}

func referToAddr(obj map[string]interface{}, name string) string {
	if sa, f := obj["ltm/virtual-address/"+name]; f {
		if va, f := sa.(map[string]interface{})["virtualAddress"]; f {
			return va.(string)
		}
	}
	return ""
}

func camelCase(s string) string {
	ss := strings.Split(s, "-")
	for i, w := range ss[1:] {
		ss[i+1] = strings.ToUpper(w[:1]) + w[1:]
	}

	return strings.Join(ss, "")
}

func indexedName(i int, name string) string {
	if i == 0 {
		return name
	} else {
		return fmt.Sprintf("%s-%d-", name, i)
	}
}

func waitForAs3Service() {
	slog := utils.LogFromContext(context.TODO())
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 10 * time.Second,
	}
	as3ep := fmt.Sprintf("%s/any", as3Service)
	if strings.HasPrefix(as3Service, bigip.URL) {
		as3ep = fmt.Sprintf("%s/mgmt/shared/appsvcs/info", bigip.URL)
	}
	tryGet := func() error {
		if status, response, err := utils.HttpRequest(
			client, as3ep, "GET", "", map[string]string{
				"Authorization": bigip.Authorization,
			}); err != nil {
			return err
		} else if status == 200 {
			return nil
		} else {
			return fmt.Errorf("as3 parser service response with code %d, response: %s", status, response)
		}
	}
	interval := 10
	times := 60
	for i := 0; i < times; i++ {
		if err := tryGet(); err != nil {
			slog.Warnf("%s, timeout %d", err.Error(), times-i)
			time.Sleep(time.Duration(interval) * time.Second)
		} else {
			return
		}
	}
	panic(fmt.Errorf("as3 parser service is not available, abort"))
}

func newParseContext(ctx context.Context) *ParseContext {
	return &ParseContext{ctx}
}

func newConvertContext(ctx context.Context) *ConvertContext {
	return &ConvertContext{ctx}
}
