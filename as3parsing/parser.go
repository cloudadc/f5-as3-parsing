package as3parsing

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/f5devcentral/f5-bigip-rest-go/utils"
)

func (pc *ParseContext) parse(src map[string]interface{}, objs map[string]interface{}) error {
	var err error = nil
	for k, v := range src {
		t := reflect.TypeOf(v).Kind().String()
		switch t {
		case "map":
			err = pc.parsemap(k, v, objs)
		case "slice":
		case "string":
		case "bool":
		case "float64":
		default:
			err = fmt.Errorf("unknown type found: %s for %s", t, k)
		}
		if err != nil {
			break
		}
	}
	return err
}

func (pc *ParseContext) parsemap(k string, v interface{}, objs map[string]interface{}) error {
	var err error = nil
	if cls, f := v.(map[string]interface{})["class"]; f {
		switch cls.(string) {
		case "AS3":
			err = pc.parse(v.(map[string]interface{}), objs)
		case "ADC":
			err = pc.parse(v.(map[string]interface{}), objs)
		case "Controls":
		case "Tenant":
			obj := map[string]interface{}{}
			objs[k] = obj
			err = pc.parse(v.(map[string]interface{}), obj)
		case "Application":
			obj := map[string]interface{}{}
			objs[k] = obj
			err = pc.parse(v.(map[string]interface{}), obj)
		case "Pool":
			resname := "ltm/pool/" + k
			objs[resname] = v
			err = pc.parse(v.(map[string]interface{}), objs)
		case "Monitor":
			if t, f := v.(map[string]interface{})["monitorType"]; f {
				if t == "icmp" {
					t = "gateway-icmp"
				}
				resname := fmt.Sprintf("ltm/monitor/%s/%s", t, k)
				objs[resname] = v
			}
		case "Persist":
			err = pc.parsePersist(k, v, objs)
		case "iRule":
			restname := "ltm/rule/" + k
			objs[restname] = v
		case "SNAT_Pool":
			restname := "ltm/snatpool/" + k
			objs[restname] = v
		case "Service_Address":
			restname := "ltm/virtual-address/" + k
			objs[restname] = v
		case "Certificate":
			restname := "fake_api/certificate/" + k
			objs[restname] = v
			err = pc.parseCertificate(k, v.(map[string]interface{}), objs)
		case "CA_Bundle":
			restname := "fake_api/ca_bundle/" + k
			objs[restname] = v
			err = pc.parseCABundle(k, v.(map[string]interface{}), objs)
		default:
			svcPtn := `^Service_(Generic|HTTP|L4|HTTPS|SCTP|TCP|UDP|Forwarding)$`
			prfPtn := `^([^_\s]+_Profile|TLS_(Server|Client))$`
			if matched, e := regexp.MatchString(svcPtn, cls.(string)); e == nil && matched {
				resname := "ltm/virtual/" + k
				objs[resname] = v
				err = pc.parse(v.(map[string]interface{}), objs)
			} else if matched, e := regexp.MatchString(prfPtn, cls.(string)); e == nil && matched {
				err = pc.parseProfile(k, cls.(string), v, objs)
			} else {
				err = fmt.Errorf("unknown class: %s for %s", cls.(string), k)
			}
		}
	}
	return err
}

func (pc *ParseContext) parseCertificate(name string, obj, objdst map[string]interface{}) error {
	slog := utils.LogFromContext(pc)
	cc := newConvertContext(pc.Context)
	uploadsUrl := "shared/file-transfer/uploads"
	fileDir := "file:/var/config/rest/downloads"
	filenamePrefix := "__PARTITION____SUBFOLDER__"

	pass := ""
	keypath := fmt.Sprintf("sys/file/ssl-key/%s.key", name)
	crtpath := fmt.Sprintf("sys/file/ssl-cert/%s.crt", name)
	capath := fmt.Sprintf("sys/file/ssl-cert/%s-bundle.crt", name)

	for k, v := range obj {
		switch k {
		case "class":
		case "certificate":
			filename := filenamePrefix + "_" + name + ".crt"
			if reflect.TypeOf(v).Kind().String() == "string" {
				objdst[crtpath] = map[string]interface{}{
					"name":       name + ".crt",
					"sourcePath": fmt.Sprintf("%s/%s", fileDir, filename),
				}
				objdst[uploadsUrl+"/"+filename] = map[string]interface{}{
					"content": v,
				}
			}
		case "privateKey":
			filename := filenamePrefix + "_" + name + ".key"
			if reflect.TypeOf(v).Kind().String() == "string" {
				objdst[keypath] = map[string]interface{}{
					"name":       name + ".key",
					"sourcePath": fmt.Sprintf("%s/%s", fileDir, filename),
				}
				objdst[uploadsUrl+"/"+filename] = map[string]interface{}{
					"content": v,
				}
			}
		case "chainCA":
			filename := filenamePrefix + "_" + name + "-bundle.crt"
			if reflect.TypeOf(v).Kind().String() == "string" {
				objdst[capath] = map[string]interface{}{
					"name":       name + "-bundle.crt",
					"sourcePath": fmt.Sprintf("%s/%s", fileDir, filename),
				}
				objdst[uploadsUrl+"/"+filename] = map[string]interface{}{
					"content": v,
				}
			}
		case "passphrase":
			s, err := cc.convertSecret(v)
			if err != nil {
				return err
			} else {
				pass = s
			}
		default:
			slog.Warnf("ignored certificate field: %s in this version", k)
		}
	}

	if pass != "" {
		if _, f := objdst[keypath]; f {
			objdst[keypath].(map[string]interface{})["passphrase"] = pass
		}
	}
	return nil
}

func (pc *ParseContext) parseCABundle(name string, obj, objdst map[string]interface{}) error {
	uploadsUrl := "shared/file-transfer/uploads"
	fileDir := "file:/var/config/rest/downloads"
	filenamePrefix := "__PARTITION____SUBFOLDER__"

	bundlepath := fmt.Sprintf("sys/file/ssl-cert/%s", name)

	if t := reflect.TypeOf(obj["bundle"]).Kind().String(); t == "string" {
		filename := filenamePrefix + "_" + "ca_bundle-" + name + ".crt"
		objdst[bundlepath] = map[string]interface{}{
			"name":       name,
			"sourcePath": fmt.Sprintf("%s/%s", fileDir, filename),
		}
		objdst[uploadsUrl+"/"+filename] = map[string]interface{}{
			"content": obj["bundle"],
		}
	}

	return nil
}

func (pc *ParseContext) parsePersist(k string, v interface{}, objs map[string]interface{}) error {
	var err error = nil
	if t, f := v.(map[string]interface{})["persistenceMethod"]; f {
		var rt string
		switch t.(string) {
		case "destination-address":
			rt = "dest-addr"
		case "tls-session-id":
			rt = "ssl"
		case "sip-info":
			rt = "sip"
		case "source-address":
			rt = "source-addr"
		default:
			rt = t.(string)
		}
		resname := "ltm/persistence/" + rt + "/" + k
		objs[resname] = v
	}
	return err
}

func (pc *ParseContext) parseProfile(k, cls string, v interface{}, objs map[string]interface{}) error {
	slog := utils.LogFromContext(pc)
	var err error = nil
	switch cls {
	case "Multiplex_Profile":
		resname := "ltm/profile/one-connect/" + k
		objs[resname] = v
	case "L4_Profile":
		resname := "ltm/profile/fastl4/" + k
		objs[resname] = v
	case "TLS_Server":
		resname := "ltm/profile/client-ssl/" + k
		objs[resname] = v
	case "TLS_Client":
		resname := "ltm/profile/server-ssl/" + k
		objs[resname] = v
	default:
		rep := strings.Replace(cls, "_Profile", "", -1)
		lrep := strings.ToLower(rep)
		slog.Debugf("find kind '%s' from class '%s'", lrep, cls)
		resname := fmt.Sprintf("ltm/profile/%s/%s", lrep, k)
		objs[resname] = v
	}
	return err
}
