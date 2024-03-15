package as3parsing

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"

	"github.com/f5devcentral/f5-bigip-rest-go/utils"
)

func (cc *ConvertContext) convert(parent string, objsrc map[string]interface{}, objdst map[string]interface{}) error {
	var err error = nil
	for k, v := range objsrc {
		tn := strings.Split(k, "/")
		if len(tn) > 2 {
			l := len(tn)
			// t := strings.Join(tn[0:l-1], "/")
			n := tn[l-1]
			switch strings.Join(tn[0:2], "/") {
			case "ltm/virtual":
				err = cc.convertVirtual(parent, n, v.(map[string]interface{}), objsrc, objdst)
			case "ltm/pool":
				err = cc.convertPool(n, v.(map[string]interface{}), objdst)
			case "ltm/profile":
				err = cc.convertProfile(parent, tn[2], n, v.(map[string]interface{}), objsrc, objdst)
			case "ltm/monitor":
				err = cc.convertMonitor(k, n, v.(map[string]interface{}), objdst)
			case "ltm/persistence":
				err = cc.convertPersist(k, n, v.(map[string]interface{}), objdst)
			case "ltm/rule":
				err = cc.convertiRule(n, v.(map[string]interface{}), objdst)
			case "ltm/snatpool":
				err = cc.convertSnatpool(n, v.(map[string]interface{}), objdst)
			case "ltm/virtual-address":
				err = cc.convertVirtualAddress(n, v.(map[string]interface{}), objdst)
			case "fake_api/certificate":
			case "fake_api/ca_bundle":
			case "shared/file-transfer":
				kind := strings.Join(tn[0:l-1], "/")
				err = cc.convertSharedFileTransfer(parent, kind, n, v.(map[string]interface{}), objdst)
			case "sys/file":
				kind := strings.Join(tn[0:l-1], "/")
				err = cc.convertSysCertificate(parent, kind, n, v.(map[string]interface{}), objdst)
			default:
				err = fmt.Errorf("found unknown key type: %s name: '%s'", strings.Join(tn[0:2], "/"), k)
			}
		} else {
			objdst[k] = map[string]interface{}{}
			err = cc.convert(parent+"/"+k, v.(map[string]interface{}), objdst[k].(map[string]interface{}))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (cc *ConvertContext) convertSharedFileTransfer(parent, kind, name string, obj, objdst map[string]interface{}) error {
	pf := strings.Split(parent, "/") // fmt: /Sample_02/A1
	partition, subfolder := pf[1], pf[2]
	name = strings.ReplaceAll(name, "_PARTITION_", partition)
	name = strings.ReplaceAll(name, "_SUBFOLDER_", subfolder)

	copiedfileobj, err := utils.DeepCopy(obj)
	if err != nil {
		return err
	}
	objdst[kind+"/"+name] = copiedfileobj

	return nil
}

func (cc *ConvertContext) convertSysCertificate(parent, kind, name string, obj, objdst map[string]interface{}) error {
	// replace partition and subfolder.
	pf := strings.Split(parent, "/") // fmt: /Sample_02/A1
	partition, subfolder := pf[1], pf[2]
	copiedfileobj, err := utils.DeepCopy(obj)
	if err != nil {
		return err
	}
	fileobj := copiedfileobj.(map[string]interface{})
	if orig, f := fileobj["sourcePath"]; f {
		sp := orig.(string)
		sp = strings.ReplaceAll(sp, "_PARTITION_", partition)
		sp = strings.ReplaceAll(sp, "_SUBFOLDER_", subfolder)
		fileobj["sourcePath"] = sp
	}

	objdst[kind+"/"+name] = fileobj
	return nil
}

func (cc *ConvertContext) convertVirtualAddress(name string, obj, objdst map[string]interface{}) error {
	virtualAddress := map[string]interface{}{}

	for k, v := range obj {
		switch k {
		case "class":
		case "icmpEcho":
			// f5-appsvcs: behaviors from f5-appsvcs which is chibaolechengde
			// itemCopy.icmpEcho = itemCopy.icmpEcho.replace(/able$/, 'abled');
			virtualAddress[restname("ltm/virtual-address", k)] = strings.ReplaceAll(v.(string), "able", "abled")
		case "routeAdvertisement":
			virtualAddress[restname("ltm/virtual-address", k)] = strings.ReplaceAll(v.(string), "able", "abled")
		default:
			dt, err := cc.convertByType("ltm/virtual-address", k, v)
			if err != nil {
				return err
			}
			virtualAddress[restname("ltm/virtual-address", k)] = dt
		}
	}

	// use address as the virtual-address name.
	// "0107176c:3: Invalid Virtual Address, the IP address 172.16.142.112 already exists."
	// however, this error will still happen when vs in different partitions refer to the same IP. Just as AS3 behaves.
	// github issue: https://github.com/F5Networks/f5-appsvcs-extension/issues/628
	if ipaddr, f := virtualAddress["address"]; !f {
		return fmt.Errorf("virtual-address 'address' field not found")
	} else {
		virtualAddress["name"] = ipaddr
		objdst["ltm/virtual-address/"+ipaddr.(string)] = virtualAddress
		return nil
	}
}

func (cc *ConvertContext) convertSnatpool(name string, obj, objdst map[string]interface{}) error {
	snatpool := map[string]interface{}{
		"name": name,
	}
	for k, v := range obj {
		switch k {
		case "class":
		default:
			dt, err := cc.convertByType("ltm/snatpool", k, v)
			if err != nil {
				return err
			}
			snatpool[restname("ltm/snatpool", k)] = dt
		}
	}
	objdst["ltm/snatpool/"+name] = snatpool
	return nil
}

func (cc *ConvertContext) convertiRule(name string, obj, objdst map[string]interface{}) error {
	irule := map[string]interface{}{
		"name": name,
	}
	for k, v := range obj {
		switch k {
		case "class":
		default:
			dt, err := cc.convertByType("ltm/rule", k, v)
			if err != nil {
				return err
			}
			irule[restname("ltm/rule", k)] = dt
		}
	}

	objdst["ltm/rule/"+name] = irule
	return nil
}

func (cc *ConvertContext) convertPersist(kn, name string, obj, objdst map[string]interface{}) error {
	persist := map[string]interface{}{
		"name": name,
	}
	for k, v := range obj {
		switch k {
		case "class":
		case "persistenceMethod":
		case "duration":
			if i, ok := v.(float64); ok && i == 0 {
				persist[restname("ltm/persistence", k)] = "indefinite"
			} else {
				persist[restname("ltm/persistence", k)] = v
			}
		case "passphrase":
			pass, err := cc.convertSecret(v)
			if err != nil {
				return err
			}
			persist[restname("ltm/persistence", k)] = pass
		default:
			dt, err := cc.convertByType("ltm/persistence", k, v)
			if err != nil {
				return err
			}
			persist[restname("ltm/persistence", k)] = dt
		}
	}

	objdst[kn] = persist

	return nil
}

func (cc *ConvertContext) convertSecret(obj interface{}) (string, error) {
	pkind := reflect.TypeOf(obj).Kind().String()
	if pkind == "map" {
		if ciphertext, f := obj.(map[string]interface{})["ciphertext"]; f {
			if protected, f := obj.(map[string]interface{})["protected"]; !f ||
				// none or f5sv
				(strings.Index(protected.(string), "eyJhbGciOiJkaXIiLCJlbmMiOiJub25lIn0") != 0 &&
					strings.Index(protected.(string), "eyJhbGciOiJkaXIiLCJlbmMiOiJmNXN2In0") != 0) {
				return "", fmt.Errorf("not support non-base64 way")
			}
			b, err := base64.StdEncoding.DecodeString(ciphertext.(string))
			if err != nil {
				return "", err
			} else {
				return string(b), nil
			}
		} else {
			return "", fmt.Errorf("not found ciphertext")
		}
	} else if pkind == "string" {
		return obj.(string), nil
	} else {
		return "", fmt.Errorf("unsupported kind of secret")
	}
}

func (cc *ConvertContext) convertBool(kind, as3name string, value bool) interface{} {
	if k, f := properties[kind]; f {
		if n, f := k[as3name]; f {
			if n.Truth != "" && value {
				return n.Truth
			} else if n.Falsehood != "" && !value {
				return n.Falsehood
			}
		}
	}
	return value
}

func (cc *ConvertContext) convertF5base64(obj map[string]interface{}) (interface{}, error) {
	if b, f := obj["base64"]; f {
		bb, err := base64.StdEncoding.DecodeString(b.(string))
		if err != nil {
			return "", err
		} else {
			return string(bb), nil
		}
	} else {
		return obj, nil
	}
}

func (cc *ConvertContext) convertF5string(obj interface{}) (interface{}, error) {
	m := obj.(map[string]interface{})
	if _, f := m["base64"]; f {
		return cc.convertF5base64(m)
	}
	if _, f := m["text"]; f {
		return m["text"], nil
	}
	if _, f := m["url"]; f {
		return "", fmt.Errorf("'url' not supported")
	}
	if _, f := m["copyFrom"]; f {
		return "", fmt.Errorf("'url' not supported")
	}
	if _, f := m["bigip"]; f {
		return refers(m), nil
	}
	if _, f := m["use"]; f {
		return refers(m), nil
	}
	// return "", fmt.Errorf("cannot convert from obj %v", obj)
	return obj, nil
}

func (cc *ConvertContext) convertByType(kind, as3name string, v interface{}) (interface{}, error) {
	t := reflect.TypeOf(v).Kind().String()
	switch t {
	case "bool":
		return cc.convertBool(kind, as3name, v.(bool)), nil
	case "map":
		return cc.convertF5string(v)
	default:
		return v, nil
	}
}

func (cc *ConvertContext) convertVirtual(parent, name string, obj, objsrc, objdst map[string]interface{}) error {
	virtual := map[string]interface{}{
		"name":        name,
		"description": strings.Split(parent, "/")[2], // parent string as '/partition/subfolder'
	}
	profiles := []interface{}{}
	addrs := []string{}
	redirect80 := false
	for k, v := range obj {
		switch k {
		case "class":
			switch v.(string) {
			case "Service_HTTP":
				virtual["ipProtocol"] = "tcp"
			case "Service_L4":
				virtual["ipProtocol"] = "tcp"
			case "Service_UDP":
				virtual["ipProtocol"] = "udp"
			case "Service_HTTPS":
				virtual["ipProtocol"] = "tcp"
			default:
				virtual["ipProtocol"] = "any"
			}
			if p, f := obj["layer4"]; f {
				virtual["ipProtocol"] = p
			}
		case "persistenceMethods":
			plist := []interface{}{}
			for _, p := range v.([]interface{}) {
				if pref := refers(p); pref != "" {
					plist = append(plist, map[string]string{
						"name": renamePersist(pref),
					})
				}
			}
			virtual["persist"] = utils.SortIt(&plist)
		case "profileTCP":
			if typeString(v) && v.(string) == "normal" {
				profiles = append(profiles, map[string]interface{}{
					"name": "/Common/f5-tcp-progressive",
				})
			} else {
				profiles = append(profiles, map[string]interface{}{
					"name": refers(v),
				})
			}
		case "profileHTTP":
			if typeString(v) && v.(string) == "basic" {
				profiles = append(profiles, map[string]interface{}{
					"name": "/Common/http",
				})
			} else {
				profiles = append(profiles, map[string]interface{}{
					"name": refers(v),
				})
			}
		case "profileMultiplex":
			profiles = append(profiles, map[string]interface{}{
				"name": refers(v),
			})
		case "profileFTP":
			profiles = append(profiles, map[string]interface{}{
				"name": refers(v),
			})
			// slog.Infof("setting persit to empty")
			// virtual["persist"] = []interface{}{}
		case "profileUDP":
			profiles = append(profiles, map[string]interface{}{
				"name": refers(v),
			})
		case "profileL4":
			if typeString(v) && v.(string) == "basic" {
				profiles = append(profiles, map[string]interface{}{
					"name": "/Common/fastL4",
				})
			} else {
				profiles = append(profiles, map[string]interface{}{
					"name": refers(v),
				})
			}
		case "serverTLS":
			if t := reflect.TypeOf(v).Kind().String(); t == "slice" {
				for _, sslprof := range v.([]interface{}) {
					profiles = append(profiles, map[string]interface{}{
						"name": refers(sslprof),
					})
				}
			} else if t == "string" {
				profiles = append(profiles, map[string]interface{}{
					"name": refers(v),
				})
			}
		case "clientTLS":
			if t := reflect.TypeOf(v).Kind().String(); t == "slice" {
				for _, sslprof := range v.([]interface{}) {
					profiles = append(profiles, map[string]interface{}{
						"name": refers(sslprof),
					})
				}
			} else if t == "string" {
				profiles = append(profiles, map[string]interface{}{
					"name": refers(v),
				})
			}
		case "snat":
			if t := reflect.TypeOf(v).Kind().String(); t == "map" {
				virtual["sourceAddressTranslation"] = map[string]string{
					"type": "snat",
					"pool": refers(v),
				}
			} else {
				switch v {
				case "none":
					virtual["sourceAddressTranslation"] = map[string]string{
						"type": v.(string),
					}
				case "auto":
					virtual["sourceAddressTranslation"] = map[string]string{
						"type": "automap",
					}
				case "self":
					virtual["sourceAddressTranslation"] = map[string]string{
						"type": "snat",
						"pool": fmt.Sprintf("%s-self", name),
					}
				}
			}
		case "virtualAddresses":
			for _, addr := range obj["virtualAddresses"].([]interface{}) {
				t := reflect.TypeOf(addr).Kind().String()
				if t == "map" {
					if n, f := addr.(map[string]interface{})["use"]; f {
						addrs = append(addrs, referToAddr(objsrc, n.(string)))
					}
				} else if t == "string" {
					addrs = append(addrs, addr.(string))
				} else {
					return fmt.Errorf("virtualAddresses format is %s, not support yet", t)
				}
			}
		case "virtualPort":
		case "mirroring":
			if v.(string) == "none" {
				virtual[restname("ltm/virtual", k)] = "disabled"
			} else if v.(string) == "L4" {
				virtual[restname("ltm/virtual", k)] = "enabled"
			}
		case "redirect80":
			if v.(bool) {
				redirect80 = true
			}
		case "iRules":
			if ls, ok := v.([]interface{}); ok {
				rules := []string{}
				for _, i := range ls {
					rules = append(rules, refers(i))
				}
				virtual[restname("ltm/virtual", k)] = rules
			}
		default:
			dt, err := cc.convertByType("ltm/virtual", k, v)
			if err != nil {
				return err
			}
			virtual[restname("ltm/virtual", k)] = dt
		}
	}

	if _, f := virtual["pool"]; !f {
		virtual["pool"] = ""
	}
	virtual["profiles"] = utils.SortIt(&profiles)
	for i, addr := range addrs {
		copiedvobj, err := utils.DeepCopy(virtual)
		if err != nil {
			return err
		}
		vobj := copiedvobj.(map[string]interface{})
		if utils.IsIpv6(addr) {
			vobj["destination"] = fmt.Sprintf("%s.%v", addr, obj["virtualPort"])
		} else {
			vobj["destination"] = fmt.Sprintf("%s:%v", addr, obj["virtualPort"])
		}
		if snattarget, f := obj["snat"]; f {
			if t := refers(snattarget); t == "self" {
				spname := indexedName(i, name) + "-self"
				vobj["sourceAddressTranslation"].(map[string]interface{})["pool"] = spname

				objk := fmt.Sprintf("ltm/snatpool/%s", spname)
				objdst[objk] = map[string]interface{}{
					"name":    spname,
					"members": []string{addr},
				}
			}
		}

		vname := indexedName(i, name)
		objk := fmt.Sprintf("ltm/virtual/%s", vname)
		vobj["name"] = vname
		objdst[objk] = vobj

		if redirect80 {
			copiedvobj, err := utils.DeepCopy(virtual)
			if err != nil {
				return err
			}
			vobj := copiedvobj.(map[string]interface{})
			vobj["destination"] = fmt.Sprintf("%s:%v", addr, 80)
			vname := indexedName(i, name+"-Redirect-")
			vobj["rules"] = []string{
				"/Common/_sys_https_redirect",
			}
			// never use the type '[]map[string]interface{}', because:
			//  it declares types for 2 levels of the data
			vobj["profiles"] = []interface{}{
				map[string]interface{}{"name": "/Common/f5-tcp-progressive"},
				map[string]interface{}{"name": "/Common/http"},
			}
			vobj["persist"] = []interface{}{}
			objk := fmt.Sprintf("ltm/virtual/%s", vname)
			vobj["name"] = vname
			delete(vobj, "pool")
			objdst[objk] = vobj
		}
	}

	for _, addr := range addrs {
		if _, f := objdst["ltm/virtual-address/"+addr]; !f {
			objdst["ltm/virtual-address/"+addr] = map[string]interface{}{
				"name":    addr,
				"address": addr,
				"arp":     "enabled", //required, set default
				// "arp":     "disabled", //required, as3 default
			}
		}
	}
	return nil
}

func (cc *ConvertContext) convertPool(name string, obj, objdst map[string]interface{}) error {
	pool := map[string]interface{}{
		"name": name,
	}

	monitors := []string{}
	monOps := ""
	for k, v := range obj {
		switch k {
		case "class":
		case "members":
			// don't do member arrangement. do it at pool.members phrase.
		case "monitors":
			for _, m := range v.([]interface{}) {
				mstr := refers(m)
				// f5-appsvcs: mon = (mon === 'icmp') ? 'gateway_icmp' : mon;
				if mstr == "icmp" {
					mstr = "gateway_icmp"
				}
				monitors = append(monitors, mstr)
			}
		case "minimumMonitors":
			if _, ok := v.(string); !ok {
				monOps = fmt.Sprintf("min %d of ", int(v.(float64)))
			} else {
				monOps = "all"
			}
		default:
			dt, err := cc.convertByType("ltm/pool", k, v)
			if err != nil {
				return err
			}
			pool[restname("ltm/pool", k)] = dt
		}
	}

	pool["monitor"] = ""
	if len(monitors) > 0 {
		if monOps == "all" {
			pool["monitor"] = strings.Join(monitors, " and ")
		} else {
			// f5-appsvcs: default to be min 1 of
			pool["monitor"] = monOps + strings.Join(monitors, " ")
		}
	}
	objdst["ltm/pool/"+name] = pool
	return nil
}

func (cc *ConvertContext) convertMonitor(kn, name string, obj, objdst map[string]interface{}) error {
	monitor := map[string]interface{}{
		"name": name,
	}
	for k, v := range obj {
		switch k {
		case "class":
		case "monitorType":
		case "send":
			str := v.(string)
			str = strings.ReplaceAll(str, "\r", "\\r")
			str = strings.ReplaceAll(str, "\n", "\\n")
			monitor[restname("ltm/monitor", k)] = str
		case "receive":
			str := v.(string)
			str = strings.ReplaceAll(str, "\r", "\\r")
			str = strings.ReplaceAll(str, "\n", "\\n")
			monitor[restname("ltm/monitor", k)] = str
		default:
			dt, err := cc.convertByType("ltm/monitor", k, v)
			if err != nil {
				return err
			}
			monitor[restname("ltm/monitor", k)] = dt
		}
	}

	objdst[kn] = monitor
	return nil
}

func (cc *ConvertContext) convertProfile(parent, kind, name string, obj, objsrc, objdst map[string]interface{}) error {
	switch kind {
	case "http":
		return cc.convertHttpProfile(name, obj, objdst)
	case "one-connect":
		return cc.convertOneconnectProfile(name, obj, objdst)
	case "tcp":
		return cc.convertTcpProfile(name, obj, objdst)
	case "udp":
		return cc.convertUdpProfile(name, obj, objdst)
	case "fastl4":
		return cc.convertCommonProfile(kind, name, obj, objdst)
	case "client-ssl":
		return cc.convertClientsslProfile(parent, kind, name, obj, objsrc, objdst)
	case "server-ssl":
		return cc.convertServersslProfile(parent, kind, name, obj, objsrc, objdst)
	case "ftp":
		return cc.convertFtpProfile(name, obj, objdst)
	default:
		return fmt.Errorf("unknown profile type: %s", kind)
	}
}

func (cc *ConvertContext) convertServersslProfile(parent, kind, name string, obj, objsrc, objdst map[string]interface{}) error {
	profile := map[string]interface{}{
		"name":   name,
		"caFile": "/Common/ca-bundle.crt", // by default, however, it's rarely in product case.
	}

	for k, v := range obj {
		switch k {
		case "class":
		case "trustCA":
			t := reflect.TypeOf(v).Kind().String()
			if t == "string" {
				if v.(string) == "generic" {
					profile["caFile"] = "/Common/ca-bundle.crt"
				} else {
					return fmt.Errorf("if trustCA is string, it must be 'generic'")
				}
			} else if t == "map" {
				profile["caFile"] = refers(v)
			}
		case "clientCertificate":
			ckname := v.(string)
			clscert := fmt.Sprintf("fake_api/certificate/%s", ckname)
			if cert, f := objsrc[clscert]; f {
				certobj := cert.(map[string]interface{})
				if crt, f := certobj["certificate"]; f {
					profile["cert"] = tlsRefers(ckname+".crt", parent, crt)
				}
				if pkey, f := certobj["privateKey"]; f {
					profile["key"] = tlsRefers(ckname+".key", parent, pkey)
				}
				if ca, f := certobj["chainCA"]; f {
					profile["chain"] = tlsRefers(ckname+"-bundle.crt", parent, ca)
				}
				if pass, f := certobj["passphrase"]; f {
					if pass, err := cc.convertSecret(pass); err != nil {
						return err
					} else {
						profile["passphrase"] = pass
					}
				}
			}
		case "authenticationFrequency":
			value := strings.ReplaceAll(v.(string), "one-time", "once")
			value = strings.ReplaceAll(value, "every-time", "always")
			profile[restname("ltm/profile/"+kind, k)] = value
		default:
			dt, err := cc.convertByType("ltm/profile/"+kind, k, v)
			if err != nil {
				return err
			}
			profile[restname("ltm/profile/"+kind, k)] = dt
		}
	}

	objdst["ltm/profile/"+kind+"/"+name] = profile
	return nil
}

func (cc *ConvertContext) convertClientsslProfile(parent, kind, name string, obj, objsrc, objdst map[string]interface{}) error {
	profiles := map[string]interface{}{}
	pcommon := map[string]interface{}{}
	for k, v := range obj {
		switch k {
		case "class":
		case "certificates":
			if items, ok := v.([]interface{}); ok {
				for i, item := range items {
					n, sniDefault := name, "true"
					if i != 0 {
						n = fmt.Sprintf("%s-%d-", n, i)
						sniDefault = "false"
					}

					profile := map[string]interface{}{
						"name":       n,
						"sniDefault": sniDefault,
						"serverName": "none",
					}
					if ckname, f := item.(map[string]interface{})["certificate"]; f {
						if matchToSNI, f := item.(map[string]interface{})["matchToSNI"]; f {
							if sn, ok := matchToSNI.(string); ok {
								profile["serverName"] = sn
							}
						}

						clscert := fmt.Sprintf("fake_api/certificate/%s", ckname)
						if cert, f := objsrc[clscert]; f {
							certobj := cert.(map[string]interface{})
							if crt, f := certobj["certificate"]; f {
								profile["cert"] = tlsRefers(ckname.(string)+".crt", parent, crt)
							}
							if pkey, f := certobj["privateKey"]; f {
								profile["key"] = tlsRefers(ckname.(string)+".key", parent, pkey)
							}
							if ca, f := certobj["chainCA"]; f {
								profile["chain"] = tlsRefers(ckname.(string)+"-bundle.crt", parent, ca)
							}
							if pass, f := certobj["passphrase"]; f {
								if pass, err := cc.convertSecret(pass); err != nil {
									return err
								} else {
									profile["passphrase"] = pass
								}
							}
						}

						profiles[profile["name"].(string)] = profile
					}
				}
			}
		case "authenticationFrequency":
			value := strings.ReplaceAll(v.(string), "one-time", "once")
			value = strings.ReplaceAll(value, "every-time", "always")
			pcommon[restname("ltm/profile/"+kind, k)] = value
		case "authenticationTrustCA":
			t := reflect.TypeOf(v).Kind().String()
			if t == "map" {
				if bipca, f := v.(map[string]interface{})["bigip"]; f {
					pcommon["caFile"] = bipca
				}
			} else if t == "string" {
				capath := v.(string)
				if bundleobj, f := objsrc["fake_api/ca_bundle/"+capath]; f {
					bundle := bundleobj.(map[string]interface{})["bundle"]
					pcommon["caFile"] = tlsRefers(capath, parent, bundle)
				} else {
					return fmt.Errorf("cannot convert ca_bundle for authenticationTrustCA: %v", v)
				}
			}
		default:
			dt, err := cc.convertByType("ltm/profile/"+kind, k, v)
			if err != nil {
				return err
			}
			pcommon[restname("ltm/profile/"+kind, k)] = dt
		}
	}
	for pname, p := range profiles {
		profile := p.(map[string]interface{})
		for k, v := range pcommon {
			profile[k] = v
		}
		objdst["ltm/profile/"+kind+"/"+pname] = profile
	}
	return nil
}

func (cc *ConvertContext) convertCommonProfile(kind, name string, obj, objdst map[string]interface{}) error {
	profile := map[string]interface{}{
		"name": name,
	}

	for k, v := range obj {
		switch k {
		case "class":
		default:
			dt, err := cc.convertByType("ltm/profile/"+kind, k, v)
			if err != nil {
				return err
			}
			profile[restname("ltm/profile/"+kind, k)] = dt
		}
	}
	objdst["ltm/profile/"+kind+"/"+name] = profile
	return nil
}

func (cc *ConvertContext) convertUdpProfile(name string, obj, objdst map[string]interface{}) error {
	profile := map[string]interface{}{
		"name": name,
	}

	for k, v := range obj {
		switch k {
		case "class":
		default:
			dt, err := cc.convertByType("ltm/profile/udp", k, v)
			if err != nil {
				return err
			}
			profile[restname("ltm/profile/udp", k)] = dt
		}
	}
	objdst["ltm/profile/udp/"+name] = profile
	return nil
}

func (cc *ConvertContext) convertTcpProfile(name string, obj, objdst map[string]interface{}) error {
	profile := map[string]interface{}{
		"name": name,
	}

	for k, v := range obj {
		switch k {
		case "class":
		case "mptcp":
			// f5-appsvcs
			// if (item.mptcp !== 'passthrough') item.mptcp += 'd';
			if v.(string) != "passthrough" {
				profile[restname("ltm/profile/tcp", k)] = v.(string) + "d"
			}
		default:
			dt, err := cc.convertByType("ltm/profile/tcp", k, v)
			if err != nil {
				return err
			}
			profile[restname("ltm/profile/tcp", k)] = dt
		}
	}
	objdst["ltm/profile/tcp/"+name] = profile
	return nil
}

func (cc *ConvertContext) convertFtpProfile(name string, obj, objdst map[string]interface{}) error {
	profile := map[string]interface{}{
		"name": name,
	}

	for k, v := range obj {
		switch k {
		case "class":
		default:
			dt, err := cc.convertByType("ltm/profile/ftp", k, v)
			if err != nil {
				return err
			}
			profile[restname("ltm/profile/ftp", k)] = dt
		}
	}

	objdst["ltm/profile/ftp/"+name] = profile
	return nil
}

func (cc *ConvertContext) convertHttpProfile(name string, obj, objdst map[string]interface{}) error {
	profile := map[string]interface{}{
		"name": name,
	}

	//  HTTP Strict Transport Security.
	hsts := map[string]interface{}{}
	for k, v := range obj {
		switch k {
		case "class":
		case "responseChunking":
			if bigip.Version >= "15." && (v.(string) == "selective" || v.(string) == "preserve") {
				profile["responseChunking"] = "sustain"
			} else {
				dt, err := cc.convertByType("ltm/profile/http", k, v)
				if err != nil {
					return err
				}
				profile[restname("ltm/profile/http", k)] = dt
			}
		case "requestChunking":
			if bigip.Version >= "15." && (v.(string) == "selective" || v.(string) == "preserve") {
				profile["requestChunking"] = "sustain"
			} else {
				dt, err := cc.convertByType("ltm/profile/http", k, v)
				if err != nil {
					return err
				}
				profile[restname("ltm/profile/http", k)] = dt
			}
		case "insertHeader":
			name, f1 := v.(map[string]interface{})["name"]
			value, f2 := v.(map[string]interface{})["value"]
			if f1 && f2 {
				profile[restname("ltm/profile/http", k)] = fmt.Sprintf("%s: %s", name, value)
			}
		default:
			if strings.Index(k, "hsts") == 0 {
				hsts[k] = v
			}
			dt, err := cc.convertByType("ltm/profile/http", k, v)
			if err != nil {
				return err
			}
			profile[restname("ltm/profile/http", k)] = dt
		}
	}
	opt := cc.convertHttpProfileHsts(hsts)
	copiedhsts, err := utils.DeepCopy(*opt)
	if err != nil {
		return err
	}
	profile["hsts"] = copiedhsts
	objdst["ltm/profile/http/"+name] = profile

	return nil
}

func (cc *ConvertContext) convertHttpProfileHsts(hsts map[string]interface{}) *map[string]interface{} {
	opt := map[string]interface{}{}
	for k, v := range hsts {
		if strings.Index(k, "hsts") == 0 {
			nk := strings.Replace(k, "hsts", "", 1)
			nk = strings.ToLower(string(nk[0])) + nk[1:]
			dt, _ := cc.convertByType("ltm/profile/http/hsts", nk, v)
			opt[restname("ltm/profile/http/hsts", nk)] = dt
		}
	}

	return &opt
}

func (cc *ConvertContext) convertOneconnectProfile(name string, obj, objdst map[string]interface{}) error {
	profile := map[string]interface{}{
		"name": name,
	}

	for k, v := range obj {
		switch k {
		case "class":
		default:
			dt, err := cc.convertByType("ltm/profile/one-connect", k, v)
			if err != nil {
				return err
			}
			profile[restname("ltm/profile/one-connect", k)] = dt
		}
	}

	objdst["ltm/profile/one-connect/"+name] = profile
	return nil
}
