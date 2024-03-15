package as3parsing

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/f5devcentral/f5-bigip-rest-go/utils"
)

// AS3ToRestProperties is used to generate restPropFilePath from as3PropFilePath
func AS3ToRestProperties(as3PropFilePath, restPropFilePath string) error {
	bprop, err := ioutil.ReadFile(as3PropFilePath)
	if err != nil {
		return err
	}

	var p map[string]interface{}
	err = json.Unmarshal(bprop, &p)
	if err != nil {
		return err
	}

	ltmProps := map[string]map[string]interface{}{}
	for k, v := range p {
		if strings.Index(k, "ltm ") == 0 {
			// if 0 == strings.Index(k, "ltm ") { // Yoda conditions
			kname := strings.Replace(k, " ", "/", -1)
			ltmProps[kname] = map[string]interface{}{}
			props := v.([]interface{})
			for _, p := range props {
				pobj := p.(map[string]interface{})
				name := pobj["id"].(string)
				if altId, f := pobj["altId"]; f {
					name = altId.(string)
				}
				copiednpobj, err := utils.DeepCopy(pobj)
				if err != nil {
					return err
				}
				npobj := copiednpobj.(map[string]interface{})
				npobj["restname"] = camelCase(npobj["id"].(string))
				delete(npobj, "id")
				delete(npobj, "altId")
				ltmProps[kname][name] = npobj
			}
		}
	}

	bLtmProps, err := json.MarshalIndent(ltmProps, "", "    ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(restPropFilePath, bLtmProps, 0644)
}

func addDefaults(ctx context.Context, declaration map[string]interface{}) (map[string]interface{}, error) {
	slog := utils.LogFromContext(ctx)
	defer utils.TimeIt(slog)("addDefaults timecost")
	defer utils.TimeItToPrometheus()()

	rlt := map[string]interface{}{}
	if adc, f := declaration["class"]; !f || adc != "ADC" {
		return rlt, fmt.Errorf("invalid declaration: not class ADC found")
	}

	if strings.HasPrefix(as3Service, bigip.URL) {
		return addDefaultsViaBigip(ctx, declaration)
	} else {
		declaration["scratch"] = "defaults-only"
		return addDefaultsViaLocal(ctx, declaration)
	}
}

func customizeProperties(ctx context.Context, restobjs map[string]interface{}) error {
	defer utils.TimeItToPrometheus()()
	slog := utils.LogFromContext(ctx)
	defer utils.TimeIt(slog)("tell me when customizeProperties takes long time...")
	// Notes:
	//	Generally, we should not add logics to this function,
	// 	Instead, we should do that in parse and convert functions.
	// 	Here we just add logics for crossing multiple objs.

	// move virtual-address to "" subfolder
	relayVirtualAddress := func() {

		for _, pobj := range restobjs {
			vas := map[string]interface{}{}
			folders := pobj.(map[string]interface{})
			for _, fobj := range folders {
				resources := fobj.(map[string]interface{})
				for r, body := range resources {
					if strings.HasPrefix(r, "ltm/virtual-address") {
						if _, f := vas[r]; !f {
							vas[r] = map[string]interface{}{}
						}
						// assemble all properties of the multiple virtual-address
						jsonbody := body.(map[string]interface{})
						for k, v := range jsonbody {
							vas[r].(map[string]interface{})[k] = v
						}
						delete(resources, r)
					}
				}
			}

			if _, found := folders[""]; !found {
				folders[""] = vas
			}

		}
	}

	// add ssl profiles to virtual
	// doing it here(after convert) is because
	//  all 'ltm/profile/client-ssl' are only ready after 'convert'
	addSNIProfiles := func() {
		tlsProfNames := []string{}
		for pname, pobj := range restobjs {
			folders := pobj.(map[string]interface{})
			for fname, folder := range folders {
				resources := folder.(map[string]interface{})
				for rname := range resources {
					if strings.HasPrefix(rname, "ltm/profile/client-ssl/") {
						tnarr := strings.Split(rname, "/")
						tlsProfName := tnarr[len(tnarr)-1]
						tlsProfNames = append(tlsProfNames, utils.Keyname(pname, fname, tlsProfName))
					}
				}
			}
		}
		for pname, pobj := range restobjs {
			folders := pobj.(map[string]interface{})
			for fname, fobj := range folders {
				resources := fobj.(map[string]interface{})
				for rname, rs := range resources {
					if !strings.HasPrefix(rname, "ltm/virtual/") {
						continue
					}
					rbody := rs.(map[string]interface{})
					oldpl, found := rbody["profiles"]
					if !found {
						continue
					}

					newpl := []interface{}{}
					for _, profobj := range oldpl.([]interface{}) {
						profname := profobj.(map[string]interface{})["name"].(string)
						pfp := utils.Keyname(pname, fname, profname)
						newpl = append(newpl, profobj)
						if utils.Contains(tlsProfNames, pfp) {
							ptn := fmt.Sprintf("%s-\\d+-", pfp)
							for _, tlspfp := range tlsProfNames {
								// match all "/partitionx/folderx/sslprofilex-\d-" and append it to newpl
								matched, err := regexp.MatchString(ptn, tlspfp)
								if err == nil && matched {
									pfparr := strings.Split(tlspfp, "/")
									_, _, matchedprofname := pfparr[0], pfparr[1], pfparr[2]
									newpl = append(newpl, map[string]interface{}{
										"name": matchedprofname,
									})
								}
							}
						}
					}
					rbody["profiles"] = newpl
				}
			}
		}
	}

	relayVirtualAddress()
	addSNIProfiles()
	return nil
}

func addDefaultsViaLocal(ctx context.Context, declaration map[string]interface{}) (map[string]interface{}, error) {
	slog := utils.LogFromContext(ctx)
	rlt := map[string]interface{}{}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 10 * time.Second,
	}
	bsend, err := json.Marshal(declaration)
	if err != nil {
		return rlt, err
	}
	as3ep := fmt.Sprintf("%s/validate", as3Service)
	if status, response, err := utils.HttpRequest(
		client, as3ep, "POST",
		string(bsend),
		map[string]string{
			"Content-Type": "application/json",
		},
	); err != nil {
		return rlt, err
	} else if status == 200 {
		var fulldecl map[string]interface{}
		slog.Debugf("addDefaults as3body: %s", response)
		err := json.Unmarshal(response, &fulldecl)
		if err != nil {
			return rlt, err
		} else {
			return fulldecl, nil
		}
	} else {
		return rlt, fmt.Errorf("failed to add default values to declaration through %s: %d, %s", as3Service, status, string(response))
	}
}

func addDefaultsViaBigip(ctx context.Context, declaration map[string]interface{}) (map[string]interface{}, error) {
	slog := utils.LogFromContext(ctx)
	rlt := map[string]interface{}{}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 60 * time.Second,
	}
	// if show=expanded, the reference would be expanded to fullpath
	// if declaration.scratch=='defaults-only', sometimes, it would reports error:
	//    code: 422, message : "Cannot read property 'undefined' of undefined",
	as3ep := fmt.Sprintf("%s/mgmt/shared/appsvcs/declare?show=full", as3Service)
	as3obj := map[string]interface{}{
		"class":       "AS3",
		"action":      "dry-run",
		"persist":     false,
		"declaration": declaration,
	}
	bsend, err := json.Marshal(as3obj)
	if err != nil {
		return rlt, err
	}
	if status, response, err := utils.HttpRequest(
		client, as3ep, "POST",
		string(bsend),
		map[string]string{
			"Content-Type":  "application/json",
			"Authorization": bigip.Authorization,
		},
	); err != nil {
		return rlt, err
	} else if status == 200 {
		var fullas3resp map[string]interface{}
		slog.Debugf("addDefaults as3body: %s", response)
		err := json.Unmarshal(response, &fullas3resp)
		if err != nil {
			return rlt, err
		} else {
			if fulldecl, f := fullas3resp["declaration"]; f {
				return fulldecl.(map[string]interface{}), nil
			} else {
				return declaration, nil
			}
		}
	} else if status == 202 {
		// TODO: as3 check turns to async mode, need to handle it
		//   {
		// 	"id": "94a17d6d-68e9-4ee9-aca4-ecf7fa54084b",
		// 	"results": [
		// 	  {
		// 		"message": "Declaration successfully submitted",
		// 		"tenant": "",
		// 		"host": "",
		// 		"runTime": 0,
		// 		"code": 0
		// 	  }
		// 	],
		// 	"declaration": {},
		// 	"selfLink": "https://localhost/mgmt/shared/appsvcs/task/94a17d6d-68e9-4ee9-aca4-ecf7fa54084b"
		//   }
		return rlt, fmt.Errorf("as3 check turns to async mode, need to handle it: %s", string(response))
	} else {
		return rlt, fmt.Errorf("failed to add default values to declaration through %s: %d, %s", as3Service, status, string(response))
	}
}
