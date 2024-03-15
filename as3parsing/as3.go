package as3parsing

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/f5devcentral/f5-bigip-rest-go/utils"

	f5_bigip "github.com/f5devcentral/f5-bigip-rest-go/bigip"
)

func ParseAS3(ctx context.Context, as3obj map[string]interface{}) (map[string]interface{}, error) {
	slog := utils.LogFromContext(ctx)
	defer utils.TimeIt(slog)("ParseAS3 timecost")
	defer utils.TimeItToPrometheus()()

	restobjs := map[string]interface{}{}
	if _, f := as3obj["declaration"]; !f {
		return restobjs, fmt.Errorf("no declaration found in the given as3 body")
	}
	declaration, err := utils.DeepCopy(as3obj["declaration"])
	if err != nil {
		return restobjs, err
	}
	if decl, err := addDefaults(ctx, declaration.(map[string]interface{})); err != nil {
		return restobjs, err
	} else {
		as3obj["declaration"] = decl
	}
	restobjs, err = parseToRest(ctx, as3obj)
	if err != nil {
		return restobjs, err
	}

	err = customizeProperties(ctx, restobjs)
	return restobjs, err
}

func parseToRest(ctx context.Context, as3obj map[string]interface{}) (map[string]interface{}, error) {
	defer utils.TimeItToPrometheus()()
	objs1 := map[string]interface{}{}
	objs2 := map[string]interface{}{}
	slog := utils.LogFromContext(ctx)
	pc, cc := newParseContext(ctx), newConvertContext(ctx)
	if err := pc.parse(as3obj, objs1); err != nil {
		return objs2, err
	} else {
		bobjs, _ := utils.MarshalNoEscaping(objs1)
		slog.Debugf("parsed as3body: %s", bobjs)
	}

	if err := cc.convert("", objs1, objs2); err != nil {
		return objs2, err
	} else {
		bobjs, _ := utils.MarshalNoEscaping(objs2)
		slog.Debugf("converted as3body: %s", bobjs)
	}

	return objs2, nil
}

func loadProperties() error {
	// fp := os.Args[0]
	// propPath := strings.Join([]string{path.Dir(fp), "rest.properties.json"}, "/")
	// if _, err := os.Stat(propPath); err != nil {
	// 	_, fp, _, _ := runtime.Caller(0) // for devel purpose
	// 	propPath = strings.Join([]string{path.Dir(fp), "schema", "rest.properties.json"}, "/")
	// }

	// slog.Debugf("rest properties json path: %s", propPath)
	// props, err := ioutil.ReadFile(propPath)
	// if err != nil {
	// 	slog.Errorf("failed to read %s", err)
	// 	return err
	// }

	bProps, err := propFile.ReadFile("rest.properties.json")
	if err != nil {
		return fmt.Errorf("failed to open rest.properties.json: %s", err.Error())
	}
	if err := json.Unmarshal(bProps, &properties); err != nil {
		return fmt.Errorf("failed to unmarshal properties data: %s", err)
	}
	return nil
}

func Initialize(bip *f5_bigip.BIGIP, as3Svc string, logLevel string) error {
	as3Service = as3Svc
	bigip = bip
	waitForAs3Service()
	return loadProperties()
}
