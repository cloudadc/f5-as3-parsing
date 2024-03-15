package as3parsing

import "context"

type Property struct {
	RestName        string                 `json:"restname"`
	Falsehood       string                 `json:"falsehood"`
	Truth           string                 `json:"truth"`
	Extend          string                 `json:"extend"`
	QuotedString    bool                   `json:"quotedString"`
	IntToString     bool                   `json:"intToString"`
	MinVersion      string                 `json:"minVersion"`
	RequiredModules map[string]interface{} `json:"requiredModules"`
	Default         string                 `json:"default"`
}

type Properties map[string]Property

type ParseContext struct {
	context.Context
}
type ConvertContext struct {
	context.Context
}
