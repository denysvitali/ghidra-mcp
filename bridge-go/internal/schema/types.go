// Package schema parses, sanitizes, and serves tool definitions sourced
// from the Ghidra plugin's /mcp/schema endpoint.
//
// The upstream format is produced by Java's AnnotationScanner
// (src/main/java/com/xebyte/core/AnnotationScanner.java) and looks like:
//
//	{
//	  "tools": [
//	    {
//	      "path": "/decompile_function",
//	      "method": "POST",
//	      "description": "Decompile a function by address",
//	      "category": "function",
//	      "category_description": "Function-level operations",
//	      "params": [
//	        {
//	          "name": "address",
//	          "type": "string",
//	          "description": "Function address",
//	          "source": "body",
//	          "paramType": "address",
//	          "required": true
//	        }
//	      ]
//	    }
//	  ]
//	}
package schema

// ParamSource describes where a parameter travels in the upstream HTTP call.
type ParamSource string

const (
	SourceBody  ParamSource = "body"
	SourceQuery ParamSource = "query"
	SourcePath  ParamSource = "path"
)

// ParamDef is one input parameter, normalized from the upstream schema.
type ParamDef struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"` // string | integer | boolean | number | object | array
	Description string      `json:"description"`
	Source      ParamSource `json:"source"`    // body | query | path
	ParamType   string      `json:"paramType"` // address | string | etc
	Required    bool        `json:"required"`
	Default     any         `json:"default,omitempty"`
	Enum        []string    `json:"enum,omitempty"`
}

// ToolDef is one MCP tool, normalized and sanitized.
type ToolDef struct {
	Name          string     `json:"name"`
	OriginalName  string     `json:"originalName"`
	SanitizedName string     `json:"sanitizedName"`
	NameCollided  bool       `json:"nameCollided"`
	Endpoint      string     `json:"endpoint"`
	HTTPMethod    string     `json:"httpMethod"`
	Description   string     `json:"description"`
	Category      string     `json:"category"`
	CategoryDesc  string     `json:"categoryDescription"`
	Params        []ParamDef `json:"params"`
}

// RawTool is the upstream AnnotationScanner shape before normalization.
type RawTool struct {
	Path         string     `json:"path"`
	Method       string     `json:"method"`
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	Category     string     `json:"category"`
	CategoryDesc string     `json:"categoryDescription"`
	Params       []RawParam `json:"params"`
}

// RawParam is the upstream AnnotationScanner parameter shape.
type RawParam struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Source      string   `json:"source"`
	ParamType   string   `json:"paramType"`
	Required    bool     `json:"required"`
	Default     any      `json:"default"`
	Enum        []string `json:"enum"`
}

// RawSchema is the top-level shape returned by GET /mcp/schema.
type RawSchema struct {
	Tools []RawTool `json:"tools"`
}
