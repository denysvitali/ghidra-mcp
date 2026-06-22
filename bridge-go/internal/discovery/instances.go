package discovery

import "time"

// Instance represents a discovered Ghidra server reachable over UDS.
type Instance struct {
	Socket     string       `json:"socket"`
	PID        int          `json:"pid"`
	Project    string       `json:"project"`
	Programs   []string     `json:"programs,omitempty"`
	Info       InstanceInfo `json:"info"`
	Discovered time.Time    `json:"discovered"`
}

// InstanceInfo is the upstream /mcp/instance_info payload.
type InstanceInfo struct {
	Project        string   `json:"project"`
	Programs       []string `json:"programs,omitempty"`
	CurrentProgram string   `json:"currentProgram,omitempty"`
	Port           int      `json:"port,omitempty"`
	PID            int      `json:"pid,omitempty"`
	Transport      string   `json:"transport,omitempty"`
	Discovery      string   `json:"discovery,omitempty"`
	Count          int      `json:"count,omitempty"`
}
