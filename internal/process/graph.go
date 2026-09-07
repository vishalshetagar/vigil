// Package process tracks bounded, identity-aware process history.
package process

import (
	"container/list"
	"vigil/internal/event"
)

type Node struct {
	Key        string         `json:"key"`
	Identity   event.Identity `json:"identity"`
	ParentKey  string         `json:"parent_key,omitempty"`
	Comm       string         `json:"comm,omitempty"`
	Filename   string         `json:"filename,omitempty"`
	Generation uint64         `json:"generation"`
	FirstNS    uint64         `json:"first_ns"`
	LastNS     uint64         `json:"last_ns"`
	Exited     bool           `json:"exited"`
	Partial    bool           `json:"partial"`
	Exec       *event.Event   `json:"exec,omitempty"`
}

type entry struct {
	node    *Node
	recency *list.Element
}
type Graph struct {
	nodes     map[string]entry
	order     *list.List
	capacity  int
	Evictions uint64
}

func New(capacity int) *Graph {
	if capacity < 1 {
		capacity = 1
	}
	return &Graph{nodes: make(map[string]entry), order: list.New(), capacity: capacity}
}

// Apply must be called by one ordered processor. Returned nodes must not be mutated.
func (g *Graph) Apply(e event.Event) *Node {
	if e.Type == event.Gap {
		return nil
	}
	key := e.Key()
	x, ok := g.nodes[key]
	if !ok {
		if len(g.nodes) >= g.capacity {
			oldest := g.order.Front()
			delete(g.nodes, oldest.Value.(string))
			g.order.Remove(oldest)
			g.Evictions++
		}
		n := &Node{Key: key, Identity: e.Process, ParentKey: e.ParentKey(), FirstNS: e.TimeNS, Partial: e.Type != event.Fork}
		x = entry{n, g.order.PushBack(key)}
		g.nodes[key] = x
	}
	g.order.MoveToBack(x.recency)
	n := x.node
	if e.TimeNS < n.LastNS {
		return n
	} // late events never overwrite newer image state
	n.LastNS = e.TimeNS
	if n.ParentKey == "" {
		n.ParentKey = e.ParentKey()
	}
	if e.Type == event.Exec {
		n.Generation++
		n.Filename = e.Filename
		n.Comm = e.Comm
		copy := e
		n.Exec = &copy
	}
	if n.Comm == "" {
		n.Comm = e.Comm
	}
	if e.Type == event.Exit && e.GroupDead {
		n.Exited = true
	}
	return n
}

func (g *Graph) Get(key string) *Node { return g.nodes[key].node }
func (g *Graph) Len() int             { return len(g.nodes) }

// Ancestors is cycle-safe and has a fixed depth bound, including missing parents.
func (g *Graph) Ancestors(key string, limit int) []*Node {
	var out []*Node
	seen := map[string]bool{key: true}
	n := g.Get(key)
	for n != nil && n.ParentKey != "" && len(out) < limit {
		if seen[n.ParentKey] {
			break
		}
		seen[n.ParentKey] = true
		n = g.Get(n.ParentKey)
		if n != nil {
			out = append(out, n)
		}
	}
	return out
}
