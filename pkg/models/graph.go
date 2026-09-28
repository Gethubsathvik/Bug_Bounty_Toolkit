package models

import (
	"sort"
	"strings"
	"time"
)

// NodeKind identifies the type of a node in the asset graph.
type NodeKind string

const (
	NodeOrganization NodeKind = "organization"
	NodeDomain       NodeKind = "domain"
	NodeSubdomain    NodeKind = "subdomain"
	NodeIP           NodeKind = "ip"
	NodePort         NodeKind = "port"
	NodeService      NodeKind = "service"
	NodeEndpoint     NodeKind = "endpoint"
	NodeParameter    NodeKind = "parameter"
	NodeTechnology   NodeKind = "technology"
)

// Node is a vertex in the asset graph. Key is globally unique and canonical so
// that repeated scans converge on the same node.
type Node struct {
	Kind  NodeKind          `json:"kind"`
	Key   string            `json:"key"`
	Label string            `json:"label,omitempty"`
	Attrs map[string]string `json:"attrs,omitempty"`
	First time.Time         `json:"first_seen"`
	Last  time.Time         `json:"last_seen"`
}

// EdgeRel enumerates the relationship vocabulary of the asset graph.
type EdgeRel string

const (
	RelOwns         EdgeRel = "owns"          // organization -> domain
	RelHasSubdomain EdgeRel = "has_subdomain" // domain -> subdomain
	ResolvesTo      EdgeRel = "resolves_to"   // subdomain -> ip
	RelExposes      EdgeRel = "exposes"       // ip -> service
	RelServesPort   EdgeRel = "serves_port"   // ip -> port
	RelUsesTech     EdgeRel = "uses"          // service -> technology
	RelHasEndpoint  EdgeRel = "has_endpoint"  // service -> endpoint
	RelHasParam     EdgeRel = "has_parameter" // endpoint -> parameter
	RelRedirectsTo  EdgeRel = "redirects_to"  // service -> service
)

// Edge is a directed relationship between two nodes.
type Edge struct {
	From  NodeKind `json:"from_kind"`
	FromK string   `json:"from"`
	Rel   EdgeRel  `json:"rel"`
	To    NodeKind `json:"to_kind"`
	ToK   string   `json:"to"`
	Attrs string   `json:"attrs,omitempty"`
}

// Graph is an in-memory asset graph. It is not concurrency safe on its own;
// callers must synchronise access (the storage layer serialises writes).
type Graph struct {
	nodes map[string]Node
	edges map[string]Edge
}

// NewGraph returns an empty graph.
func NewGraph() *Graph {
	return &Graph{nodes: make(map[string]Node), edges: make(map[string]Edge)}
}

func nodeKey(kind NodeKind, key string) string { return string(kind) + "\x00" + key }

// AddNode inserts or updates a node, merging attributes. Existing attributes
// win so that a later, less-informed observation cannot overwrite a richer one.
func (g *Graph) AddNode(n Node) {
	if n.Kind == "" || strings.TrimSpace(n.Key) == "" {
		return
	}
	if n.First.IsZero() {
		n.First = time.Now().UTC()
	}
	if n.Last.IsZero() {
		n.Last = n.First
	}
	k := nodeKey(n.Kind, n.Key)
	if cur, ok := g.nodes[k]; ok {
		if n.First.Before(cur.First) || cur.First.IsZero() {
			cur.First = n.First
		}
		if n.Last.After(cur.Last) {
			cur.Last = n.Last
		}
		if cur.Label == "" {
			cur.Label = n.Label
		}
		if cur.Attrs == nil {
			cur.Attrs = map[string]string{}
		}
		for ak, av := range n.Attrs {
			if _, exists := cur.Attrs[ak]; !exists {
				cur.Attrs[ak] = av
			}
		}
		g.nodes[k] = cur
		return
	}
	if n.Attrs == nil {
		n.Attrs = map[string]string{}
	}
	g.nodes[k] = n
}

// AddEdge inserts an edge, ignoring exact duplicates.
func (g *Graph) AddEdge(e Edge) {
	if e.From == "" || e.To == "" || e.Rel == "" {
		return
	}
	k := string(e.From) + "\x00" + e.FromK + "\x00" + string(e.Rel) + "\x00" + string(e.To) + "\x00" + e.ToK
	g.edges[k] = e
}

// Nodes returns nodes of a kind sorted by key.
func (g *Graph) Nodes(kind NodeKind) []Node {
	out := []Node{}
	for _, n := range g.nodes {
		if kind == "" || n.Kind == kind {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Edges returns all edges, sorted for deterministic report output.
func (g *Graph) Edges() []Edge {
	out := make([]Edge, 0, len(g.edges))
	for _, e := range g.edges {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FromK != out[j].FromK {
			return out[i].FromK < out[j].FromK
		}
		if out[i].Rel != out[j].Rel {
			return out[i].Rel < out[j].Rel
		}
		return out[i].ToK < out[j].ToK
	})
	return out
}

// Len reports the node count.
func (g *Graph) Len() int { return len(g.nodes) }

// Stats summarizes the graph by node kind.
func (g *Graph) Stats() map[NodeKind]int {
	out := map[NodeKind]int{}
	for _, n := range g.nodes {
		out[n.Kind]++
	}
	return out
}
