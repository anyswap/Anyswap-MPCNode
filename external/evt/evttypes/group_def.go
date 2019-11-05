package evttypes

func NewGrouDef(name string, key string, threshold int) *GroupDef {
	return &GroupDef{
		Name: name,
		Key:  key,
		Root: Root{Threshold: threshold, Nodes: make([]interface{}, 0)},
	}
}

func NewNode(threshold int, weight int) *Node {
	return &Node{
		Weight:    weight,
		Threshold: threshold,
		Nodes:     make([]interface{}, 0),
	}
}

func (node *Node) AddNode(newNode *Node) *Node {
	node.Nodes = append(node.Nodes, *newNode)
	return node
}

func (node *Node) AddLeaf(leaf *Leaf) *Node {
	node.Nodes = append(node.Nodes, leaf)
	return node
}

func (root *Root) AddNode(newNode *Node) *Root {
	root.Nodes = append(root.Nodes, newNode)
	return root
}

func (root *Root) AddLeaf(leaf *Leaf) *Root {
	root.Nodes = append(root.Nodes, leaf)
	return root
}
