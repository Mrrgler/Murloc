#pragma once

struct mrgl_tree_node{
	struct mrgl_tree_node* pParent;
	struct mrgl_tree_node* pChilds[2];
	uint32_t key;
};


struct mrgl_tree_header{
	struct mrgl_tree_node* pIndexTable[32];
	uint32_t TreeSizes[32]; // size in nodes, not in blocks
	uint32_t BitMap;
};

void mrgl_tree_insert(struct mrgl_tree_header* pTreeHeader, uint32_t key, struct mrgl_tree_node* pNewNode);
struct mrgl_tree_node* mrgl_tree_find(struct mrgl_tree_header* pTreeHeader, uint32_t key);
void mrgl_tree_remove(struct mrgl_tree_header* pTreeHeader, struct mrgl_tree_node* pNode);







