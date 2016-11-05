#pragma once

struct mrgl_sizelist_node{
	struct mrgl_sizelist_node* pPrev;
	struct mrgl_sizelist_node* pNext;
	uint32_t size;
};

struct mrgl_sizelist_header{
	uint32_t bitmask;
	uint32_t bitmask2[32];
	uint32_t size_div;
	uint32_t table_size;
	struct mrgl_sizelist_node** pTable;
};

void mrgl_sizelist_insert(struct mrgl_sizelist_header* pHeader, struct mrgl_sizelist_node* pNode);
uint32_t mrgl_sizelist_next(struct mrgl_sizelist_header* pHeader, uint32_t index);
struct mrgl_sizelist_node* mrgl_sizelist_find(struct mrgl_sizelist_header* pHeader, uint32_t size);
void mrgl_sizelist_remove(struct mrgl_sizelist_header* pHeader, struct mrgl_sizelist_node* pNode);