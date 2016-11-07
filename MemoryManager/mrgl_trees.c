#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "mrgl_trees.h"
#include "mrgl_alloc_config.h"


 
inline static void mrgl_BitScanForward(uint32_t* pIndex, uint32_t key)
{
#ifdef _MSC_VER
	_BitScanForward(pIndex, key);
#else
	*pIndex = __builtin_ctz(key);
#endif
}

inline static void mrgl_BitScanReverse(uint32_t* pIndex, uint32_t key)
{
#ifdef _MSC_VER
	_BitScanReverse(pIndex, key);
#else
	*pIndex = 31 - __builtin_clz(key);
#endif
}

/*void check_node(struct tree_node_size* pParent, struct tree_node_size* pNode)
{
	if(pNode->key == 0xdddddddd || pNode->key != pNode->pNextFree->size){
		pNode = pNode;
	}
	if(pNode->pParent != pParent || pNode->pNextFree->pSizeNode != pNode){
		pNode = pNode;
	}
	if(pNode->pChilds[0] != NULL){
		check_node(pNode, pNode->pChilds[0]);
	}
	if(pNode->pChilds[1] != NULL){
		check_node(pNode, pNode->pChilds[1]);
	}
}*/

/*void check_tree()
{
	for(uint32_t i = 0; i < 32; i++){
		if(middlefin_tree_size.pIndexTable[i] != NULL){
			check_node((struct tree_node_size*)((i << 2) | 0x3) , middlefin_tree_size.pIndexTable[i]);
		}
	}
}*/

inline static uint32_t addr_dist(uint32_t addr1, uint32_t addr2)
{
	return addr1 < addr2 ? (addr2 - addr1) : (addr1 - addr2);
}

void mrgl_tree_insert(struct mrgl_tree_header* pTreeHeader, uint32_t key, struct mrgl_tree_node* pNewNode)
{
	mrgl_assert(key >= 4, "Invalid key");
	uint32_t ikey, tree_index;
	struct mrgl_tree_node* pNode;

	mrgl_BitScanReverse(&tree_index, key);

	pNode = pTreeHeader->pIndexTable[tree_index];
	ikey = 1 << (tree_index - 1);

	if(pNode == NULL){
		// create new node
		pNewNode->pParent = (struct mrgl_tree_node*)((tree_index << 2) | 0x3); // addresses should be always 4-byte aligned atleast, so (pParent & 0x3) != 0 will be the mark of the top node
		pNewNode->pChilds[0] = NULL;
		pNewNode->pChilds[1] = NULL;
		pNewNode->key = key;
		// create new tree
		pTreeHeader->pIndexTable[tree_index] = pNewNode;
		pTreeHeader->BitMap = pTreeHeader->BitMap | (1 << tree_index);

		return;
	}

	while(true){
		uint32_t index = (key & ikey) != 0;// >> 31;

		if(pNode->pChilds[index] == NULL){
			// create new node
			pNewNode->pParent = pNode;
			pNewNode->pChilds[0] = NULL;
			pNewNode->pChilds[1] = NULL;
			pNewNode->key = key;
			pNode->pChilds[index] = pNewNode;
			break;
		}

		pNode = pNode->pChilds[index];
		ikey = ikey >> 1;
	}

}

struct mrgl_tree_node* mrgl_tree_traverse_prev(struct mrgl_tree_node* pNode)
{
	struct mrgl_tree_node* pClosestNode = pNode;

	while(pNode != NULL){
		if(pNode->key > pClosestNode->key){
			pClosestNode = pNode;
		}
		if(pNode->pChilds[1] != NULL){
			pNode = pNode->pChilds[1];
		}else{
			pNode = pNode->pChilds[0];
		}
	}

	return pClosestNode;
}

struct mrgl_tree_node* mrgl_tree_traverse_next(struct mrgl_tree_node* pNode)
{
	struct mrgl_tree_node* pClosestNode = pNode;

		while(pNode != NULL){
			if(pNode->key < pClosestNode->key){
				pClosestNode = pNode;
			}
			if(pNode->pChilds[0] != NULL){
				pNode = pNode->pChilds[0];
			}else{
				pNode = pNode->pChilds[1];
			}
		}

	return pClosestNode;
}

struct mrgl_tree_node* mrgl_tree_find(struct mrgl_tree_header* pTreeHeader, uint32_t key)
{
	mrgl_assert(key >= 4, "Invalid key");
	// any closest find
	uint32_t ikey, tree_index, min_dist;
	struct mrgl_tree_node* pNode, *pClosestNode;

	mrgl_BitScanReverse(&tree_index, key);

	pNode = pTreeHeader->pIndexTable[tree_index];
	ikey = 1 << (tree_index - 1);
	// if appropriate tree is lacking nodes, check its neighbors
	if(pNode == NULL){
		if(pTreeHeader->BitMap != 0){
			uint32_t BitMapH = pTreeHeader->BitMap & (0xfffffffe << tree_index);
			uint32_t BitMapL = pTreeHeader->BitMap & ((1 << tree_index) - 1);
			uint32_t tree_indexl, tree_indexh;

			if(BitMapH != 0){
				mrgl_BitScanForward(&tree_indexh, BitMapH);

				if(BitMapL != 0){
					mrgl_BitScanReverse(&tree_indexl, BitMapL);
					// calculate distance to the left and right neighbors, choose closest
					if((tree_index - tree_indexl) < (tree_indexh - tree_index)){
						pNode = mrgl_tree_traverse_prev(pTreeHeader->pIndexTable[tree_indexl]);
					}else{
						pNode = mrgl_tree_traverse_next(pTreeHeader->pIndexTable[tree_indexh]);
					}
				}else{
					pNode = mrgl_tree_traverse_next(pTreeHeader->pIndexTable[tree_indexh]);
				}
			}else{
				mrgl_BitScanReverse(&tree_indexl, BitMapL);
				pNode = mrgl_tree_traverse_prev(pTreeHeader->pIndexTable[tree_indexl]);
			}
			return pNode;
		}else{
			return NULL;
		}
	}
	// calculate distance between nodes in current tree branch, choose closest
	pClosestNode = pNode;
	min_dist = addr_dist(key, (uint32_t)pNode);

	while(pNode != NULL){
		uint32_t index = (key & ikey) != 0;
		uint32_t dist;
		// if we find perfect match return result
		if((uint32_t)pNode->key == key){
			return pNode;
		}
		dist = addr_dist(key, pNode->key);

		if(dist < min_dist){
			min_dist = dist;
			pClosestNode = pNode;
		}

		pNode = pNode->pChilds[index];
		ikey = ikey >> 1;
	}

	return pClosestNode;
}

void mrgl_tree_remove(struct mrgl_tree_header* pTreeHeader, struct mrgl_tree_node* pNode)
{
	// remove node from tree
	struct mrgl_tree_node** pParentChildsAddr;

	if(((uint32_t)pNode->pParent & 0x3) != 0){
		// top node
		uint32_t tree_index = (uint32_t)pNode->pParent >> 2;

		pParentChildsAddr = &pTreeHeader->pIndexTable[tree_index];
		if(pNode->pChilds[0] == NULL && pNode->pChilds[1] == NULL){
			pTreeHeader->BitMap = pTreeHeader->BitMap & (~(1 << tree_index));
		}
	}else{
		if(pNode->pParent->pChilds[0] == pNode){
			pParentChildsAddr = &pNode->pParent->pChilds[0];
		}else{
			pParentChildsAddr = &pNode->pParent->pChilds[1];
		}
	}

	if(pNode->pChilds[0] == NULL && pNode->pChilds[1] == NULL){
		// node without childs, just remove
		*pParentChildsAddr = NULL;
	}else{
		// swap with the most farther child
		struct mrgl_tree_node* pChildNode = pNode;
		struct mrgl_tree_node** pChildNodeParentAddr;

		while(pChildNode->pChilds[0] != NULL || pChildNode->pChilds[1] != NULL){
			if(pChildNode->pChilds[0] != NULL){
				pChildNodeParentAddr = &pChildNode->pChilds[0];
				pChildNode = pChildNode->pChilds[0];
			}else{
				pChildNodeParentAddr = &pChildNode->pChilds[1];
				pChildNode = pChildNode->pChilds[1];
			}
		}
		pChildNode->pParent = pNode->pParent;
		*pChildNodeParentAddr = NULL;
		pChildNode->pChilds[0] = pNode->pChilds[0];
		if(pNode->pChilds[0] != NULL){
			pNode->pChilds[0]->pParent = pChildNode;
		}
		if(pNode->pChilds[1] != NULL){
			pNode->pChilds[1]->pParent = pChildNode;
		}
		pChildNode->pChilds[1] = pNode->pChilds[1];
		*pParentChildsAddr = pChildNode;
	}

}