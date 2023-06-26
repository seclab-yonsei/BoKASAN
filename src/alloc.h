#ifndef __BOKASAN_ALLOC__
#define __BOKASAN_ALLOC__

#include <linux/kobject.h>
#include <linux/mm.h>
#include <linux/slub_def.h>

inline void *kasan_mem_to_shadow(const void *addr);

void init_kasan(void);

void make_4k_page(void* object);

size_t ksize_(const void *object);

size_t get_kasan_size(size_t size);
int kmalloc_index_(size_t size);

bool check_poison(unsigned long vaddr, unsigned long ip);

bool is_bokasan_allocated(unsigned long vaddr);
bool is_bokasan_allocated_page(unsigned long vaddr);

bool is_shadow_page_exist(unsigned long vaddr);
bool is_page_exist(unsigned long vaddr);

void clear_kasan_alloc_shadow(unsigned long vaddr);

bool alloc_shadow(size_t size, unsigned long addr);

void bokasan_poison_shadow(const void *address, size_t size, u8 value);
void bokasan_poison_shadow_irq(const void *address, size_t size, u8 value);

void bokasan_unpoison_shadow(const void *address, size_t size, u8 value);
void bokasan_unpoison_shadow_irq(const void *address, size_t size, u8 value);

bool bokasan_kmalloc(const void *object, size_t size);
bool bokasan_kmalloc_large(const void *object, size_t size, gfp_t flags);

void bokasan_alloc_pages_(struct page *page, unsigned int order);
void bokasan_free_pages_(struct page *page, unsigned int order);

void bokasan_kfree_poison(struct kmem_cache *cache, const void* addr, size_t size);

#define KASAN_MAX_OBJECT_SIZE 0x2000

// #define CONFIG_KASAN_SHADOW_OFFSET	0xdffffc0000000000
#define CONFIG_KASAN_SHADOW_OFFSET	0xDFFFEFF000000000 //0xdfffebe000000000
#define KASAN_SHADOW_SCALE_SHIFT	3
#define KASAN_SHADOW_OFFSET 		_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)

#define KASAN_SHADOW_SCALE_SIZE (1UL << KASAN_SHADOW_SCALE_SHIFT)
#define KASAN_SHADOW_MASK       (KASAN_SHADOW_SCALE_SIZE - 1)

#define BOKASAN_OBJECT			0x7F
#define BOKASAN_PAGE			0x7E

#define BOKASAN_FREE_PAGE       0xFF
#define BOKASAN_PAGE_REDZONE	0xFE
#define BOKASAN_REDZONE   		0xFC
#define BOKASAN_FREE      		0xFB

#endif