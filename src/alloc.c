#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>

#include <asm/pgtable_types.h>
#include <asm/tlbflush.h>

#include "alloc.h"
#include "page.h"
#include "report.h"
#include "process_handle.h"

void* g_shadow_memory;

void* (* __vmalloc_node_range_)(unsigned long size, unsigned long align,
			unsigned long start, unsigned long end, gfp_t gfp_mask,
			pgprot_t prot, unsigned long vm_flags, int node,
			const void *caller);

int (* change_page_attr_set_clr_)(unsigned long *addr, int numpages, pgprot_t mask_set, pgprot_t mask_clr,
				    int force_split, int in_flag, struct page **pages);

inline void *kasan_mem_to_shadow(const void *addr){
	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT) + KASAN_SHADOW_OFFSET;
}

void init_kasan(void){
	unsigned long vaddr = 0xffff880000100000;
	unsigned long shadow_start, shadow_end;
	size_t size = PAGE_SIZE * 0x100;

	__vmalloc_node_range_ = (void *)kallsyms_lookup_name("__vmalloc_node_range");
	change_page_attr_set_clr_ = (void*) kallsyms_lookup_name("change_page_attr_set_clr");

	shadow_start = (unsigned long)kasan_mem_to_shadow((void*)vaddr);
	shadow_end = (unsigned long)kasan_mem_to_shadow((void*)vaddr + size);

	g_shadow_memory = __vmalloc_node_range_(size >> KASAN_SHADOW_SCALE_SHIFT, 1,
			shadow_start, shadow_end,
			GFP_KERNEL | __GFP_ZERO | __GFP_RETRY_MAYFAIL,
			PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
			__builtin_return_address(0));

	bokasan_poison_shadow((void*)vaddr, size, BOKASAN_FREE_PAGE);

	pages_clear_present_bit(vaddr, size);
}

static inline size_t slab_ksize(const struct kmem_cache *s)
{
	// if (s->flags & SLAB_KASAN)
		// return s->object_size;
	/*
	 * If we have the need to store the freelist pointer
	 * back there or track user information then we can
	 * only use the space before that information.
	 */
	// if (s->flags & (SLAB_TYPESAFE_BY_RCU | SLAB_STORE_USER))
		// return s->inuse;
	/*
	 * Else we can use all the padding etc for the allocation
	 */
	return s->size;
}

size_t ksize_(const void *object)
{
	struct page *page;

	if (unlikely(object == ZERO_SIZE_PTR))
		return 0;

	page = virt_to_head_page(object);

	if (unlikely(!PageSlab(page))) {
		WARN_ON(!PageCompound(page));
		return PAGE_SIZE << compound_order(page);
	}

	return slab_ksize(page->slab_cache);
}

/*
 * Figure out which kmalloc slab an allocation of a certain size
 * belongs to.
 * 0 = zero alloc
 * 1 =  65 .. 96 bytes
 * 2 = 129 .. 192 bytes
 * n = 2^(n-1)+1 .. 2^n
 */
int kmalloc_index_(size_t size)
{
	if (!size)
		return 0;

	// if (size <= KMALLOC_MIN_SIZE)
	// 	return KMALLOC_SHIFT_LOW;

	// if (KMALLOC_MIN_SIZE <= 32 && size > 64 && size <= 96)
	// 	return 1;
	// if (KMALLOC_MIN_SIZE <= 64 && size > 128 && size <= 192)
	// 	return 2;
	// if (size <=          8) return 3;
	// if (size <=         16) return 4;
	// if (size <=         32) return 5;
	// if (size <=         64) return 6;
	// if (size <=        128) return 7;
	// if (size <=        256) return 8;
	if (size <=        512) return 9;
	if (size <=       1024) return 10;
	if (size <=   2 * 1024) return 11;
	if (size <=   4 * 1024) return 12;
	if (size <=   8 * 1024) return 13;
	if (size <=  16 * 1024) return 14;
	if (size <=  32 * 1024) return 15;
	if (size <=  64 * 1024) return 16;
	if (size <= 128 * 1024) return 17;
	if (size <= 256 * 1024) return 18;
	if (size <= 512 * 1024) return 19;
	if (size <= 1024 * 1024) return 20;
	if (size <=  2 * 1024 * 1024) return 21;
	if (size <=  4 * 1024 * 1024) return 22;
	if (size <=  8 * 1024 * 1024) return 23;
	if (size <=  16 * 1024 * 1024) return 24;
	if (size <=  32 * 1024 * 1024) return 25;
	if (size <=  64 * 1024 * 1024) return 26;
	BUG();

	/* Will never be reached. Needed because the compiler may complain */
	return -1;
}

/*
 * Adaptive redzone policy taken from the userspace AddressSanitizer runtime.
 * For larger allocations larger redzones are used.
 */
static size_t optimal_redzone(size_t object_size)
{
	int rz =
			object_size <= (1 << 14) - 256  ? 256 :
			object_size <= (1 << 15) - 512  ? 512 :
			object_size <= (1 << 16) - 1024 ? 1024 : 2048;
	return rz;
}

size_t get_kasan_size(size_t size){
	return size + optimal_redzone(size);
}

void make_4k_page(void* object){
	int l, pid = task_pid_nr(current);
	unsigned long addr;

	lookup_address((unsigned long)object, &l);

	if(l == PG_LEVEL_2M || l == PG_LEVEL_1G){
		addr = (unsigned long) object;

		if(is_current_pid_present()){
			remove_pid(pid);
			change_page_attr_set_clr_(&addr, 1, __pgprot(0), __pgprot(0), 1, 0, NULL);
			add_pid(pid);
		} else{
			change_page_attr_set_clr_(&addr, 1, __pgprot(0), __pgprot(0), 1, 0, NULL);
		}
	}
}

bool is_shadow_page_exist(unsigned long vaddr){
	unsigned int l;
	pte_t *pte = lookup_address((unsigned long)kasan_mem_to_shadow((void *) vaddr), &l);
	
	if(pte != NULL){
		if(l == PG_LEVEL_2M){
			pmd_t *pmd = (pmd_t*)pte;

			if(pmd_val(*pmd) == 0 || !pmd_present(*pmd) || pmd_none(*pmd)){
				return false;
			}
		} else if(l == PG_LEVEL_4K){
				if(pte_val(*pte) == 0 || !pte_present(*pte) || pte_none(*pte) || !pte_accessible(current->mm, *pte)){
					return false;
				}
		}
		else {
			pr_info("is_shadow_page_exist: not 4K or 2M l %u", l);
			return false;
		}
	} else{
		return false;
	}

	return true;
}

bool is_page_exist(unsigned long vaddr){
	unsigned int l;
	pte_t *pte = lookup_address(vaddr, &l);

	if(pte != NULL){
		if(likely(l == PG_LEVEL_4K)){
			if(pte_val(*pte) == 0){
				return false;
			}

			if(!pte_present(*pte)){
				return false;
			}

			if(pte_none(*pte)){
				return false;
			}
		}
		else if(l == PG_LEVEL_2M){
			pmd_t *pmd = (pmd_t*)pte;

			if(pmd_val(*pmd) == 0 || !pmd_present(*pmd) || pmd_none(*pmd)){
				pr_info("is_page_exist: pmd val 0");
				return false;
			}
		} else {
			pr_info("is_page_exist: l %u", l);
			return false;
		}
	}else{
		return false;
	}

	return true;
}

static __always_inline bool memory_is_poisoned_1(unsigned long addr)
{
	s8* shadow_addr = (s8 *)kasan_mem_to_shadow((void *)addr);
	s8 shadow_value = *shadow_addr;

	if (unlikely(shadow_value)) {
		s8 last_accessible_byte = addr & KASAN_SHADOW_MASK;
		return unlikely(last_accessible_byte >= shadow_value);
	}

	return false;
}

void clear_kasan_alloc_shadow(unsigned long vaddr){
	size_t size;
	unsigned long start;

	if(unlikely(ZERO_OR_NULL_PTR(vaddr))) return;

	size = ksize_((void *) vaddr);
	start = vaddr;

	if(is_bokasan_allocated_page(start)){
		if(!irq_count())
			bokasan_unpoison_shadow((void *)start, size, BOKASAN_PAGE);
		else
			bokasan_unpoison_shadow_irq((void *)start, size, BOKASAN_PAGE);
	}
}

// Check address validity
bool check_poison(unsigned long vaddr, unsigned long ip){
	if(memory_is_poisoned_1(vaddr)){
		char fname[100];

		snprintf(fname, 100, "%pS", (void*)ip);

		if(!strncmp(fname, "clear_page_erms", strlen("clear_page_erms"))){
			clear_kasan_alloc_shadow(vaddr);
			set_present_bit(vaddr);

			return true;
		}

		// Raise kernel panic if address is not valid
		report_poison_1(vaddr, ip);

		return false;
	}

	return true;
}

bool is_bokasan_allocated(unsigned long vaddr){
	s8* shadow_addr;
	s8 shadow_value;

	if(unlikely(ZERO_OR_NULL_PTR(vaddr))) return false;

	shadow_addr = (s8 *)kasan_mem_to_shadow((void *)vaddr);
	shadow_value = *shadow_addr;

	if(BOKASAN_OBJECT == shadow_value)
		return true;

	return false;
}

bool is_bokasan_allocated_page(unsigned long vaddr){
	s8* shadow_addr = (s8 *)kasan_mem_to_shadow((void *)vaddr);
	s8 shadow_value;

	if(!is_page_exist((unsigned long)shadow_addr)) return false;

	shadow_value = *shadow_addr;

	if(0 != shadow_value)
		return true;

	// shadow_addr = (s8 *)kasan_mem_to_shadow((void *)(vaddr & ~(PAGE_SIZE-1)));
	// shadow_value = *shadow_addr;

	// if(0 != shadow_value)
	// 	return true;

	return false;
}

/*
 * Poisons the shadow memory for 'size' bytes starting from 'addr'.
 * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
 */
void bokasan_poison_shadow(const void *address, size_t size, u8 value)
{
	void *shadow_start, *shadow_end;

	shadow_start = kasan_mem_to_shadow(address);
	shadow_end = kasan_mem_to_shadow(address + size);

	memset(shadow_start, value, shadow_end - shadow_start);
}

void bokasan_poison_shadow_irq(const void *address, size_t size, u8 value)
{
	void *shadow_start, *shadow_end;

	shadow_start = kasan_mem_to_shadow(address);
	shadow_end = kasan_mem_to_shadow(address + size);

	memset(shadow_start, value, shadow_end - shadow_start);
}

void bokasan_unpoison_shadow(const void *address, size_t size, u8 value)
{
	bokasan_poison_shadow(address, size, value);

	if (size & KASAN_SHADOW_MASK) {
		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);

		*shadow = size & KASAN_SHADOW_MASK;
	}
}

void bokasan_unpoison_shadow_irq(const void *address, size_t size, u8 value)
{
	bokasan_poison_shadow_irq(address, size, value);

	if (size & KASAN_SHADOW_MASK) {
		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);

		*shadow = size & KASAN_SHADOW_MASK;
	}
}

bool alloc_shadow_page_1m(unsigned long shadow_start){
	int pid = -1;
	size_t page_count = 0x100;

	shadow_start = shadow_start & ~(PAGE_SIZE*page_count-1);

	if(is_current_pid_present()){
		pid = task_pid_nr(current);
	}

	remove_pid(pid);

	g_shadow_memory = __vmalloc_node_range_(PAGE_SIZE*page_count, 1,
			shadow_start, shadow_start+PAGE_SIZE*page_count,
			GFP_KERNEL | __GFP_ZERO | __GFP_RETRY_MAYFAIL,
			PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
			__builtin_return_address(0));

	if(pid != -1) add_pid(pid);

	if(!ZERO_OR_NULL_PTR(g_shadow_memory)) return true;

	return false;
}

bool alloc_shadow_page(unsigned long shadow_start){
	int pid = -1;

	if(irq_count()) {
		return false;
	}

	shadow_start = shadow_start & ~(PAGE_SIZE-1);

	if(is_current_pid_present()){
		pid = task_pid_nr(current);
	}

	remove_pid(pid);

	g_shadow_memory = __vmalloc_node_range_(PAGE_SIZE, 1,
			shadow_start, shadow_start+PAGE_SIZE,
			GFP_KERNEL | __GFP_ZERO | __GFP_RETRY_MAYFAIL,
			PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
			__builtin_return_address(0));

	if(pid != -1) add_pid(pid);

	if(!ZERO_OR_NULL_PTR(g_shadow_memory)) return true;

	remove_pid(pid);

	g_shadow_memory = __vmalloc_node_range_(PAGE_SIZE*2, 1,
			shadow_start, shadow_start+PAGE_SIZE*2,
			GFP_KERNEL | __GFP_ZERO | __GFP_RETRY_MAYFAIL,
			PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
			__builtin_return_address(0));

	if(pid != -1) add_pid(pid);

	if(!ZERO_OR_NULL_PTR(g_shadow_memory)) return true;

	remove_pid(pid);

	g_shadow_memory = __vmalloc_node_range_(PAGE_SIZE*4, 1,
			shadow_start, shadow_start+PAGE_SIZE*4,
			GFP_KERNEL | __GFP_ZERO | __GFP_RETRY_MAYFAIL,
			PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
			__builtin_return_address(0));

	if(pid != -1) add_pid(pid);

	if(!ZERO_OR_NULL_PTR(g_shadow_memory)) return true;

	return false;
}

bool alloc_shadow(size_t size, unsigned long addr){
	unsigned long shadow_addr;
	unsigned long addr_first = 0, addr_last = 0;

	if(size == 0) return false;

	addr_first = addr & ~(PAGE_SIZE-1);
	addr_last = PAGE_ALIGN(addr + size) - 1;

	for(; addr_first < addr_last; addr_first += PAGE_SIZE){
		shadow_addr = (unsigned long)kasan_mem_to_shadow((void *)addr_first);

		if(!is_page_exist(shadow_addr)){
			if(alloc_shadow_page_1m(shadow_addr) == false && alloc_shadow_page(shadow_addr) == false){
				pr_err("alloc_shadow failed... addr %px shadow_addr %px size %lx\n", (void *)addr, (void*)shadow_addr, size);

				return false;
			}
		}

		if(!is_bokasan_allocated_page(addr_first)){
			memset((void*)shadow_addr, BOKASAN_PAGE, PAGE_SIZE >> KASAN_SHADOW_SCALE_SHIFT);
		}
	}

	return true;
}

bool bokasan_kmalloc(const void *object, size_t size){
	unsigned long redzone_start;
	unsigned long redzone_end;

	if(unlikely(object == NULL)) return false;

	redzone_start = round_up((unsigned long)object + size,
				KASAN_SHADOW_SCALE_SIZE);
	redzone_end = round_up((unsigned long)object + ksize_(object),
				KASAN_SHADOW_SCALE_SIZE);

	// Allocate shadow memory
	if(alloc_shadow(ksize_(object), (unsigned long)object) == false){
		return false;
	}

	if(size < KASAN_SHADOW_SCALE_SIZE){
		bokasan_unpoison_shadow(object, round_up(size, KASAN_SHADOW_SCALE_SIZE), BOKASAN_OBJECT);
	}
	else{
		bokasan_unpoison_shadow(object, size, BOKASAN_OBJECT);
	}

	// Make redzone
	bokasan_poison_shadow((void *)redzone_start, redzone_end - redzone_start, BOKASAN_REDZONE);

	// Clear page present bit
	pages_clear_present_bit((unsigned long)object, ksize_(object));

	return true;
}

bool bokasan_kmalloc_large(const void *object, size_t size, gfp_t flags)
{
	struct page *page;
	unsigned long redzone_start;
	unsigned long redzone_end;

	if (unlikely(object == NULL))
		return false;

	page = virt_to_page(object);
	redzone_start = round_up((unsigned long)(object + size),
				KASAN_SHADOW_SCALE_SIZE);
	redzone_end = (unsigned long)object + (PAGE_SIZE << compound_order(page));

	if(alloc_shadow(ksize_(object), (unsigned long)object) == false){
		pr_info("[kasan_kmalloc] failed!");
		return false;
	}

	bokasan_unpoison_shadow(object, size, BOKASAN_OBJECT);
	bokasan_poison_shadow((void *)redzone_start, redzone_end - redzone_start, BOKASAN_PAGE_REDZONE);

	pages_clear_present_bit((unsigned long)object, redzone_end - (unsigned long)object);

	return true;
}

void bokasan_alloc_pages_(struct page *page, unsigned int order)
{
	if (likely(!PageHighMem(page))){
		if(alloc_shadow(PAGE_SIZE << order, (unsigned long)page_address(page)) == false){
			pr_info("[kasan_kmalloc] failed!");
			return;
		}

		bokasan_unpoison_shadow(page_address(page), PAGE_SIZE << order, 0);
	}
}

void bokasan_free_pages_(struct page *page, unsigned int order)
{
	if (likely(!PageHighMem(page))){
		if(alloc_shadow(PAGE_SIZE << order, (unsigned long)page_address(page)) == false){
			pr_info("[kasan_kmalloc] failed!");
			return;
		}

		bokasan_poison_shadow(page_address(page), PAGE_SIZE << order, BOKASAN_FREE_PAGE);

		make_4k_page(page_address(page));

		pages_clear_present_bit((unsigned long)page_address(page), PAGE_SIZE << order);
	}
}

void bokasan_kfree_poison(struct kmem_cache *cache, const void* addr, size_t _size){
	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
		return;

	// Set BOKASAN_FREE
	bokasan_poison_shadow(addr, _size, BOKASAN_FREE);
}