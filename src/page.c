#include <linux/kernel.h>
#include <linux/module.h>

#include <asm/tlbflush.h>
#include <asm/pgtable_types.h>

#include "page.h"
#include "alloc.h"

bool is_page_protnone(unsigned long vaddr){
	unsigned int l;
	pte_t* pte;
	pteval_t val;

	pte = lookup_address(vaddr, &l);

	if(l == PG_LEVEL_4K){
		val = native_pte_val(*pte);

		if((val & _PAGE_PRESENT) != _PAGE_PRESENT){
			// if((val & _PAGE_PROTNONE) == _PAGE_PROTNONE){
			if((val & _PAGE_SPECIAL) == _PAGE_SPECIAL){
				return true;
			}
		}
	} else if(l == PG_LEVEL_2M){

	}

	return false;
}

void set_present_bit(unsigned long vaddr){
	pte_t *pte;
	pteval_t val;
	unsigned int l;

	pte = lookup_address(vaddr, &l);

	if(l == PG_LEVEL_4K){
		val = native_pte_val(*pte);

		if((val & _PAGE_USER) != _PAGE_USER){
			val |= _PAGE_PRESENT;
			// val &= ~_PAGE_PROTNONE;
			val &= ~_PAGE_SPECIAL;

			set_pte(pte, __pte(val));
			__flush_tlb_all();
		}
	} else if(l == PG_LEVEL_2M){

	} else{
			printk("[set_present_bit] page 4K nor 2M\n");
	}
}

void pages_clear_present_bit(unsigned long vaddr, size_t size){
	int i = 0;

	// pr_crit("pages_clear_present_bit: vaddr start: 0x%px, size: 0x%lx", vaddr, size);

	for(; i <= (size-1) / PAGE_SIZE; i++){
		clear_present_bit(vaddr + i * PAGE_SIZE);

		// pr_crit("pages_clear_present_bit: vaddr: 0x%px", vaddr + i*PAGE_SIZE);
	}
}

void clear_present_bit(unsigned long vaddr){
	pte_t *pte;
	pteval_t val;
	unsigned int l;

	pte = lookup_address(vaddr, &l);

	if(l == PG_LEVEL_4K){
		val = native_pte_val(*pte);

		if((val & _PAGE_USER) != _PAGE_USER){
			val &= ~_PAGE_PRESENT;
			// val |= _PAGE_PROTNONE;
			val |= _PAGE_SPECIAL;

			set_pte(pte, __pte(val));
			__flush_tlb_all();

			// printk("[clear_present_bit] vaddr = 0x%lx pte val = 0x%lx\n", vaddr, val);
		}
	} else if(l == PG_LEVEL_2M) {

	} else{
		printk("[clear_present_bit] not level 4K or 2M\n");
	}
}
