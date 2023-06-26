#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/stacktrace.h>

#include "report.h"
#include "alloc.h"

void report_poison_1(unsigned long vaddr, unsigned long ip){
	int max_entries = 20, i = 0;
	char fname[100];
	s8 shadow_value;

	unsigned long entries[max_entries];
	struct stack_trace trace = {
		.nr_entries = 0,
		.entries = entries,
		.max_entries = max_entries,
		.skip = 0
	};

	save_stack_trace(&trace);

	for (i = 0; i < trace.nr_entries; i++) {
		if (entries[i] == ip)
			break;
	}

	snprintf(fname, 100, "%pS", (void *)ip);

	if (strstr(fname, "memcpy") != NULL || strstr(fname, "memset") != NULL || strstr(fname, "memmove") != NULL){
		if (i < max_entries-1){
			ip = entries[i+1];
		}
	}

	shadow_value = *(s8 *)kasan_mem_to_shadow((void *)vaddr);

	pr_crit("==================================================================\n");

	if((unsigned long)(shadow_value & 0xff) == BOKASAN_FREE){
		pr_err("BUG: KASAN: use-after-free in %pS vaddr: %px\n", (void *)ip, (void *)vaddr);
	}
	else if((unsigned long)(shadow_value & 0xff) == BOKASAN_REDZONE){
		pr_crit("BUG: KASAN: out-of-bounds access in %pS vaddr: %px\n", (void *)ip, (void *)vaddr);
	}
	else if((unsigned long)(shadow_value & 0xff) == BOKASAN_FREE_PAGE){
		pr_err("BUG: KASAN: use-after-free (page) in %pS vaddr: %px\n", (void *)ip, (void *)vaddr);
	}
	else {
		pr_crit("BUG: KASAN: out-of-bounds access in %pS vaddr: %px\n", (void *)ip, (void *)vaddr);
	}

	// dump_stack();

	panic("bokasan panic...\n");
}
