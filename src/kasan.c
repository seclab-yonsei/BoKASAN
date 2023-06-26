#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/mempool.h>

#include <asm/traps.h>
#include <asm/tlbflush.h>
#include <asm/pgtable_types.h>

#include "kasan.h"
#include "hook.h"
#include "page.h"
#include "alloc.h"
#include "process_handle.h"

#define MINOR_BASE 	0
#define MINOR_NUM 	1

#define MAX_ALLOC_TRIAL 10

MODULE_DESCRIPTION("BoKASAN");
MODULE_AUTHOR("Mingi Cho");
MODULE_LICENSE("GPL");

unsigned long g_vaddr;
int major;

static struct cdev bokasan_devs;
static struct class *bokasan_class;

static int bokasan_open(struct inode *inode, struct file *file){
	return 0;
}
static int bokasan_release(struct inode *inode, struct file *file){
	return 0;
}

static ssize_t bokasan_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos){
	return 0;
}

static ssize_t bokasan_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos){
	return 0;
}

static long bokasan_ioctl(struct file *filp, unsigned int cmd, unsigned long arg){
	pid_info inf;

	switch(cmd){
		case SET_PID:
			if(copy_from_user(&inf, (void __user *)arg, sizeof(inf)) > 0) return 0;

			add_pid(inf.pid);
			break;
		case REMOVE_PID:
			if(copy_from_user(&inf, (void __user *)arg, sizeof(inf)) > 0) return 0;

			remove_pid(inf.pid);
			break;
		default:
			printk("there is no such cmd\n");
			break;
	}

	return 0;
}

static void bokasan_setup_cdev(int minor, struct file_operations *fops){
	int err, devno = MKDEV(major, minor);
	cdev_init(&bokasan_devs, fops);
	bokasan_devs.owner = THIS_MODULE;
	bokasan_devs.ops = fops;
	err = cdev_add(&bokasan_devs, devno, MINOR_NUM);

	if(err)
		printk(KERN_NOTICE "bokasan_setup_cdev failed. err: %d", err);

	bokasan_class = class_create(THIS_MODULE, DEVICE_NAME);
	if(IS_ERR(bokasan_class)){
		printk(KERN_ERR "bokasan_class_create\n");
		cdev_del(&bokasan_devs);
		unregister_chrdev_region(devno, MINOR_NUM);
	}

	device_create(bokasan_class, NULL, MKDEV(major, 0), NULL, "kasan%d", 0);
}

// Allocation functions
static asmlinkage void* fh_kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags){
	void* object = NULL, *rz_obj = NULL;
	int i = 0, j = 0;
	size_t size = 0;

	// Selective sanitization
	if(!is_current_pid_present() || irq_count()){
		for(i = 0; i <= MAX_ALLOC_TRIAL; i++){
			object = real_kmem_cache_alloc(cachep, flags);

			if(ZERO_OR_NULL_PTR(object)) return object;

			if(i == MAX_ALLOC_TRIAL) break;

			if(is_page_protnone((unsigned long)object)){
				bokasan_kmalloc(object, 0);
			}
			else{
				break;
			}
		}

		return object;
	} else {
		// Sanitized allocation
		char fname[100];
		void * temp_obj[MAX_ALLOC_TRIAL] = {NULL,};

		snprintf(fname, 100, "%pS", __builtin_return_address(0));

		if(strstr(fname, "skb_clone") != NULL){
			object = real_kmem_cache_alloc(cachep, flags);

			return object;
		}

		size = cachep->object_size;

		object = real_kmem_cache_alloc(cachep, flags);

		if(ZERO_OR_NULL_PTR(object)) return object;

		for(i = 0; i < MAX_ALLOC_TRIAL; i++){
			rz_obj = real_kmem_cache_alloc(cachep, flags);

			if(rz_obj == object + cachep->size){
				make_4k_page(object);
				make_4k_page(rz_obj);

				bokasan_kmalloc(object, size);
				bokasan_kmalloc(rz_obj, 0);

				for(j = 0; j < i; j++)
					real_kmem_cache_free(cachep, temp_obj[j]);

				break;
			}else{
				temp_obj[i] = object;
				object = rz_obj;
			}
		}

		return object;
	}
}

static asmlinkage void* fh_kmem_cache_alloc_trace(struct kmem_cache *cachep, gfp_t flags, size_t size){
	void* object = NULL;
	int i = 0;

	if(!is_current_pid_present() || irq_count() || size > KMALLOC_MAX_CACHE_SIZE){
		for(i = 0; i <= MAX_ALLOC_TRIAL; i++){
			object = real_kmem_cache_alloc_trace(cachep, flags, size);

			if(ZERO_OR_NULL_PTR(object)) return object;

			if(i == MAX_ALLOC_TRIAL) break;

			if(is_page_protnone((unsigned long)object)){
				bokasan_kmalloc(object, 0);
			}
			else{
				break;
			}
		}

		return object;
	}
	else {
		size_t kasan_size;
		int index;

		if(!size) return ZERO_SIZE_PTR;

		kasan_size = get_kasan_size(size);

		index = kmalloc_index_(kasan_size);

		if(!index) return NULL;

		if(index >= 14)
			object = real_kmem_cache_alloc_trace(cachep, flags, size);
		else
			object = real_kmem_cache_alloc_trace(kmalloc_caches[index], flags, kasan_size);

		if(ZERO_OR_NULL_PTR(object)) return object;

		make_4k_page(object);

		bokasan_kmalloc(object, size);

		return object;
	}
}

static asmlinkage void* fh__kmalloc(size_t size, gfp_t flags){
	void* object = NULL;
	int i = 0;

	if(!is_current_pid_present() || irq_count() || size > KMALLOC_MAX_CACHE_SIZE){
		for(i = 0; i <= MAX_ALLOC_TRIAL; i++){
			object = real__kmalloc(size, flags);

			if(ZERO_OR_NULL_PTR(object)) return object;

			if(i == MAX_ALLOC_TRIAL) break;

			if(is_page_protnone((unsigned long)object)){
				bokasan_kmalloc(object, 0);
			}
			else{
				break;
			}
		}

		return object;
	}
	else{
		size_t kasan_size;

		if(!size) return ZERO_SIZE_PTR;

		kasan_size = get_kasan_size(size);

		object = real__kmalloc(kasan_size, flags);

		if(ZERO_OR_NULL_PTR(object)) return object;

		make_4k_page(object);

		bokasan_kmalloc(object, size);

		return object;
	}
}

static asmlinkage void* fh_kmem_cache_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid){
	void* object = NULL, *rz_obj = NULL;
	int i = 0;
	size_t size = 0;

	if(!is_current_pid_present() || irq_count() || size > KASAN_MAX_OBJECT_SIZE){
		for(i = 0; i <= MAX_ALLOC_TRIAL; i++){
			object = real_kmem_cache_alloc_node(cachep, flags, nodeid);

			if(ZERO_OR_NULL_PTR(object)) return object;

			if(i == MAX_ALLOC_TRIAL) break;

			if(is_page_protnone((unsigned long)object)){
				bokasan_kmalloc(object, 0);
			}
			else{
				break;
			}
		}

		return object;
	} else {
		void * temp_obj[MAX_ALLOC_TRIAL] = {NULL,};
		int j = 0;

		size = cachep->object_size;

		object = real_kmem_cache_alloc_node(cachep, flags, nodeid);

		if(ZERO_OR_NULL_PTR(object)) return object;

		for(i = 0; i < MAX_ALLOC_TRIAL; i++){
			rz_obj = real_kmem_cache_alloc_node(cachep, flags, nodeid);

			if(rz_obj == object + cachep->size){
				make_4k_page(object);
				make_4k_page(rz_obj);

				bokasan_kmalloc(object, size);
				bokasan_kmalloc(rz_obj, 0);

				for(j = 0; j < i; j++)
					real_kmem_cache_free(cachep, temp_obj[j]);

				break;
			}else{
				temp_obj[i] = object;
				object = rz_obj;
			}
		}

		return object;
	}
}

static asmlinkage void* fh_kmem_cache_alloc_node_trace(struct kmem_cache *cachep, gfp_t flags, int nodeid, 
												size_t size){
	void* object = NULL;
	int i = 0;

	if(!is_current_pid_present() || irq_count() || size > KASAN_MAX_OBJECT_SIZE){
		for(i = 0; i <= MAX_ALLOC_TRIAL; i++){
			object = real_kmem_cache_alloc_node_trace(cachep, flags, nodeid, size);

			if(ZERO_OR_NULL_PTR(object)) return object;

			if(i == MAX_ALLOC_TRIAL) break;

			if(is_page_protnone((unsigned long)object)){
				bokasan_kmalloc(object, 0);
			}
			else{
				break;
			}
		}

		return object;
	}
	else {
		size_t kasan_size;
		int index;

		if(!size) return ZERO_SIZE_PTR;

		kasan_size = get_kasan_size(size);

		index = kmalloc_index_(kasan_size);

		if(!index) return NULL;

		if(index >= 14)
			object = real_kmem_cache_alloc_node_trace(cachep, flags, nodeid, size);
		else
			object = real_kmem_cache_alloc_node_trace(kmalloc_caches[index], flags, nodeid, size);

		if(ZERO_OR_NULL_PTR(object)) return object;

		make_4k_page(object);

		bokasan_kmalloc(object, size);

		return object;
	}
}

static asmlinkage void* fh__kmalloc_node(size_t size, gfp_t flags, int nodeid){
	void* object = NULL;
	int i = 0;

	if(!is_current_pid_present() || irq_count() || size > KASAN_MAX_OBJECT_SIZE){
		for(i = 0; i <= MAX_ALLOC_TRIAL; i++){
			object = real__kmalloc_node(size, flags, nodeid);

			if(ZERO_OR_NULL_PTR(object)) return object;

			if(i == MAX_ALLOC_TRIAL) break;

			if(is_page_protnone((unsigned long)object)){
				bokasan_kmalloc(object, 0);
			}
			else{
				break;
			}
		}

		return object;
	}
	else{
		size_t kasan_size;

		if(!size) return ZERO_SIZE_PTR;

		kasan_size = get_kasan_size(size);
		object = real__kmalloc_node(kasan_size, flags, nodeid);

		if(ZERO_OR_NULL_PTR(object)) return object;

		make_4k_page(object);

		bokasan_kmalloc(object, size);

		return object;
	}
}

static asmlinkage void* fh_kmalloc_order(size_t size, gfp_t flags, unsigned int order){
	void* object = NULL;

	if(!is_current_pid_present() || irq_count()){
		object = real_kmalloc_order(size, flags, order);

		if(ZERO_OR_NULL_PTR(object)) return object;

		if(is_page_protnone((unsigned long)object)){
			clear_kasan_alloc_shadow((unsigned long)object);
		}

		return object;
	}
	else{
		size_t kasan_size;

		if(!size) return ZERO_SIZE_PTR;

		kasan_size = get_kasan_size(size);
		object = real_kmalloc_order(size, flags, order);

		if(ZERO_OR_NULL_PTR(object)) return object;

		clear_kasan_alloc_shadow((unsigned long)object);

		bokasan_kmalloc_large(object, size, flags);

		return object;
	}
}

static asmlinkage void* fh_kmalloc_large_node(size_t size, gfp_t flags, int node){
	void* object = NULL;

	if(!is_current_pid_present() || irq_count()){
		object = real_kmalloc_large_node(size, flags, node);

		if(ZERO_OR_NULL_PTR(object)) return object;

		if(is_page_protnone((unsigned long)object)){
			clear_kasan_alloc_shadow((unsigned long)object);
		}

		return object;
	}
	else{
		size_t kasan_size;

		if(!size) return ZERO_SIZE_PTR;

		kasan_size = get_kasan_size(size);
		object = real_kmalloc_large_node(size, flags, node);

		if(ZERO_OR_NULL_PTR(object)) return object;

		make_4k_page(object);

		bokasan_kmalloc_large(object, size, flags);

		return object;
	}
}

static asmlinkage void* fh___kmalloc_track_caller(size_t size, gfp_t gfpflags, unsigned long caller){
	void* object = NULL;

	if(!is_current_pid_present() || irq_count() || size > KMALLOC_MAX_CACHE_SIZE){
		object = real___kmalloc_track_caller(size, gfpflags, caller);

		return object;
	}
	else{
		ssize_t kasan_size;

		if(!size) return ZERO_SIZE_PTR;

		kasan_size = get_kasan_size(size);
		object = real___kmalloc_track_caller(kasan_size, gfpflags, caller);

		if(ZERO_OR_NULL_PTR(object)) return object;

		make_4k_page(object);

		bokasan_kmalloc(object, size);

		return object;
	}
}

static asmlinkage void* fh___kmalloc_node_track_caller(size_t size, gfp_t gfpflags, int node, unsigned long caller){
	void* object = NULL;

	if(!is_current_pid_present() || irq_count() || size > KMALLOC_MAX_CACHE_SIZE){
		object = real___kmalloc_node_track_caller(size, gfpflags, node, caller);

		return object;
	}
	else{
		int kasan_size = get_kasan_size(size);
		object = real___kmalloc_node_track_caller(kasan_size, gfpflags, node, caller);

		if(ZERO_OR_NULL_PTR(object)) return object;

		make_4k_page(object);

		bokasan_kmalloc(object, size);

		return object;
	}
}

// Deallocation functions
static asmlinkage void fh_kzfree(void *objp){
	struct page *page;

	if(objp == NULL) return;

	if(is_shadow_page_exist((unsigned long)objp) && is_bokasan_allocated((unsigned long)objp)){
		size_t size = ksize_(objp);

		page = virt_to_head_page(objp);

		if (unlikely(!PageSlab(page))) {
			BUG_ON(!PageCompound(page));
			return;
		}

		bokasan_kfree_poison(page->slab_cache, objp, size);

		return;
	}

	real_kzfree((void *)objp);
}

static asmlinkage void fh_kfree(void *objp){
	struct page *page;

	if(objp == NULL) return;

	if(is_shadow_page_exist((unsigned long)objp) && is_bokasan_allocated((unsigned long)objp)){
		size_t size = ksize_(objp);

		page = virt_to_head_page(objp);

		if (unlikely(!PageSlab(page))) {
			BUG_ON(!PageCompound(page));
			return;
		}

		bokasan_kfree_poison(page->slab_cache, objp, size);

		return;
	}

	real_kfree(objp);
}

static asmlinkage void fh_kmem_cache_free(struct kmem_cache *cachep, void *objp){
	if(objp == NULL) return;

	if(is_shadow_page_exist((unsigned long)objp) && is_bokasan_allocated((unsigned long)objp)){
		size_t size = ksize_(objp);

		bokasan_kfree_poison(cachep, objp, size);
	}
	else {
		real_kmem_cache_free(cachep, objp);
	}
}

static asmlinkage void fh_prep_compound_page(struct page *page, unsigned int order){
	bokasan_alloc_pages_(page, order);

	real_prep_compound_page(page, order);
}

// Debug handler
static asmlinkage void fh_do_debug(struct pt_regs *regs, unsigned long error_code){
	unsigned long vaddr = g_vaddr;
	unsigned long dr6;

	get_debugreg(dr6, 6);

	if(dr6 & DR_STEP){
		set_debugreg(0, 6);

		/*
		 * The SDM says "The processor clears the BTF flag when it
		 * generates a debug exception."  Clear TIF_BLOCKSTEP to keep
		 * TIF_BLOCKSTEP in sync with the hardware BTF flag.
		 */

		regs->flags &= ~X86_EFLAGS_TF;

		// Mark page not present
		clear_present_bit(vaddr);
	}
	else{
		real_do_debug(regs, error_code);
	}
}

// Page fault handler
static asmlinkage long fh_do_page_fault(struct pt_regs *regs,
		unsigned long error_code, unsigned long address)
{
	long ret = 0;
	unsigned long vaddr = address;

	// Filter out irrelevant memory access
	if(is_page_protnone(vaddr)){
		// Mark page present
		set_present_bit(vaddr);

		// Check address validity
		if(is_shadow_page_exist(vaddr))
			check_poison(vaddr, regs->ip);

		g_vaddr = vaddr;

		// Single-step
		regs->flags |=  X86_EFLAGS_TF;

		return ret;
	}

	if(is_current_pid_present()){
		int pid = task_pid_nr(current);

		remove_pid(pid);
		ret = real_do_page_fault(regs, error_code, address);
		add_pid(pid);
	} else{
		ret = real_do_page_fault(regs, error_code, address);
	}

	return ret;
}

// Follow child process
static asmlinkage long fh__do_fork(unsigned long clone_flags, unsigned long stack_start,
	unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr, unsigned long tls)
{
	int pid = task_pid_nr(current);
	long result;

	if(is_current_pid_present()){
		remove_pid(pid);
		result = real__do_fork(clone_flags, stack_start, stack_size, parent_tidptr, child_tidptr, tls);
		add_pid(pid);

		if(result != 0)
			add_pid(result);
	} else{
		result = real__do_fork(clone_flags, stack_start, stack_size, parent_tidptr, child_tidptr, tls);
	}

	return result;
}

static asmlinkage size_t fh_ksize(void* object)
{
	if(unlikely(ZERO_OR_NULL_PTR(object))) return 0;

	clear_kasan_alloc_shadow((unsigned long)object);

	return real_ksize(object);
}

/*
static asmlinkage long (*real_do_mount)(const char *dev_name, const char __user *dir_name,
		const char *type_page, unsigned long flags, void *data_page);

static asmlinkage long fh_do_mount(const char *dev_name, const char __user *dir_name,
		const char *type_page, unsigned long flags, void *data_page)
{
	// pr_crit("do_mount dev_name %s, dir_name %s pid %d", dev_name, dir_name, task_pid_nr(current));
	struct timespec64 start, finish;
	long result, delta;

	pr_crit("do_mount pid: %d", task_pid_nr(current));

	add_pid((int)task_pid_nr(current));

	ktime_get_real_ts64(&start);

	result = real_do_mount(dev_name, dir_name, type_page, flags, data_page);

	ktime_get_real_ts64(&finish);

	delta = (finish.tv_sec - start.tv_sec) * 1000000000 + (finish.tv_nsec - start.tv_nsec);

	printk("[do_mount] time: %ld\n", delta);

	return result;
}
*/

/*
 * x86_64 kernels have a special naming convention for syscall entry points in newer kernels.
 * That's what you end up with if an architecture has 3 (three) ABIs for system calls.
 */
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original)	\
	{					\
		.name = SYSCALL_NAME(_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}

// Functions to hook
static struct ftrace_hook bokasan_hooks[] = {
	HOOK("kmem_cache_alloc", fh_kmem_cache_alloc, &real_kmem_cache_alloc),
	HOOK("kmem_cache_alloc_node", fh_kmem_cache_alloc_node, &real_kmem_cache_alloc_node),

	HOOK("kmem_cache_alloc_trace", fh_kmem_cache_alloc_trace, &real_kmem_cache_alloc_trace),
	HOOK("kmem_cache_alloc_node_trace", fh_kmem_cache_alloc_node_trace, &real_kmem_cache_alloc_node_trace),

	HOOK("__kmalloc", fh__kmalloc, &real__kmalloc),
	HOOK("__kmalloc_node", fh__kmalloc_node, &real__kmalloc_node),

	HOOK("kmalloc_order", fh_kmalloc_order, &real_kmalloc_order),
	HOOK("kmalloc_large_node", fh_kmalloc_large_node, &real_kmalloc_large_node),

	HOOK("__kmalloc_track_caller", fh___kmalloc_track_caller, &real___kmalloc_track_caller),
	HOOK("__kmalloc_node_track_caller", fh___kmalloc_node_track_caller, &real___kmalloc_node_track_caller),

	HOOK("kfree", fh_kfree, &real_kfree),
	HOOK("kzfree", fh_kzfree, &real_kzfree),
	HOOK("kmem_cache_free", fh_kmem_cache_free, &real_kmem_cache_free),

	HOOK("__do_page_fault", fh_do_page_fault, &real_do_page_fault),
	HOOK("do_debug", fh_do_debug, &real_do_debug),

	HOOK("_do_fork", fh__do_fork, &real__do_fork),
	HOOK("ksize", fh_ksize, &real_ksize),

	HOOK("prep_compound_page", fh_prep_compound_page, &real_prep_compound_page)

	// HOOK("do_mount", fh_do_mount, &real_do_mount),
};

static void bokasan_chardev_init(){
	int res; 
	dev_t dev = MKDEV(major, 0);

	res = alloc_chrdev_region(&dev, MINOR_BASE, MINOR_NUM, DEVICE_NAME);
	major = MAJOR(dev);
	dev = MKDEV(major, MINOR_BASE);

	if(res < 0)
		pr_alert("bokasan_chardev_init failed. unable to get major %d\n", major);

	bokasan_setup_cdev(0, &bokasan_fops);
}

static int fh_init(void)
{
	int err;

	bokasan_chardev_init();
	init_kasan();

	err = fh_install_hooks(bokasan_hooks, ARRAY_SIZE(bokasan_hooks));

	if (err){
		pr_crit("fh_install_hooks failed. err: 0x%x", err);
		return err;
	}
	
	pr_info("BoKASAN Loaded\n");
	
	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	dev_t dev = MKDEV(major, MINOR_BASE);

	fh_remove_hooks(bokasan_hooks, ARRAY_SIZE(bokasan_hooks));
	device_destroy(bokasan_class, MKDEV(major, 0));
	class_destroy(bokasan_class);
	cdev_del(&bokasan_devs);
	unregister_chrdev(dev, DEVICE_NAME);

	pr_info("BoKASAN Unloaded\n");
}
module_exit(fh_exit);
