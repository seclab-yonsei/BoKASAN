#ifndef __MY_KASAN__
#define __MY_KASAN__

#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/slab.h>

#define DEVICE_NAME "bokasan"
#define KASAN_MAJOR 123
#define KASAN_MAX	1

#define         IOCTL_MAGIC         'K'
#define         SET_PID            _IO(IOCTL_MAGIC, 0)
#define	 	REMOVE_PID	   _IO(IOCTL_MAGIC, 1)

typedef struct{
	pid_t pid; 
} __attribute__ ((packed)) pid_info;

static int bokasan_open(struct inode *, struct file *);
static int bokasan_release(struct inode *, struct file *);
static ssize_t bokasan_read(struct file *, char *, size_t, loff_t *);
static ssize_t bokasan_write(struct file *, const char *, size_t, loff_t *);
static long bokasan_ioctl(struct file *, unsigned int, unsigned long);
static void bokasan_chardev_init(void);

static struct file_operations bokasan_fops = {
	.owner 			= THIS_MODULE,
	.open			= bokasan_open,
	.release		= bokasan_release,
	.write			= bokasan_write,
	.read			= bokasan_read,	
	.unlocked_ioctl		= bokasan_ioctl,
};

static asmlinkage void fh_do_debug(struct pt_regs *regs, unsigned long error_code);
static asmlinkage long fh_do_page_fault(struct pt_regs *regs, unsigned long error_code, unsigned long address);

static asmlinkage void* fh___kmalloc_track_caller(size_t size, gfp_t gfpflags, unsigned long caller);

static asmlinkage void* (*real_kmem_cache_alloc)(struct kmem_cache *cachep, gfp_t flags);
static asmlinkage void* (*real_kmem_cache_alloc_node)(struct kmem_cache *cachep, gfp_t flags, int node);
static asmlinkage void* (*real_kmem_cache_alloc_trace)(struct kmem_cache *cachep, gfp_t flags, size_t size);
static asmlinkage void* (*real_kmem_cache_alloc_node_trace)(struct kmem_cache *cachep, gfp_t flags, int nodeid, size_t size);
static asmlinkage void* (*real_kmem_cache_alloc_node)(struct kmem_cache *cachep, gfp_t flags, int nodeid); 

static asmlinkage void* (*real__kmalloc)(size_t size, gfp_t flags);
static asmlinkage void* (*real__kmalloc_node)(size_t size, gfp_t flags, int nodeid);

static asmlinkage void* (*real_kmalloc_order)(size_t size, gfp_t flags, unsigned int order);
static asmlinkage void* (*real_kmalloc_large_node)(size_t size, gfp_t flags, int node);

static asmlinkage void* (*real___kmalloc_track_caller)(size_t size, gfp_t gfpflags, unsigned long caller);
static asmlinkage void* (*real___kmalloc_node_track_caller)(size_t size, gfp_t gfpflags, int node, unsigned long caller);

static asmlinkage void (*real_kzfree)(const void* objp);
static asmlinkage void (*real_kfree)(void* objp);
static asmlinkage void (*real_kmem_cache_free)(struct kmem_cache *cachep, void* objp);

static asmlinkage void (*real_prep_compound_page)(struct page *page, unsigned int order);

static asmlinkage long (*real__do_fork)(unsigned long clone_flags, unsigned long stack_start,
	unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr, unsigned long tls);

static asmlinkage long (*real_do_page_fault)(struct pt_regs *regs, unsigned long error_code, unsigned long address);
static asmlinkage void (*real_do_debug)(struct pt_regs *regs, unsigned long error_code);

static asmlinkage size_t (*real_ksize)(void* object);

#endif
