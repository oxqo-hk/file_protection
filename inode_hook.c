#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/namei.h>
#include <asm/string.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/fs.h>

#include <asm/cacheflush.h>

#define PROTECTED_FILE "/home/oxqo/rootkit/test/do_not_modify"
#define AUTHORIZED_EXECUTABLE "/home/oxqo/rootkit/test/i_can_modify"
#define MAX_LEN_ENTRY 256
#define MAX_PATH 256

MODULE_LICENSE ("GPL");

typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs *);

struct inode* protected_inode;
struct file_operations* original_op;
struct file_operations* new_op;
//global vars to save original function's address
//asmlinkage long (*original_sys_open) (const char __user * filename, int flags, int mode);


//write_cr0 denied in latest kernel
inline void write_cr0_custom(unsigned long cr0) {
    unsigned long __force_order;
    asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}


void enter_kernel_addr_space(mm_segment_t *oldfs){
    *oldfs = get_fs();
    set_fs(KERNEL_DS);
}

void exit_kernel_addr_space(mm_segment_t oldfs){
    set_fs(oldfs);
}


void disable_write_protection(void){
    //write_cr0(read_cr0() & (~0x10000));
    write_cr0_custom(read_cr0() & (~0x10000));
}

void enable_write_protection(void){
    //write_cr0(read_cr0() | 0x10000);
    write_cr0_custom(read_cr0() | 0x10000);
}

void hide_module(void){
    list_del(&THIS_MODULE->list);
}

char* get_current_task(void){
    struct mm_struct *mm;
    struct task_struct *cr_task;
    char *pathname,*p;
    //get current executable name
    cr_task = get_current();
    mm = cr_task->mm;
    if (mm) {
        down_read(&mm->mmap_sem);
        if (mm->exe_file) {
                    pathname = kzalloc(PATH_MAX, GFP_ATOMIC);
                    if (pathname) {
                          p = d_path(&mm->exe_file->f_path, pathname, PATH_MAX);
                    }
                }
        up_read(&mm->mmap_sem);
    }
    kfree(pathname);
    return p;
}


int is_from_authorized_task(void){
    char *p;
    int res;
    p = get_current_task();
    res = strncmp(p, AUTHORIZED_EXECUTABLE, strlen(p));
    printk(KERN_INFO"res: %d\n", res);
    //kfree(p);
    if(res == 0) return 1;
    else return 0;
}

struct inode* get_protected_inode(void){
	int error;
	struct inode *inode;
	struct path protected_path;
	mm_segment_t fs;
	enter_kernel_addr_space(&fs);
	error=kern_path(PROTECTED_FILE, LOOKUP_FOLLOW, &protected_path);
	exit_kernel_addr_space(fs);
	if(!error){
			inode=protected_path.dentry->d_inode;
			return inode;
	}
	printk(KERN_INFO"kern_path error %llx\n", protected_path);
	return NULL;
}

//ssize_t write_hook(struct file *A, const char __user *B, size_t C, loff_t *D){
ssize_t write_iter_hook(struct kiocb *X, struct iov_iter *Y){
	ssize_t ret;
	printk(KERN_INFO"write_iter hooked\n");
	
	printk("write_iter: %p\n", original_op->write_iter);
	if(original_op->write_iter == NULL)
		return -EINVAL;
	else if(is_from_authorized_task())
		return original_op->write_iter(X, Y);
	else
		return -EACCES;
}

int open_hook(struct inode* inode, struct file* filep){
    printk(KERN_INFO"open hooked\n");
    if(original_op->open == NULL)
        return -EINVAL; 
    else if (filep->f_mode & FMODE_WRITE){
        if (is_from_authorized_task())
            return original_op->open(inode, filep);
        else
            return -EACCES;
    }
    else
        return original_op->open(inode, filep);
}

struct file_operations* new_inode_operations(void){
	struct file_operations* ret = kmalloc(sizeof(struct file_operations), GFP_KERNEL);
	memcpy(ret, original_op, sizeof(struct file_operations));
	ret->write_iter = write_iter_hook;
    ret->open = open_hook;
	return ret;
}
 
static int __init mod_init (void){
    protected_inode = get_protected_inode();
    if (protected_inode == NULL){
    	printk(KERN_INFO"cannot get inode address\n may be protected file doesn't exist\n");
    	return -1;
    }
    original_op = protected_inode->i_fop;
    printk(KERN_INFO"protected_inode: %llx\n", protected_inode);
    printk(KERN_INFO"before: %llx\n", protected_inode->i_fop);
    printk(KERN_INFO"write: %llx\n", protected_inode->i_fop->write);
    //turn off write protection
    disable_write_protection();
    new_op = new_inode_operations();
    protected_inode->i_fop = new_op;
    
    printk(KERN_INFO"after: %llx\n", protected_inode->i_fop);
    //hide_module();
    //restore write protection
    enable_write_protection();
    //set_memory_ro(g_sys_call_table_p, 1);
                
    return 0;

}
    
static void mod_exit (void){
    disable_write_protection();
    //set_memory_rw(g_sys_call_table_p, 1);
    protected_inode->i_fop = original_op;
    kfree(new_op);
    enable_write_protection();
    //set_memory_ro(g_sys_call_table_p, 1);
}
    
module_init(mod_init);
module_exit(mod_exit);