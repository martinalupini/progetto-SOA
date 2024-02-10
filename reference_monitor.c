#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <linux/syscalls.h>
#include "lib/include/scth.h"

#define MODNAME "Reference monitor"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Martina Lupini");
MODULE_DESCRIPTION("This module implements a reference monitor that deny the opening in write mode of the specified files or directories");


//reference monitor//////////////////////////////////////////

typedef struct ref_monitor {
	char *pass;
	char *monitor_mode;
	char **file_protected;
	char **dir_protected;
	spinlock_t lock;
	
} monitor_t;

monitor_t monitor;


//system calls////////////////////////////////////////////////
unsigned long the_syscall_table = 0x0;
int entry1=0;
int entry2=0;
int entry3=0;
int entry4=0;

module_param(the_syscall_table, ulong, 0660);
module_param(entry1, int, 0660);
module_param(entry2, int, 0660);
module_param(entry3, int, 0660);
module_param(entry4, int, 0660);

unsigned long the_ni_syscall;

unsigned long new_sys_call_array[4];
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};
#define AUDIT if(1)




__SYSCALL_DEFINEx(1, _start_monitor, char *, pass){

	printk("%s: called sys_start_monitor", MODNAME);
	
	/*
	
	spin_lock(&(monitor.lock));
	
	
	
	spin_unlock(&(monitor.lock));*/
	return 0;
}

__SYSCALL_DEFINEx(1, _stop_monitor, char *, pass){

	printk("%s: called sys_stop_monitor", MODNAME);
	return 0;
}

__SYSCALL_DEFINEx(2, _monitor_recon, char *, pass, const char __user *, path){
	
	printk("%s: called sys_monitor_recon", MODNAME);
	return 0;
}

__SYSCALL_DEFINEx(2, _monitor_recoff, char *, pass, const char __user *, path){
	
	printk("%s: called sys_monitor_recoff", MODNAME);
	return 0;
}






long sys_start_monitor = (unsigned long) __x64_sys_start_monitor; 
long sys_stop_monitor = (unsigned long) __x64_sys_stop_monitor; 
long sys_monitor_recon = (unsigned long) __x64_sys_monitor_recon; 
long sys_monitor_recoff = (unsigned long) __x64_sys_monitor_recoff; 
//pre-handlers////////////////////////////////////////////////
static int mkdir_wrapper(struct kprobe *ri, struct pt_regs *regs){
	
	printk("%s: mkdir intercepted.", MODNAME);	
	
	return 0;

}

static int rmdir_wrapper(struct kprobe *ri, struct pt_regs *regs){
	
	printk("%s: rmdir intercepted.", MODNAME);	
	
	return 0;

}


static int open_wrapper(struct kprobe *ri, struct pt_regs *regs){
	
	printk("%s: open intercepted.", MODNAME);	
	
	return 0;

}

static int link_wrapper(struct kprobe *ri, struct pt_regs *regs){
	
	printk("%s: link intercepted.", MODNAME);	
	
	return 0;

}


static int unlink_wrapper(struct kprobe *ri, struct pt_regs *regs){
	
	printk("%s: unlink intercepted.", MODNAME);	
	
	return 0;

}



//kprobes////////////////////////////////////////////////////
static struct kprobe kp_mkdir = {
        .symbol_name =  "do_mkdirat",
        .pre_handler = mkdir_wrapper,
};

static struct kprobe kp_rmdir = {
        .symbol_name =  "do_rmdirat",
        .pre_handler = rmdir_wrapper,
};

static struct kprobe kp_open = {
        .symbol_name =  "do_filp_open",
        .pre_handler = open_wrapper,
};


static struct kprobe kp_unlink = {
        .symbol_name =  "do_unlinkat",
        .pre_handler = unlink_wrapper,
};

static struct kprobe kp_link = {
        .symbol_name =  "do_linkat",
        .pre_handler = link_wrapper,
};
//initialization module//////////////////////////////////////
int init_module(void) {
	int i;
	int ret;
	
	printk("%s: initializing\n",MODNAME);
	
	monitor.pass = "prova";
	monitor.monitor_mode = "ON";
	char *file[]={NULL};
	char *dir[]= {NULL};
	monitor.file_protected = file;
	monitor.dir_protected = dir;
	spin_lock_init(&(monitor.lock));
	
	
	//installing system calls
	if (the_syscall_table == 0x0){
	   printk("%s: cannot manage sys_call_table address set to 0x0\n",MODNAME);
	   return -1;
	}


	printk("%s: received sys_call_table address %px\n",MODNAME,(void*)the_syscall_table);
	
	new_sys_call_array[0] = (unsigned long)sys_start_monitor;
	new_sys_call_array[1] = (unsigned long)sys_stop_monitor;
	new_sys_call_array[2] = (unsigned long)sys_monitor_recon;
	new_sys_call_array[3] = (unsigned long)sys_monitor_recoff;
	

        ret = get_entries(restore,HACKED_ENTRIES,(unsigned long*)the_syscall_table,&the_ni_syscall);

        if (ret != HACKED_ENTRIES){
                printk("%s: could not hack %d entries (just %d)\n",MODNAME,HACKED_ENTRIES,ret); 
                return -1;      
        }

	unprotect_memory();

        for(i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)the_syscall_table)[restore[i]] = (unsigned long)new_sys_call_array[i];
              
        }

	protect_memory();
	
	entry1 = restore[0];
	entry2 = restore[1];
	entry3 = restore[2];
	entry4 = restore[3];

        printk("%s: all new system-calls correctly installed on sys-call table\n",MODNAME);
	



	//registering kprobes
	ret = register_kprobe(&kp_mkdir);
        if (ret < 0) {
                printk("%s: kprobe mkdir registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }
        
        ret = register_kprobe(&kp_open);
        if (ret < 0) {
                printk("%s: kprobe open registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }
        
        ret = register_kprobe(&kp_link);
        if (ret < 0) {
                printk("%s: kprobe link registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }

	ret = register_kprobe(&kp_rmdir);
        if (ret < 0) {
                printk("%s: kprobe rmdir registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }
        
        ret = register_kprobe(&kp_unlink);
        if (ret < 0) {
                printk("%s: kprobe unlink registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }
	
	printk("%s: kprobes installed", MODNAME);

	ret = 0;
	return ret;
}


//cleanup module//////////////////////////////////////////////
void cleanup_module(void) {
 	int i;
        printk("%s: shutting down\n",MODNAME);
        
        //restoring syscall table
        unprotect_memory();
        for(i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
        }
	protect_memory();
        printk("%s: sys-call table restored to its original content\n",MODNAME);
        
        
        //unregistering kprobes
        unregister_kprobe(&kp_mkdir);
        unregister_kprobe(&kp_open);
        unregister_kprobe(&kp_rmdir);
        unregister_kprobe(&kp_link);
        unregister_kprobe(&kp_unlink);
        printk("%s: kprobes unregistered\n", MODNAME);

        
}

