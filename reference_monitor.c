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

enum {ON, OFF, RECON, RECOFF};


typedef struct ref_monitor {
	char *pass;
	int monitor_mode;
	char **path_protected;
	int last_path;
	spinlock_t lock;
	struct file *file;
	
} monitor_t;

monitor_t monitor;


//system calls////////////////////////////////////////////////
unsigned long the_syscall_table = 0x0;
int entry1=0;
int entry2=0;
int entry3=0;
int entry4=0;
int entry5=0;
int entry6=0;

module_param(the_syscall_table, ulong, 0660);
module_param(entry1, int, 0660);
module_param(entry2, int, 0660);
module_param(entry3, int, 0660);
module_param(entry4, int, 0660);
module_param(entry5, int, 0660);
module_param(entry6, int, 0660);

unsigned long the_ni_syscall;

unsigned long new_sys_call_array[6];
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};
#define AUDIT if(1)
#define MAXSIZE 32


struct open_flag {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};


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

__SYSCALL_DEFINEx(1, _monitor_recon, char *, pass){
	
	printk("%s: called sys_monitor_recon", MODNAME);
	return 0;
}

__SYSCALL_DEFINEx(1, _monitor_recoff, char *, pass, const char __user *, path){
	
	printk("%s: called sys_monitor_recoff", MODNAME);
	return 0;
}


__SYSCALL_DEFINEx(1, _add_path, const char __user *, path){
	
	printk("%s: called sys_add_path", MODNAME);
	return 0;
}


__SYSCALL_DEFINEx(1, _remove_path, const char __user *, path){
	
	printk("%s: called sys_remove_path", MODNAME);
	return 0;
}


long sys_start_monitor = (unsigned long) __x64_sys_start_monitor; 
long sys_stop_monitor = (unsigned long) __x64_sys_stop_monitor; 
long sys_monitor_recon = (unsigned long) __x64_sys_monitor_recon; 
long sys_monitor_recoff = (unsigned long) __x64_sys_monitor_recoff; 
long sys_add_path = (unsigned long) __x64_sys_add_path;
long sys_remove_path = (unsigned long) __x64_sys_remove_path;
//pre-handlers////////////////////////////////////////////////


int control_flag(int flag){
	int ret, ret1;
	
	ret = (flag & O_RDWR) ^ (O_RDWR);
	ret1 = (flag & O_WRONLY) ^ (O_WRONLY);

	return ret | ret1;
}


static int open_wrapper(struct kprobe *ri, struct pt_regs *regs){

	/*
	int i=-1;
	
	int dfd = (int)(regs->di); //arg0
	//char *path = ((struct filename *)(regs->si))->name; //arg1
	int flags = ((struct open_flag *)(regs->dx))->open_flag; //arg2
	char run[5]; 
	
	
	struct file *file = fget(dfd);
	char *path = ((file->f_path).dentry->d_name).name; 
	char *dir =((file->f_path).dentry->d_parent->d_name).name;
	
	//path = d_path(&file->f_path, tmp, PAGE_SIZE);
	
	strncpy(run, path, 4);
	run[4]='\0';
	
	
	if( strcmp(run, "/run") ==0 ){
		 return 0;
	}
	
	//checking if the file is protected 
	printk("%s: open intercepted: file is %s in dir %s and flags are %d",MODNAME, path, dir,  flags);
	
	
	for(i=0; monitor.file_protected[i] != NULL; i++){
		if(strcmp(monitor.file_protected[i], path) == 0 && control_flag(flags) == 0){
			printk("%s: current file cannot be opened in write mode: open rejected\n",MODNAME);
			goto reject;
		}
	}
		
	//checking if creating a file in a protected directory
	
	dir = find_dir(path);
	for(i=0; monitor.dir_protected[i] != NULL; i++){
		if(strcmp(monitor.dir_protected[i], dir) == 0 && is_creating(flags) == 0){
			printk("%s: current file cannot be created because directory %s cannot be written: create rejected\n",MODNAME, dir);
			goto reject;
		
		}
	}
	
	
	
	return 0;
	
reject:
	regs->di = (unsigned long)NULL;
	regs->si = (unsigned long)NULL;
	regs->dx = (unsigned long)NULL;
	
	*/
	
	return 0;

}



//kprobes////////////////////////////////////////////////////

static struct kprobe kp_open = {
        .symbol_name =  "do_filp_open",
        .pre_handler = open_wrapper,
};


//initialization module//////////////////////////////////////
int init_module(void) {
	int i;
	int ret;
	char *path[MAXSIZE];
	
	printk("%s: initializing\n",MODNAME);
	
	monitor.pass = "prova";
	monitor.monitor_mode = ON;
	path[0] = "/home/martina/Desktop/progetto-SOA/file";
	path[1] = NULL;
	monitor.path_protected = path;
	monitor.last_path = 2;
	spin_lock_init(&(monitor.lock));
	
	//opening file of custom filesystem//////////////////////////////////////
	
	monitor.file = filp_open("singlefile-FS/mount/the-file", O_RDWR, 0);
	printk("%s: opened file %s", MODNAME, monitor.file->f_path.dentry->d_iname);
	
	//installing system calls//////////////////////////////////////////////////
	if (the_syscall_table == 0x0){
	   printk("%s: cannot manage sys_call_table address set to 0x0\n",MODNAME);
	   return -1;
	}


	printk("%s: received sys_call_table address %px\n",MODNAME,(void*)the_syscall_table);
	
	new_sys_call_array[0] = (unsigned long)sys_start_monitor;
	new_sys_call_array[1] = (unsigned long)sys_stop_monitor;
	new_sys_call_array[2] = (unsigned long)sys_monitor_recon;
	new_sys_call_array[3] = (unsigned long)sys_monitor_recoff;
	new_sys_call_array[4] = (unsigned long)sys_add_path;
	new_sys_call_array[5] = (unsigned long)sys_remove_path;
	

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
	entry5 = restore[4];
	entry6 = restore[5];

        printk("%s: all new system-calls correctly installed on sys-call table\n",MODNAME);
	



	//registering kprobes//////////////////////////////////////////////////////////////
        ret = register_kprobe(&kp_open);
        if (ret < 0) {
                printk("%s: kprobe open registering failed, returned %d\n",MODNAME,ret);
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
        unregister_kprobe(&kp_open);
        
        printk("%s: kprobes unregistered\n", MODNAME);

        
}

