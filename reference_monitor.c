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


int control_flag(int flag){
	int ret, ret1;
	
	ret = (flag & O_RDWR) ^ (O_RDWR);
	ret1 = (flag & O_WRONLY) ^ (O_WRONLY);

	return ret | ret1;
}


int is_creating(int flag){
	int ret = (flag & O_CREAT) ^ O_CREAT;
	return ret;
}

char *find_dir(char *path){

	int i= strlen(path)-1;
	char *new_string = kmalloc(strlen(path), GFP_KERNEL);
	
	while(i>=0){
		
		if(path[i] != '/'){ 
			new_string[i] = '\0'; 
		}
		else{
			new_string[i]='\0';
			i--;
		 	break;
		}
		i--;

	}
	
	while(i>=0){
		new_string[i] = path[i];
		i--;
	}
	
	return new_string;
}

static int mkdir_wrapper(struct kprobe *ri, struct pt_regs *regs){
	
	printk("%s: mkdir intercepted.", MODNAME);	
	
	return 0;

}

static int rmdir_wrapper(struct kprobe *ri, struct pt_regs *regs){
	
	printk("%s: rmdir intercepted.", MODNAME);	
	
	return 0;

}


static int open_wrapper(struct kprobe *ri, struct pt_regs *regs){
	int i=-1;
	char *dir;
	char *path = ((struct filename *)(regs->si))->name; //arg1
	int flags = ((struct open_flag *)(regs->dx))->open_flag; //arg2
	char run[5];
	
	strncpy(run, path, 4);
	run[5]='\0';
	
	if( strcmp(run, "/run") ==0 ) {
		printk("Equals");
		return 0;
	}
	
	//checking if the file is protected 
	printk("%s: open intercepted: file is %s and flags are %d",MODNAME, path, flags);
	
	/*
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
        .symbol_name =  "__x64_sys_mkdir",
        .pre_handler = mkdir_wrapper,
};

static struct kprobe kp_rmdir = {
        .symbol_name =  "__x64_sys_rmdir",
        .pre_handler = rmdir_wrapper,
};

static struct kprobe kp_open = {
        .symbol_name =  "do_filp_open",
        .pre_handler = open_wrapper,
};


static struct kprobe kp_unlink = {
        .symbol_name =  "__x64_sys_unlink",
        .pre_handler = unlink_wrapper,
};

static struct kprobe kp_link = {
        .symbol_name =  "__x64_sys_link",
        .pre_handler = link_wrapper,
};
//initialization module//////////////////////////////////////
int init_module(void) {
	int i;
	int ret;
	char *file[MAXSIZE];
	char *dir[MAXSIZE];
	
	printk("%s: initializing\n",MODNAME);
	
	monitor.pass = "prova";
	monitor.monitor_mode = "ON";
	file[0] = "/home/martina/Desktop/progetto-SOA/file";
	file[1] = NULL;
	dir[0]= NULL;
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

