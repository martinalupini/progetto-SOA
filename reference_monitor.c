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
#define MAXSIZE 32


typedef struct ref_monitor {
	char *pass;
	int mode;
	char *path[MAXSIZE];
	int last_path;
	spinlock_t lock;
	struct file *file;
	
} monitor_t;

monitor_t monitor;

//pre-handlers////////////////////////////////////////////////


static int open_pre_handler(struct kprobe *ri, struct pt_regs *regs){
	
	int i=-1;
	
	int dfd = (int)(regs->di); //arg0
	char *path = ((struct filename *)(regs->si))->name; //arg1
	int flags = ((struct open_flag *)(regs->dx))->open_flag; //arg2
	
	
	char run[5]; 
	strncpy(run, path, 4);
	run[4]='\0';
	if( strcmp(run, "/run") ==0 ){
		 return 0;
	}
	
	
	//checking if the file is protected 
	printk("%s: open intercepted: file is %s and flags are %d\n",MODNAME, path, flags);
	
	
	for(i=0; i<monitor.last_path ; i++){
		if(strcmp(monitor.path[i], path) == 0 &&  !(flag & O_RDWR) && !(flag & O_WRONLY)){
			printk("%s: Current path cannot be opened in write mode: open rejected\n",MODNAME);
			goto reject;
		}
	}

	return 0;
	
reject:
	regs->di = (unsigned long)NULL;
	regs->si = (unsigned long)NULL;
	regs->dx = (unsigned long)NULL;
	
	return 0;

}



//kprobes////////////////////////////////////////////////////

static struct kprobe kp_open = {
        .symbol_name =  "do_filp_open",
        .pre_handler = open_pre_handler,
};


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
#define get_euid()  current->cred->euid.val


struct open_flag {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};



__SYSCALL_DEFINEx(1, _start_monitor, char __user *, pass_user){
	
	int ret;
	int len_pass = strlen(pass_user)+1;
	char* pass = (char*)kmalloc(len_pass, GFP_KERNEL);
	ret = copy_from_user(pass, pass_user, len_pass);
	
	printk("%s: called sys_start_monitor\n", MODNAME);
	
	if(strcmp(pass, monitor.pass) != 0 || get_euid() != 0) return -1;
	
	spin_lock(&(monitor.lock));
	
	switch(monitor.mode) {
	
		case ON:
			break;
		case OFF:
		 	enable_kprobe(&kp_open);
		 	break;
		 case RECON:
		 	break;
		 case RECOFF:
		 	enable_kprobe(&kp_open);
		 	break;
		 default:
		 	enable_kprobe(&kp_open);
		 	break;
	
	}
	
	monitor.mode = ON;
	spin_unlock(&(monitor.lock));
	kfree(pass);
	printk("%s: Monitor is now ON\n", MODNAME);
	return 0;
}

__SYSCALL_DEFINEx(1, _stop_monitor, char __user *, pass_user){
	
	int ret;
	int len_pass = strlen(pass_user)+1;
	char* pass = (char*)kmalloc(len_pass, GFP_KERNEL);
	ret = copy_from_user(pass, pass_user, len_pass);
	
	printk("%s: called sys_stop_monitor\n", MODNAME);
	
	if(strcmp(pass, monitor.pass) != 0 || get_euid() != 0) return -1;
	
	spin_lock(&(monitor.lock));
	
	switch(monitor.mode) {
	
		case ON:
			disable_kprobe(&kp_open);
			break;
		case OFF:
		 	break;
		 case RECON:
		 	disable_kprobe(&kp_open);
		 	break;
		 case RECOFF:
		 	break;
		 default:
		 	disable_kprobe(&kp_open);
		 	break;
	
	}
	
	monitor.mode = OFF;
	spin_unlock(&(monitor.lock));
	kfree(pass);
	printk("%s: Monitor is now OFF\n", MODNAME);
	return 0;
}

__SYSCALL_DEFINEx(1, _monitor_recon, char __user *, pass_user){

	int ret;
	int len_pass = strlen(pass_user)+1;
	char* pass = (char*)kmalloc(len_pass, GFP_KERNEL);
	ret = copy_from_user(pass, pass_user, len_pass);
	
	printk("%s: called sys_monitor_recon\n", MODNAME);
	
	if(strcmp(pass, monitor.pass) != 0 || get_euid() != 0) return -1;
	
	spin_lock(&(monitor.lock));
	
	switch(monitor.mode) {
	
		case ON:
			break;
		case OFF:
		 	enable_kprobe(&kp_open);
		 	break;
		 case RECON:
		 	break;
		 case RECOFF:
		 	enable_kprobe(&kp_open);
		 	break;
		 default:
		 	enable_kprobe(&kp_open);
		 	break;
	
	}
	
	monitor.mode = RECON;
	spin_unlock(&(monitor.lock));
	kfree(pass);
	printk("%s: Monitor is now RECON\n", MODNAME);
	return 0;
}

__SYSCALL_DEFINEx(1, _monitor_recoff, char *, pass_user){

	int ret;
	int len_pass = strlen(pass_user)+1;
	char* pass = (char*)kmalloc(len_pass, GFP_KERNEL);
	ret = copy_from_user(pass, pass_user, len_pass);
	
	printk("%s: called sys_monitor_recoff\n", MODNAME);
	
	if(strcmp(pass, monitor.pass) != 0 || get_euid() != 0) return -1;
	
	spin_lock(&(monitor.lock));
	
	switch(monitor.mode) {
	
		case ON:
			disable_kprobe(&kp_open);
			break;
		case OFF:
		 	break;
		 case RECON:
		 	disable_kprobe(&kp_open);
		 	break;
		 case RECOFF:
		 	break;
		 default:
		 	disable_kprobe(&kp_open);
		 	break;
	
	}
	
	monitor.mode = RECOFF;
	spin_unlock(&(monitor.lock));
	kfree(pass);
	printk("%s: Monitor is now RECOFF\n", MODNAME);
	return 0;
}


__SYSCALL_DEFINEx(2, _add_path, char __user *, new_path, char __user *, pass_user){
	int i;
	int ret;
	int len_pass;
	char *pass;
	int len = strlen(new_path)+1;
	char* file_path = (char*)kmalloc(len, GFP_KERNEL);
	ret = copy_from_user(file_path, new_path, len);
	
	len_pass = strlen(pass_user)+1;
	pass = (char*)kmalloc(len_pass, GFP_KERNEL);
	ret = copy_from_user(pass, pass_user, len_pass);
	
	
	printk("%s: called sys_add_path\n", MODNAME);
	
	if(strcmp(pass, monitor.pass) != 0 || get_euid() != 0) return -1;
	
	//check if currently in RECON or RECOFF
	spin_lock(&(monitor.lock)); //to avoid reconficuring mode while adding path
	if(monitor.mode == OFF || monitor.mode == ON){
		spin_unlock(&(monitor.lock));
		kfree(pass);
		return -1;
	}
	
	//check if blacklist full
	if(monitor.last_path == MAXSIZE-1){
		printk("%s: Maximum number of path already present\n", MODNAME);
		spin_unlock(&(monitor.lock));
		kfree(pass);
		return -1;
	}
	
	//check if path already present
	for( i=0; i<monitor.last_path; i++){
		printk("path at %d is %s\n", i, monitor.path[i]);
		if( strcmp(monitor.path[i], file_path) == 0 ){
			printk("%s: Path already blacklisted\n", MODNAME);
			spin_unlock(&(monitor.lock));
			kfree(pass);
			return 0;
		}
	} 
	
	monitor.path[monitor.last_path]= file_path;
	monitor.last_path++;
	spin_unlock(&(monitor.lock));
	kfree(pass);
	return 0;
}


__SYSCALL_DEFINEx(2, _remove_path, const char __user *, old_path, char __user *, pass_user){
	int i, j;
	int ret;
	int len_pass;
	char *pass;
	int len = strlen(old_path)+1;
	char* file_path = (char*)kmalloc(len, GFP_KERNEL);
	ret = copy_from_user(file_path, old_path, len);
	
	len_pass = strlen(pass_user)+1;
	pass = (char*)kmalloc(len_pass, GFP_KERNEL);
	ret = copy_from_user(pass, pass_user, len_pass);
	
	
	printk("%s: called sys_remove_path\n", MODNAME);
	
	if(strcmp(pass, monitor.pass) != 0 || get_euid() != 0) return -1;
	
	//check if currently in RECON or RECOFF
	spin_lock(&(monitor.lock));
	if(monitor.mode == OFF || monitor.mode == ON){
		spin_unlock(&(monitor.lock));
		kfree(pass);
		return -1;
	}
	
	//check if path is present in blacklist
	for( i=0; i<monitor.last_path; i++){
		printk("path at %d is %s\n", i, monitor.path[i]);
		if( strcmp(monitor.path[i], file_path) == 0 ){
			//removing path
			if((j==0 && monitor.last_path ==0) || j==MAXSIZE-1){
				monitor.path[j]= NULL;
			}else{
				for(j=i; j<monitor.last_path-1 ; j++){
					monitor.path[j] = monitor.path[j+1];
				}
			}
			monitor.last_path--;
			spin_unlock(&(monitor.lock));
			kfree(pass);
			return 0;
		}
	} 
	
	spin_unlock(&(monitor.lock));
	kfree(pass);
	printk("%s: Path not present in blacklist\n", MODNAME);
	return -1;
}


long sys_start_monitor = (unsigned long) __x64_sys_start_monitor; 
long sys_stop_monitor = (unsigned long) __x64_sys_stop_monitor; 
long sys_monitor_recon = (unsigned long) __x64_sys_monitor_recon; 
long sys_monitor_recoff = (unsigned long) __x64_sys_monitor_recoff; 
long sys_add_path = (unsigned long) __x64_sys_add_path;
long sys_remove_path = (unsigned long) __x64_sys_remove_path;


//initialization module//////////////////////////////////////
int init_module(void) {
	int i;
	int ret;
	//char *path[MAXSIZE];
	
	printk("%s: initializing\n",MODNAME);
	
	monitor.pass = "prova";
	monitor.mode = ON;
	//monitor.path[0] = "/home/martina/Desktop/progetto-SOA/file";
	monitor.last_path = 0;
	spin_lock_init(&(monitor.lock));
	
	//opening file of custom filesystem//////////////////////////////////////
	
	
	//monitor.file = filp_open("singlefile-FS/mount/the-file", O_RDWR, 0);
	//printk("%s: opened file %s", MODNAME, monitor.file->f_path.dentry->d_iname); 
	
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
	
	printk("%s: kprobes installed\n", MODNAME);

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

