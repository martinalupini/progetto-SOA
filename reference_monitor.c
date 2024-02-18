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
#include <linux/namei.h>
#include <linux/random.h>
#include "lib/include/scth.h"
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/fs_struct.h>
#include <linux/mm_types.h>
#include "lib/include/cryptohash.h"

#define MODNAME "Reference monitor"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Martina Lupini");
MODULE_DESCRIPTION("This module implements a reference monitor that deny the opening in write mode of the specified files or directories");

//reference monitor//////////////////////////////////////////
#define MAXSIZE 32
#define PASS_LENGTH 32 


enum {ON, OFF, RECON, RECOFF};


typedef struct ref_monitor {
	char pass[32];
	int mode;
	char *path[MAXSIZE];
	int last_path;
	spinlock_t lock;
	struct file *file;
	
} monitor_t;

monitor_t monitor;

char *the_file;

//deferred work struct and function///////////////////////////

typedef struct _packed_work{
        pid_t tgid;
        pid_t pid;
        uid_t uid;
        uid_t euid;
        char comm_path[128];
        char comm[64];
        struct work_struct the_work;
} packed_work;


void register_access(unsigned long input){

	packed_work *data = (void*)container_of((void*)input,packed_work,the_work);
	struct file *file = NULL;
	struct file *exe = NULL;
	char *buf = vmalloc(204800); //allocating 2MB 
	char *str = kzalloc(1024, GFP_KERNEL);
	char *hash;
	loff_t pos = 0;
	int ret;
	
	if(buf == NULL || str == NULL) return;
	
	
	//printk("TGID: %d PID: %d UID: %d EUID: %d Program name: %s Path: %s\n", data->tgid, data->pid, data->uid, data->euid, data->comm, data->comm_path);
	
	//crypto hash file
	
	if(data->comm_path == NULL)  goto out;
	
	exe = filp_open(data->comm_path, O_RDONLY , 0);
    	if (IS_ERR(exe)) {
    		printk("%s Deferred Work: Impossible to open the executable file\n", MODNAME);
        	goto out;
    	}
    	
    	ret = kernel_read(exe, buf, 204800, &pos);
    	hash = sha256(buf);
    	sprintf(str, "TGID: %d PID: %d UID: %d EUID: %d Program name: %s Hash exe file content: %s\n", data->tgid, data->pid, data->uid, data->euid, data->comm, hash);
    	
	printk("%s Deferred Work: File written with %s, bytes hash are %d\n", MODNAME, str, strlen(hash));
	
	
    	//file = filp_open("/home/martina/Desktop/progetto-SOA/singlefile-FS/mount/the-file", O_WRONLY , 0);
    	file = filp_open(the_file, O_WRONLY , 0);
    	if (IS_ERR(file)) {
    		printk("%s Deferred Work: Impossible to open the file \"the-file\"\n", MODNAME);
        	goto out;
    	}
    	

    	ret = kernel_write(file, str, strlen(str), &pos);

out: 
	vfree(buf);
	kfree(str);
	return;
	
}

//pre-handlers////////////////////////////////////////////////
struct open_flags {
	void* buffer;
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};


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

/*
static int mkdir_wrapper(struct kprobe *ri, struct pt_regs *regs){
	
	printk("%s: mkdir intercepted.", MODNAME);	
	
	return 0;

}*/

char *full_path_user(int dfd, const __user char *user_path){
	struct path path_struct;
	char *tpath;
	char *path;
	int error = -EINVAL,flag=0;
	unsigned int lookup_flags = 0;

	tpath=kmalloc(1024,GFP_KERNEL);
	if (!(flag & AT_SYMLINK_NOFOLLOW))    lookup_flags |= LOOKUP_FOLLOW;
	error = user_path_at(dfd, user_path, lookup_flags, &path_struct);
	if(error){
		printk("%s: File %s does not exist. Error is %d\n", MODNAME, user_path, error);
		kfree(tpath);
		return NULL;
	}
	
	path = d_path(&path_struct, tpath, 1024);
	kfree(tpath);		
	return path;

}

char *full_path(struct path path_struct){
	char *tpath;
	char *path;
	
	tpath=kmalloc(1024,GFP_KERNEL);
	path = d_path(&path_struct, tpath, 1024);
	
	return path;
}

static int open_pre_handler(struct kprobe *ri, struct pt_regs *regs){
	
	int i=-1;
	packed_work *the_task;

	const char *path;
	char *exe_path;
	
	int dfd = (int)(regs->di); //arg0
	const __user char *user_path = ((struct filename *)(regs->si))->uptr; //arg1
	const char *real_path = ((struct filename *)(regs->si))->name;
	struct open_flags *op_flag = (struct open_flags *)(regs->dx); //arg2
	int flags = op_flag->open_flag;
	char *dir;

	
	char run[5]; 
	strncpy(run, real_path, 4);
	run[4]='\0';
	if( strcmp(run, "/run") ==0 ){
		 return 0;
	}
	

	//checking if file is open in write mode
	if(!(flags & O_RDWR) && !(flags & O_WRONLY) && !(flags & O_CREAT))  return 0;
	
	
	if(user_path == NULL){
		 path = real_path;
	}else{
		path = full_path_user(dfd, user_path);
		if(path == NULL) path = real_path;
	}
	
	printk("%s: open in write mode intercepted: file is %s\n",MODNAME, path);

	//if open in write mode checking if its protected
	for(i=0; i<monitor.last_path ; i++){
		if(strcmp(monitor.path[i], path) == 0){
			printk("%s: Current path cannot be opened in write mode. Open in read mode only.\n",MODNAME);
			goto reject;
		}
	}
	
	
	if(flags & O_CREAT){
		dir = find_dir(path);
	
	}
	return 0;
	
reject:
	
	//registering deferred work
	the_task = kzalloc(sizeof(packed_work),GFP_KERNEL);
	the_task->tgid = current->tgid;
	the_task->pid = current->pid;
	the_task->uid = current->cred->uid.val;
	the_task->euid = current->cred->euid.val;
	exe_path = full_path(current->mm->exe_file->f_path);
	strncpy(the_task->comm_path, exe_path, strlen(exe_path));
	strncpy(the_task->comm, current->comm, strlen(current->comm));

	
	__INIT_WORK(&(the_task->the_work),(void*)register_access, (unsigned long)(&(the_task->the_work)));

	schedule_work(&the_task->the_work);

	//the filp_open is executed but with flag 0_RDONLY. Any attempt to write will return an error.
	op_flag->open_flag = ((flags ^ O_WRONLY) ^ O_RDWR) | O_RDONLY;
	regs->dx = (unsigned long)op_flag;

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
int entry7=0;

module_param(the_syscall_table, ulong, 0660);
module_param(the_file, charp, 0660);
module_param(entry1, int, 0660);
module_param(entry2, int, 0660);
module_param(entry3, int, 0660);
module_param(entry4, int, 0660);
module_param(entry5, int, 0660);
module_param(entry6, int, 0660);
module_param(entry7, int, 0660);

unsigned long the_ni_syscall;

unsigned long new_sys_call_array[7];
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};
#define AUDIT if(1)
#define get_euid()  current->cred->euid.val


__SYSCALL_DEFINEx(1, _start_monitor, char __user *, pass_user){
	
	printk("%s: called sys_start_monitor\n", MODNAME);
	
	spin_lock(&(monitor.lock));
	
	if(auth_pass(pass_user, monitor.pass) != 0 || get_euid() != 0){
		spin_unlock(&(monitor.lock));
	 	return -1;
	 }
	
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
	
	printk("%s: Monitor is now ON\n", MODNAME);
	return 0;
}

__SYSCALL_DEFINEx(1, _stop_monitor, char __user *, pass_user){

	printk("%s: called sys_stop_monitor\n", MODNAME);
	
	spin_lock(&(monitor.lock));
	
	if(auth_pass(pass_user, monitor.pass) != 0 || get_euid() != 0){
		spin_unlock(&(monitor.lock));
	 	return -1;
	 }
	
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
	
	printk("%s: Monitor is now OFF\n", MODNAME);
	return 0;
}

__SYSCALL_DEFINEx(1, _monitor_recon, char __user *, pass_user){

	printk("%s: called sys_monitor_recon\n", MODNAME);
	
	spin_lock(&(monitor.lock));
	
	if(auth_pass(pass_user, monitor.pass) != 0 || get_euid() != 0){
		spin_unlock(&(monitor.lock));
	 	return -1;
	 }
	
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
	
	printk("%s: Monitor is now RECON\n", MODNAME);
	return 0;
}

__SYSCALL_DEFINEx(1, _monitor_recoff, char __user *, pass_user){

	
	printk("%s: called sys_monitor_recoff\n", MODNAME);
	
	spin_lock(&(monitor.lock));
	
	if(auth_pass(pass_user, monitor.pass) != 0 || get_euid() != 0){
		spin_unlock(&(monitor.lock));
	 	return -1;
	 }
	
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
	
	printk("%s: Monitor is now RECOFF\n", MODNAME);
	return 0;
}


__SYSCALL_DEFINEx(2, _add_path, char __user *, new_path, char __user *, pass_user){
	int i;
	char* file_path = full_path_user(-100, new_path);
	if(file_path == NULL) return 0;
	
	printk("%s: called sys_add_path\n", MODNAME);
	
	
	spin_lock(&(monitor.lock)); //to avoid reconficuring mode while adding path
	
	if(auth_pass(pass_user, monitor.pass) != 0 || get_euid() != 0){
		spin_unlock(&(monitor.lock));
	 	return -1;
	 }
	
	//check if currently in RECON or RECOFF
	if(monitor.mode == OFF || monitor.mode == ON){
		spin_unlock(&(monitor.lock));
		return -1;
	}
	
	//check if file is the-file
	if(file_path != NULL && strstr(file_path, "/singlefile-FS/mount/the-file") != NULL ){
		printk("%s: Cannot deny writes on the-file. file_path is %s \n", MODNAME, file_path);
		spin_unlock(&(monitor.lock));
		return -1;
	}
	 
	
	//check if blacklist full
	if(monitor.last_path == MAXSIZE-1){
		printk("%s: Maximum number of path already present\n", MODNAME);
		spin_unlock(&(monitor.lock));
		return -1;
	}
	
	//check if path already present
	for( i=0; i<monitor.last_path; i++){
		//printk("path at %d is %s\n", i, monitor.path[i]);
		if( strcmp(monitor.path[i], file_path) == 0 ){
			printk("%s: Path already blacklisted\n", MODNAME);
			spin_unlock(&(monitor.lock));
			return 0;
		}
	} 
	
	monitor.path[monitor.last_path]= file_path;
	monitor.last_path++;
	spin_unlock(&(monitor.lock));
	printk("%s: Path added successfully\n", MODNAME);
	return 0;
}


__SYSCALL_DEFINEx(2, _remove_path, const char __user *, old_path, char __user *, pass_user){
	int i, j, ret;
	int len = strlen(old_path)+1;
	char* file_path = (char*)kmalloc(len, GFP_KERNEL);
	ret = copy_from_user(file_path, old_path, len);
	
	printk("%s: called sys_remove_path\n", MODNAME);
	
	spin_lock(&(monitor.lock));
	
	if(auth_pass(pass_user, monitor.pass) != 0 || get_euid() != 0){
		spin_unlock(&(monitor.lock));
	 	return -1;
	 }
	
	//check if currently in RECON or RECOFF
	if(monitor.mode == OFF || monitor.mode == ON){
		spin_unlock(&(monitor.lock));
		return -1;
	}
	
	//check if path is present in blacklist
	for( i=0; i<monitor.last_path; i++){
		//printk("path at %d is %s\n", i, monitor.path[i]);
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
			printk("%s: Path removed successfully\n", MODNAME);
			return 0;
		}
	} 
	
	spin_unlock(&(monitor.lock));
	printk("%s: Path not present in blacklist\n", MODNAME);
	return -1;
}


__SYSCALL_DEFINEx(2, _change_pass, char __user *, new_pass, char __user *, old_pass){
	size_t len;
	char *new;
	int ret;

	printk("%s: called sys_change_pass\n", MODNAME);
	
	len = strlen(new_pass);
	new = kmalloc(len+1, GFP_KERNEL);
	ret = copy_from_user(new, new_pass, len+1);
	
	if(strcmp(new, "") ==0){
		kfree(new);
	 	return -1;
	 }
	
	spin_lock(&(monitor.lock));
	
	if(auth_pass(old_pass, monitor.pass) != 0 || get_euid() != 0){
		spin_unlock(&(monitor.lock));
	 	return -1;
	 }
	
	new = encrypt(new, len);
	memcpy(monitor.pass, new, len+1);
	
	spin_unlock(&(monitor.lock));
	
	printk("%s: Password changed successfully\n", MODNAME);
	
	return 0;


}


long sys_start_monitor = (unsigned long) __x64_sys_start_monitor; 
long sys_stop_monitor = (unsigned long) __x64_sys_stop_monitor; 
long sys_monitor_recon = (unsigned long) __x64_sys_monitor_recon; 
long sys_monitor_recoff = (unsigned long) __x64_sys_monitor_recoff; 
long sys_add_path = (unsigned long) __x64_sys_add_path;
long sys_remove_path = (unsigned long) __x64_sys_remove_path;
long sys_change_pass = (unsigned long) __x64_sys_change_pass;


//initialization module//////////////////////////////////////
int init_module(void) {
	int i;
	int ret;
	
	printk("%s: initializing\n",MODNAME);
	
	
	monitor.pass[0]= 0x29;
	monitor.pass[1]= 0x04;
	monitor.pass[2]= 0x22;
	monitor.pass[3]= 0x2d;
	monitor.pass[4]= 0x17;
	monitor.pass[5]= 0x07;
	monitor.pass[6]= 0x0a;
	monitor.pass[7]= 0x15; 
	//monitor.pass[8] = 0x57;
	monitor.pass[8] = '\0';
	
	
	monitor.mode = ON;
	monitor.path[0] = "/home/martina/Desktop/progetto-SOA/user/file.txt";
	monitor.last_path = 1;
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
	new_sys_call_array[4] = (unsigned long)sys_add_path;
	new_sys_call_array[5] = (unsigned long)sys_remove_path;
	new_sys_call_array[6] = (unsigned long)sys_change_pass;
	

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
	entry7 = restore[6];

        printk("%s: all new system-calls correctly installed on sys-call table\n",MODNAME);
	



	//registering kprobes
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
       
        printk("%s: Module correctly removed\n", MODNAME);
            
}

