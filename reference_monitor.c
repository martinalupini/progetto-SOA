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

#define MODNAME "Reference monitor"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Martina Lupini");
MODULE_DESCRIPTION("This module implements a reference monitor that deny the opening in write mode of the specified files or directories");



#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define target_func "__x64_sys_filp_open" 
#else
#define target_func "sys_filp_open" 
#endif

enum status = {ON, OFF, REC-ON, REC-OFF};

//reference monitor parametres

char pass = "prova" //TO DO: SALVARE CIFRATA
enum status monitor_mode = ON;

static struct jprobe jp = {
	.entry			= filp_open_wrapper,
	.kp = {
		.symbol_name	= target_func,
	},
};

char *black_list[] = {NULL}; //the list of files not to open in write mode


extern struct file *filp_open_wrapper(const char *, int, umode_t){
	
	printk("%s: filp_open intercepted", MODNAME);	

}

int init_module(void) {

	int ret;

	printk("%s: initializing\n",MODNAME);

	ret = register_kprobe(&kp);
        if (ret < 0) {
                printk("%s: jprobe registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }

	ret = 0;

	return ret;
}

