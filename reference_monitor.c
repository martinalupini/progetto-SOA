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

#define MODNAME "Reference monitor filp_open"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Martina Lupini");
MODULE_DESCRIPTION("This module implements a reference monitor that deny the opening in write mode of the specified files or directories");



#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define target_func "__x64_sys_filp_open" 
#else
#define target_func "sys_filp_open" 
#endif


//reference monitor parametres

char *pass = "prova"; //TO DO: SALVARE CIFRATA
char *monitor_mode = "ON";
char *black_list[] = {NULL}; //the list of files not to open in write mode


static int filp_open_wrapper(struct kprobe *ri, struct pt_regs *regs){
	
	printk("%s: filp_open intercepted.", MODNAME);	
	
	return 0;

}

static struct kprobe kp = {
        .symbol_name =  target_func,
        .pre_handler = filp_open_wrapper,
};

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

