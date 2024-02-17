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
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>

 
MODULE_DESCRIPTION("Symmetric key encryption and crypto hashing"); 
MODULE_LICENSE("GPL");

#define LIBNAME "CRYPTOHASH"

char *keystream = "JlCCpbgpW23hgxjHuPqb2e64g68OqCgx";

char *encrypt(char *plaintext, size_t datasize){ 

	int i;
	char *ciphertext;
    	//printk("%s: Encryption started\n", LIBNAME);
    
    	ciphertext = kmalloc(datasize, GFP_KERNEL);
    	if(ciphertext == NULL){
    		printk("%s: kmalloc cipertext failed\n", LIBNAME);
      		return NULL;
    	}
    
  	for(i=0; i<datasize; i++){

  	 	ciphertext[i] = plaintext[i] ^ keystream[i];
  	}
  	ciphertext[i]='\0';
  	 
  	return ciphertext;
   
   
} 

int auth_pass(char __user *pass, char *real_pass){

	int ret, i;
	size_t len = strlen(pass);
	char *try = kmalloc(len+1, GFP_KERNEL);
	ret = copy_from_user(try, pass, len+1);
	
	try = encrypt(try, len);
	
	for(i=0; i<len; i++){
		printk("pass %x try %x", real_pass[i], try[i]);
	}
	
	if(strcmp(real_pass, try) == 0){
		kfree(try);
		return 0;
	}
	kfree(try);
	return -1;
}

 
 



 

