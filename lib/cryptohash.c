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
#define HASHSIZE 32 //as written in the driver sha256 info (shown with cat /proc/crypto) 

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

	int ret;
	size_t len = strlen(pass);
	char *try = kmalloc(len+1, GFP_KERNEL);
	if(try ==NULL)  return -1;
	
	ret = copy_from_user(try, pass, len+1);
	
	try = encrypt(try, len);
	if(try == NULL)  return -1;
	
	if(strcmp(real_pass, try) == 0){
		kfree(try);
		return 0;
	}
	kfree(try);
	return -1;
}


char *sha256(char *text, size_t size){
	struct crypto_shash* algorithm;
    	struct shash_desc* desc;
    	int err;
    	char *digest = kmalloc(HASHSIZE+1, GFP_KERNEL);
    	if(digest == NULL)  return NULL;
    	
    	algorithm = crypto_alloc_shash("sha256", 0, 0);
    	if(IS_ERR(algorithm)) { 
    		printk("%s: Hashing algorithm not supported\n", LIBNAME);
    		return NULL;
	}
	
	desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(algorithm), GFP_KERNEL);
	if(!desc) { 
    		printk("%s: failed to allocate memory\n", LIBNAME);
    		return NULL;
	}
	desc->tfm = algorithm;
	
	// Initialize shash API
	err = crypto_shash_init(desc);
	if(err)  {
    		printk("%s: failed to initialize shash\n", LIBNAME);
    		goto out;
	}

	// Execute hash function
	err = crypto_shash_update(desc, text, size);
	if(err) {
    		printk("%s: failed to execute hashing function\n", LIBNAME);
    		goto out;
	}

	// Write the result to a new char buffer
	err = crypto_shash_final(desc, digest);
	if(err) {
    		printk("%s: Failed to complete hashing function\n", LIBNAME);
    		goto out;
	}

	// Finally, clean up resources
	crypto_free_shash(algorithm);
	kfree(desc);

	printk("%s: String successfully hashed\n", LIBNAME);

	return digest;

out: // Manage errors
	crypto_free_shash(algorithm);
	kfree(desc);
	return NULL;
}
