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


#define SYMMETRIC_KEY_LENGTH 32 
#define CIPHER_BLOCK_SIZE 16 
#define LIBNAME "CRYPTOHASH"


typedef struct skcipher_def { 

    struct scatterlist sg; 
    struct crypto_skcipher *tfm; 
    struct skcipher_request *req; 
    //struct tcrypt_result result; 
    char *plaintxt; 
    //char *ciphertext; 
    char *iv; 

} skcipher;  



static void skcipher_finish(skcipher *sk) { 

    if (sk->tfm) crypto_free_skcipher(sk->tfm); 
    if (sk->req)  skcipher_request_free(sk->req); 
    //if (sk->iv)  kfree(sk->iv); 
    //if (sk->plaintxt) kfree(sk->plaintxt); 
    //if (sk->ciphertext) kfree(sk->ciphertext); 
    kfree(sk);
} 


char *encrypt(char *plaintext, char *key, char *iv, size_t datasize){ 

    printk("%s: Encryption started\n", LIBNAME);
    int ret;
    skcipher *sk; 
    
    char *ciphertext;
    ciphertext = kmalloc(datasize, GFP_KERNEL);
    if(ciphertext == NULL){
    	printk("%s: kmalloc cipertext failed\n", LIBNAME);
      	return NULL;
    }
    
    sk = kmalloc(sizeof(skcipher), GFP_KERNEL);
    if(sk == NULL){
    	printk("%s: kmalloc sk failed\n", LIBNAME);
       	return NULL;
    }
    
   
    if (!(sk->tfm)) { 
        sk->tfm = crypto_alloc_skcipher("ebc-aes-aesni", 0, 0); 
        if (IS_ERR(sk->tfm)) { 
            printk("%s: Could not allocate skcipher handle\n",LIBNAME); 
            //return PTR_ERR(sk->tfm); 
            goto out;
        } 
    } 

 

    if (!sk->req) { 
        sk->req = skcipher_request_alloc(sk->tfm, GFP_KERNEL); 
        if (!sk->req) { 
            printk("%s: Could not allocate skcipher request\n", LIBNAME); 
            goto out; 
        } 
    } 

    //skcipher_request_set_callback(sk->req, CRYPTO_TFM_REQ_MAY_BACKLOG, skcipher_callback, &sk->result); 
 

    /* AES 256 with given symmetric key */ 
    if (crypto_skcipher_setkey(sk->tfm, key, SYMMETRIC_KEY_LENGTH)) { 
       	printk("%s: Key could not be set\n", LIBNAME); 
       	goto out;

    } 

    //pr_info("Symmetric key: %s\n", key); 

    //pr_info("Plaintext: %s\n", plaintext); 

   /*
    if (!sk->iv) { 
        sk->iv = kmalloc(CIPHER_BLOCK_SIZE, GFP_KERNEL);
        if (!sk->iv) { 
            printk("%s: Could not allocate iv\n", LIBNAME); 
            goto out;
        } 

    } 
    sprintf((char *)sk->iv, "%s", iv);
	
 
    
    if (!sk->plaintxt) { 
        sk->plaintxt = kmalloc(datasize, GFP_KERNEL); 

        if (!sk->plaintxt) { 
            printk("%s: Could not allocate plaintext\n", LIBNAME); 
            goto out;
        } 

    } 

    sprintf((char *)sk->plaintxt, "%s", plaintext); */

    sg_init_one(&sk->sg, plaintext, datasize); 

    skcipher_request_set_crypt(sk->req, &sk->sg, &sk->sg, datasize, iv); 

    //init_completion(&sk->result.completion); 


    /* encrypt data */ 
    ret = crypto_skcipher_encrypt(sk->req); 
    if(ret != 0) goto out;

    
    sg_copy_to_buffer(&sk->sg, 1, ciphertext, datasize);
    //ret = skcipher_result(sk, ret); 
    
    skcipher_finish(sk);

    printk("%s: Encryption request successful. Ciphertext is %s\n", LIBNAME, ciphertext); 

    return ciphertext; 
    
out:
    kfree(sk);
    return NULL;

} 

 
 



 

