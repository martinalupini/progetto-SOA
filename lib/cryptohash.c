//#include <crypto/internal/skcipher.h> 
//#include <linux/crypto.h> 
#include <linux/module.h> 
//#include <linux/scatterlist.h> 

 
MODULE_DESCRIPTION("Symmetric key encryption and crypto hashing"); 
MODULE_LICENSE("GPL");


#define SYMMETRIC_KEY_LENGTH 32 
#define CIPHER_BLOCK_SIZE 16 
#define LIBNAME CryptoHash

 
/*
struct tcrypt_result { 

    struct completion completion; 
    int err; 

}; */

 

struct skcipher_def { 

    struct scatterlist sg; 
    struct crypto_skcipher *tfm; 
    struct skcipher_request *req; 
    //struct tcrypt_result result; 
    char *plaintxt; 
    char *ciphertext; 
    char *iv; 

};  

static void skcipher_finish(struct skcipher_def *sk) { 

    if (sk->tfm) crypto_free_skcipher(sk->tfm); 
    if (sk->req)  skcipher_request_free(sk->req); 
    if (sk->iv)  kfree(sk->iv); 
    if (sk->plaintxt) kfree(sk->plaintxt); 
    if (sk->ciphertext) kfree(sk->ciphertext); 

} 

 
/*
static int skcipher_result(struct skcipher_def *sk, int rc) { 

    switch (rc) { 

    case 0: 
	 break; 

    case -EINPROGRESS: 

    case -EBUSY: 
        rc = wait_for_completion_interruptible(&sk->result.completion); 
	if (!rc && !sk->result.err) { 
            reinit_completion(&sk->result.completion); 
            break; 
        } 

        printk("%s: Skcipher encrypt returned with %d result %d\n", LIBNAME, rc, sk->result.err);
        break; 

    default: 
        printk("%s: Skcipher encrypt returned with %d result %d\n", LIBNAME, rc, sk->result.err);
        break;
    } 

    init_completion(&sk->result.completion); 

    return rc; 

} 
*/
 
/*
static void skcipher_callback(struct crypto_async_request *req, int error){ 

    struct tcrypt_result *result = req->data; 

    if (error == -EINPROGRESS)  return; 

    result->err = error; 

    complete(&result->completion); 

    printk("%s: Encryption finished successfully\n", LIBNAME); 
    
    skcipher_finish(&sk);

} */

 

char *encrypt(char *plaintext, char *key, char *iv){ 

    struct skcipher_def sk; 
    char ciphertext[SYMMETRIC_KEY_LENGTH]; 
    

    if (!sk->tfm) { 

        sk->tfm = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0); 
        if (IS_ERR(sk->tfm)) { 
            printk("%s: Could not allocate skcipher handle\n",LIBNAME); 
            //return PTR_ERR(sk->tfm); 
            return NULL;
        } 
    } 

 

    if (!sk->req) { 
        sk->req = skcipher_request_alloc(sk->tfm, GFP_KERNEL); 
        if (!sk->req) { 
            printk("%s: Could not allocate skcipher request\n", LIBNAME); 
            return NULL; 
        } 
    } 

    skcipher_request_set_callback(sk->req, CRYPTO_TFM_REQ_MAY_BACKLOG, skcipher_callback, &sk->result); 
 

    /* AES 256 with given symmetric key */ 
    if (crypto_skcipher_setkey(sk->tfm, key, SYMMETRIC_KEY_LENGTH)) { 
       	printk("%s: Key could not be set\n", LIBNAME); 
        return NULL;

    } 

    //pr_info("Symmetric key: %s\n", key); 

    //pr_info("Plaintext: %s\n", plaintext); 

 

    if (!sk->iv) { 
        sk->iv = kmalloc(CIPHER_BLOCK_SIZE, GFP_KERNEL);
        if (!sk->iv) { 
            printk("%s: Could not allocate iv\n", LIBNAME); 
            return NULL; 
        } 

    } 
    sprintf((char *)sk->iv, "%s", iv);

 

    if (!sk->plaintxt) { 
        sk->plaintxt = kmalloc(CIPHER_BLOCK_SIZE, GFP_KERNEL); 

        if (!sk->plaintxt) { 
            printk("%s: Could not allocate plaintext\n", LIBNAME); 
            return NULL;
        } 

    } 

    sprintf((char *)sk->plaintxt, "%s", plaintext); 

    sg_init_one(&sk->sg, sk->plaintxt, CIPHER_BLOCK_SIZE); 

    skcipher_request_set_crypt(sk->req, &sk->sg, &sk->sg, CIPHER_BLOCK_SIZE, sk->iv); 

    //init_completion(&sk->result.completion); 


    /* encrypt data */ 
    ret = crypto_skcipher_encrypt(sk->req); 
    if(ret !=) return NULL;

    strncpy(ciphertext, sk->ciphertext, SYMMETRIC_KEY_LENGTH);
    //ret = skcipher_result(sk, ret); 
    
    skcipher_finish(&sk);

    printk("%s: Encryption request successful. Ciphertext is %s\n", LIBNAME, ciphertext); 

    return ciphertext; 

} 

 
 



 

