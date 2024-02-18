#ifndef _CRYPTOHASH_

#define _CRYPTOHASH_ 

char *encrypt(char *plaintext, size_t datasize);
int auth_pass(char __user *pass, char *real_pass);
char *sha256(char *text);

#endif
