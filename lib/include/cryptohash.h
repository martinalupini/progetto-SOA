#ifndef _CRYPTOHASH_

#define _CRYPTOHASH_ 

char *encrypt(char *plaintext, size_t datasize);
int auth_pass(char *pass, char *real_pass);
char *sha256(char *text, size_t size);

#endif
