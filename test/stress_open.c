#include <stdio.h> 
#include <pthread.h> 
#include <string.h>
#include "syscallsCLI/lib/include/refmonitor.h"
 
#define NUM_THREADS 100


void *open_file(void *threadID) { 
    long tid = (long)threadID;
    FILE *file = fopen("file", "w"); 
    if (file == NULL) { 
        perror("Error in the opening of file"); 
        pthread_exit(NULL); 
    } 
 
    fclose(file); 
 
    pthread_exit(NULL);
} 


int main() { 
    pthread_t threads[NUM_THREADS]; 
    
    int i, ret; 
    for (i = 0; i < NUM_THREADS; i++) { 
        ret = pthread_create(&threads[i], NULL, open_file, (void *)&i); 
        if (ret) { 
            printf("Error: %s\n", strerror(ret));  
            return -1; 
        } 
    } 
 
    // Attesa della terminazione di tutti i thread 
    for (i = 0; i < NUM_THREADS; i++) { 
        ret = pthread_join(threads[i], NULL); 
        if (ret) { 
            printf("Error: %s\n", strerror(ret)); 
            return -1; 
        } 
    } 
 
    return 0;
 }

