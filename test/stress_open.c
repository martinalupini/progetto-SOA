#include <stdio.h> 
#include <pthread.h> 
#include <string.h>
#include "../user/syscallsCLI/lib/include/refmonitor.h"
 
#define NUM_THREADS 100


void *open_file(void *threadID) { 
    long tid = (long)threadID;
    FILE *file = fopen("file", "w"); 
    if (file == NULL) { 
        perror("Error in the opening of file"); 
        pthread_exit(NULL); 
    } 
    
    printf("File successfully opened\n");
    fclose(file); 
 
    pthread_exit(NULL);
} 


int main(int argc, char *argv[]) { 
    pthread_t threads[NUM_THREADS]; 
    
    if (argc != 2) { 
        printf("Usage: ./stress_open <mode>\n\nmode is 'blocked' if you want to test on blacklisted file, 'normal' otherwise\n"); 
        return 1; 
    } 
    
    if(strcmp(argv[1], "blocked") == 0){
    	recon("changeme");
    	add_path("file", "changeme");
    }else if(strcmp(argv[1], "normal") != 0){
    	printf("Select either 'blocked' or 'normal'\n");
    	return 0;
    }else{
    	recon("changeme");
    	rm_path("file", "changeme");
    }
    
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

