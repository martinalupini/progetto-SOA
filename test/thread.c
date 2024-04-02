#include <stdio.h> 
#include <pthread.h> 
#include <string.h>
#include "syscallsCLI/lib/include/refmonitor.h"
 
#define NUM_THREADS 3 
 

void *start_the_monitor(void *threadID) { 
    long tid; 
    tid = (long)threadID; 
    printf("I'm thread #%ld and I'm changing the monitor status to ON\n", tid);
    
    start_monitor("changeme");
     
    pthread_exit(NULL); 
} 
 
 void *stop_the_monitor(void *threadID) { 
    long tid; 
    tid = (long)threadID; 
    printf("I'm thread #%ld and I'm changing the monitor status to OFF\n", tid);
    
    stop_monitor("changeme");
     
    pthread_exit(NULL); 
} 
 
 
 void *recon_monitor(void *threadID) { 
    long tid; 
    tid = (long)threadID; 
    printf("I'm thread #%ld and I'm changing the monitor status to REC-ON\n", tid);
    
    recon("changeme");
     
    pthread_exit(NULL); 
} 
 
 
int main() { 
    pthread_t threads[NUM_THREADS]; 
    int rc; 
    long t; 
 
    // Creazione dei thread 
    printf("Creating thread #%ld\n", t); 
    rc = pthread_create(&threads[t], NULL, start_the_monitor, (void *)t); 
    if (rc) { 
            printf("Error: %s\n", strerror(rc)); 
            return -1; 
    }
    
    
    t++;
    printf("Creating thread #%ld\n", t); 
    rc = pthread_create(&threads[t], NULL, stop_the_monitor, (void *)t); 
    if (rc) { 
            printf("Error: %d\n", rc); 
            return -1; 
    }
    
    t++;
    printf("Creating thread #%ld\n", t); 
    rc = pthread_create(&threads[t], NULL, recon_monitor, (void *)t); 
    if (rc) { 
            printf("Error: %d\n", rc); 
            return -1; 
    }
 
    // Attendiamo la terminazione dei thread 
    for(t = 0; t < NUM_THREADS; t++) { 
        rc = pthread_join(threads[t], NULL); 
        if (rc) { 
            printf("Join error: %d\n", rc); 
            return -1; 
        } 
    } 
 
    printf("All thread terminated successfully.\n"); 
 
    pthread_exit(NULL); 
}