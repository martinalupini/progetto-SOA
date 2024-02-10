#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


char *string = "ciao\n";

int syscall_entry[4];

int start_monitor(char *x){
	return syscall(syscall_entry[0],x);
}

int stop_monitor(char *x){
	return syscall(syscall_entry[1],x);
}

int main (int argc, char *argv[]) {

	int fd;
	int i;

	
	fd=open("/home/martina/Desktop/progetto-SOA/file", O_RDWR);
	if (fd== -1) {
		perror("Open error: ");
		exit(-2);
	}

	write(fd,string,strlen(string));
	
	for(i=0; i<4; i++){
		syscall_entry[i]= atoi(argv[i+1]);
		printf("%d\n", syscall_entry[i]);
	}
	
	//stop_monitor("prova");
	
}

