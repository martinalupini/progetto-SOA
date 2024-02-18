#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


char *string = "ciao\n";

int syscall_entry[7];

int start_monitor(char *pass){
	return syscall(syscall_entry[0],pass);
}

int stop_monitor(char *pass){
	return syscall(syscall_entry[1],pass);
}

int recon(char *pass){
	return syscall(syscall_entry[2],pass);
}

int recoff(char *pass){
	return syscall(syscall_entry[3],pass);
}

int add_path(char *path, char *pass){
	return syscall(syscall_entry[4],path, pass);
}

int rm_path(char *path, char *pass){
	return syscall(syscall_entry[5],path, pass);
}

int change_pass(char *new_pass, char *old_pass){
	return syscall(syscall_entry[6],new_pass, old_pass);
}


int main (int argc, char *argv[]) {

	int fd;
	int i;
	char *buffer = malloc(256);
	char *string = "ciao";

	for(i=0; i<7; i++){
		syscall_entry[i]= atoi(argv[i+1]);
		printf("%d\n", syscall_entry[i]);
	}

	
	
	fd=open("/home/martina/Desktop/progetto-SOA/user/file.txt", O_RDWR);
	if (fd== -1) {
		perror("Open error: ");
		exit(-2);
	}

	//read(fd,buffer,256);
	write(fd, string, strlen(string));
	
	//printf("%s\n", buffer);
	
	
	/*
	i =stop_monitor("changeme");
	if(i<0) printf("error\n");
	start_monitor("changeme");
	
	recon("changeme");
	i=add_path("../singlefile-FS/mount/the-file", "changeme");
	if(i<0) printf("error adding file\n");
	add_path("/home/martina/Desktop", "changeme");
	i=change_pass("ciao", "changeme");

	
	add_path("/home/martina/Desktop/file", "ciao");

	add_path("/home/martina/Desktop", "prova");
	rm_path("/home/martina/Desktop", "prova");
	rm_path("/home/martina/Desktop/progetto-SOA", "prova");
	rm_path("/home/martina/Desktop/file", "prova");
	rm_path("/home/martina/Desktop/progetto-SOA/file", "prova");
	i = rm_path("/home/martina/Desktop/file", "prova");
	if(i<0){
		printf("Path not present or wrong password\n");
	}
	
	seteuid(1000);
	i = stop_monitor("prova");
	if(i<0){
		printf("Not root user or wrong password\n");
	}*/
	
	return 0;
}

