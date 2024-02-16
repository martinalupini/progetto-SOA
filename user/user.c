#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


char *string = "ciao\n";

int syscall_entry[6];

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


int main (int argc, char *argv[]) {

	int fd;
	int i;
	char *buffer = malloc(256);

	for(i=0; i<6; i++){
		syscall_entry[i]= atoi(argv[i+1]);
		printf("%d\n", syscall_entry[i]);
	}

	
	fd=open("/home/martina/Desktop/progetto-SOA/user/file.txt", O_RDONLY);
	if (fd== -1) {
		perror("Open error: ");
		exit(-2);
	}

	read(fd,buffer,256);
	
	printf("%s\n", buffer);
	
	
	/*
	i =stop_monitor("prova");
	if(i<0) printf("error\n");
	start_monitor("prova");
	*/
	recon("prova");
	i=add_path("../singlefile-FS/mount/the-file", "prova");
	if(i<0) printf("error adding file\n");

	//add_path("/home/martina/Desktop/file", "prova");
	/*
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

