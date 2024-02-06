#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


char *string = "ciao\n";

int main (int argc, char *argv[]) {

	int fd;
	int i;


	fd=open("file.txt", O_RDWR);
	if (fd== -1) {
		perror("Open error: ");
		exit(-2);
	}

	write(fd,string,strlen(string));
	
}

