#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "syscallsCLI/lib/include/refmonitor.h"

#define println() printf("\n")

int main (int argc, char *argv[]) {

	int fd;
	int ret;
	char *buffer = malloc(256);
	char *string = "ciao";
	char cwd[1024];
	
	getcwd(cwd, sizeof(cwd));
	
	if(geteuid() != 0){
		printf("Please run the test as root user.\n");
		return 0;
	}

	printf("\033[1;36mREFERENCE MONITOR SUBSYSTEM DEMONSTRATION\033[1;0m\n");
	
	printf("The monitor is now ON but no file or directory are blacklisted. Calling recon to change status to REC-ON.\n");
	ret = recon("changeme");
	if(ret <0){
		printf("\033[1;31mrecon error: Password uncorrect or non-root user.\033[1;0m\n");
	}
	println();
	
	
	printf("Now the monitor is in REC-ON. Adding the file %s/file.txt to the reference monitor's list.\nNOTE: the system calls add_path and remove_path can use both relative and absolute path.\n", cwd);
	ret = add_path("file.txt", "changeme");
	if(ret <0){
		printf("\033[1;31madd_path error: Password incorrect, non-root user or reference monitor not in REC-ON or REC-OFF.\033[1;0m\n");
	}
	println();
	
	printf("The path is added. Trying to open it in write mode will return an error.\n");
	fd=open("/home/martina/Desktop/progetto-SOA/user/file.txt", O_RDWR);
	if (fd== -1) {
		perror("Open error");
	}
	println();
	
	printf("Now we add the directory %s/prova to the reference monitor.\n", cwd);
	ret = add_path("prova", "changeme");
	if(ret <0){
		printf("\033[1;31madd_path error: Password incorrect, non-root user or reference monitor not in REC-ON or REC-OFF.\033[1;0m\n");
	}
	println();
	
	printf("Now we remove the path %s/file.txt\n", cwd);
	ret = rm_path("file.txt", "changeme");
	if(ret <0){
		printf("\033[1;31mrm_path error: Path not present, Password incorrect, non-root user or reference monitor not in REC-ON or REC-OFF.\033[1;0m\n");
	}
	println();
	
	printf("If we try to remove a path that is not currently in the reference monitor we'll get an error. For example let's remove /home\n"); 
	ret = rm_path("/home", "changeme");
	if(ret <0){
		printf("\033[1;31mrm_path error: Path not present, Password incorrect, non-root user or reference monitor not in REC-ON or REC-OFF.\033[1;0m\n");
	}
	println();
	
	
	printf("Now we set the monitor status to OFF. If we call add_path we'll get an error\n");
	ret = stop_monitor("changeme");
	if(ret <0){
		printf("\033[1;31mstop_monitor error: Password uncorrect or non-root user.\033[1;0m\n");
	}
	ret = add_path("prova", "changeme");
	if(ret <0){
		printf("\033[1;31madd_path error: Password incorrect, non-root user or reference monitor not in REC-ON or REC-OFF.\033[1;0m\n");
	}
	println();
	
	seteuid(1000);
	
	printf("Now we set euid to user 1000. If we try to start the monitor we'll get an error because is not called by the root user\n");
	ret = recon("changeme");
	if(ret <0){
		printf("\033[1;31mstart_monitor error: Password uncorrect or non-root user.\033[1;0m\n");
	}
	println();
	
	printf("\033[1;36mThe demonstration is terminated. If you would like you can test the reference monitor's system calls via CLI using the executable provided.\033[1;0m\n");


	return 0;
}

