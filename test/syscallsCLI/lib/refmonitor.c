#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


int start_monitor(char *pass){
	return syscall(156, pass);
}

int stop_monitor(char *pass){
	return syscall(174, pass);
}

int recon(char *pass){
	return syscall(177, pass);
}

int recoff(char *pass){
	return syscall(178, pass);
}

int add_path(char *path, char *pass){
	return syscall(180, path, pass);
}

int rm_path(char *path, char *pass){
	return syscall(181, path, pass);
}

int change_pass(char *new_pass, char *old_pass){
	return syscall(182, new_pass, old_pass);
}

