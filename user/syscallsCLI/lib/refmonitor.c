#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "include/entries.h"


int start_monitor(char *pass){
	return syscall(ENTRY1, pass);
}

int stop_monitor(char *pass){
	return syscall(ENTRY2, pass);
}

int recon(char *pass){
	return syscall(ENTRY3, pass);
}

int recoff(char *pass){
	return syscall(ENTRY4, pass);
}

int add_path(char *path, char *pass){
	return syscall(ENTRY5, path, pass);
}

int rm_path(char *path, char *pass){
	return syscall(ENTRY6, path, pass);
}

int change_pass(char *new_pass, char *old_pass){
	return syscall(ENTRY7, new_pass, old_pass);
}

