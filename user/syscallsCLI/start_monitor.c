#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "lib/include/refmonitor.h"


int main (int argc, char *argv[]) {

	int ret;
	
	if(argc!=2){
		printf("Usage: ./start_monitor <password>\n");
		return 0;
	}
	
	
	
	ret = start_monitor(argv[1]);
	if(ret <0){
		printf("\033[1;31mstart_monitor error: Password incorrect or non-root user.\033[1;0m\n");
	}
	
	return 0;
	
}
