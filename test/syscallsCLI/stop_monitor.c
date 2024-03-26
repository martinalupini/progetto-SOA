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
		printf("Usage: ./stop_monitor <password>\n");
		return 0;
	}
	
	
	
	ret = stop_monitor(argv[1]);
	if(ret <0){
		printf("\033[1;31mstop_monitor error: Password uncorrect or non-root user.\033[1;0m\n");
	}
	
	return 0;
	
}
