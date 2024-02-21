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
	
	if(argc!=3){
		printf("Usage: ./add_path <path>  <password>\n");
		return 0;
	}
	
	
	
	ret = add_path(argv[1], argv[2]);
	if(ret <0){
		printf("\033[1;31madd_path error: Path does not exists, password incorrect, non-root user or reference monitor not in REC-ON or REC-OFF.\033[1;0m\n");
	}
	
	return 0;
	
}
