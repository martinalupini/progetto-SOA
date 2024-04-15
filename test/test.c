#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../user/syscallsCLI/lib/include/refmonitor.h"

int main (int argc, char *argv[]) {

	int i;
	for(i=0; i<5; i++){
	
		recon("changeme");
		recoff("changeme");
	
	}

}
