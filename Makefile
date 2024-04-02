# Execute the commands in the following order. 
# make mount and make unmount need root capabilities.

obj-m += the_reference_monitor.o 
the_reference_monitor-objs += reference_monitor.o lib/scth.o lib/cryptohash.o lib/pathfinder.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 
		
mount:
	insmod the_reference_monitor.ko the_syscall_table=$(shell cat /sys/module/the_usctm/parameters/sys_call_table_address) the_file=$(realpath singlefile-FS/mount/the-file)
	
create-header:
	echo "#ifndef _ENTRIES_\n\n#define _ENTRIES_\n\n#define ENTRY1 $(shell cat /sys/module/the_reference_monitor/parameters/entry1)\n#define ENTRY2 $(shell cat /sys/module/the_reference_monitor/parameters/entry2)\n#define ENTRY3 $(shell cat /sys/module/the_reference_monitor/parameters/entry3)\n#define ENTRY4 $(shell cat /sys/module/the_reference_monitor/parameters/entry4)\n#define ENTRY5 $(shell cat /sys/module/the_reference_monitor/parameters/entry5)\n#define ENTRY6 $(shell cat /sys/module/the_reference_monitor/parameters/entry6)\n#define ENTRY7 $(shell cat /sys/module/the_reference_monitor/parameters/entry7)\n\n#endif" > user/syscallsCLI/lib/include/entries.h
	echo "#ifndef _ENTRIES_\n\n#define _ENTRIES_\n\n#define ENTRY1 $(shell cat /sys/module/the_reference_monitor/parameters/entry1)\n#define ENTRY2 $(shell cat /sys/module/the_reference_monitor/parameters/entry2)\n#define ENTRY3 $(shell cat /sys/module/the_reference_monitor/parameters/entry3)\n#define ENTRY4 $(shell cat /sys/module/the_reference_monitor/parameters/entry4)\n#define ENTRY5 $(shell cat /sys/module/the_reference_monitor/parameters/entry5)\n#define ENTRY6 $(shell cat /sys/module/the_reference_monitor/parameters/entry6)\n#define ENTRY7 $(shell cat /sys/module/the_reference_monitor/parameters/entry7)\n\n#endif" > test/syscallsCLI/lib/include/entries.h

# Execute make unmount to unmount the module and make clean to remove the files generated by make all	
unmount:
	rmmod the_reference_monitor
	
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rmmod the_reference_monitor
	rm ./singlefile-FS/singlefilemakefs
	umount ./singlefile-FS/mount/	
	rmdir ./singlefile-FS/mount
	rmmod singlefilefs
	rm singlefile-FS/image
	rm ./test/stress_open
	rm ./test/test
	rm ./test/thread
	rm ./user/user
	rm ./user/start_monitor
	rm ./user/stop_monitor
	rm ./user/recon
	rm ./user/recoff
	rm ./user/change_pass
	rm ./user/add_path
	rm ./user/rm_path

	
