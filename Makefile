# Execute the commands in the following order. 
# make mount and make unmount need root capabilities.

obj-m += the_reference_monitor.o 
the_reference_monitor-objs += reference_monitor.o lib/scth.o lib/cryptohash.o

A = $(shell cat /sys/module/the_usctm/parameters/sys_call_table_address)
B = $(shell realpath singlefile-FS/mount/the-file)


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 
		
mount:
	insmod the_reference_monitor.ko the_syscall_table=$(A) the_file=$(B)

# Execute make unmount to unmount the module and make clean to remove the files generated by make all	
unmount:
	rmmod the_reference_monitor.ko
	
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
