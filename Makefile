obj-m += the_reference_monitor.o 
the_reference_monitor-objs += reference_monitor.o lib/scth.o

A = $(shell cat /sys/module/the_usctm/parameters/sys_call_table_address)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	
mount:
	insmod the_reference_monitor.ko the_syscall_table=$(A)
	
unmount:
	rmmod the_reference_monitor.ko
