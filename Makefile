obj-m += reference_monitor.o 

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	
mount:
	insmod reference_monitor.ko
	
unmount:
	rmmod reference_monitor.ko
