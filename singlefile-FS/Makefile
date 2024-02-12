obj-m += singlefilefs.o
singlefilefs-objs += singlefilefs_src.o file.o dir.o

all:
	gcc singlefilemakefs.c -o singlefilemakefs
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

load-FS-driver:
	insmod singlefilefs.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm onefilemakefs

create-fs:
	dd bs=4096 count=100 if=/dev/zero of=image
	./singlefilemakefs image
	mkdir mount
	
mount-fs:
	mount -o loop -t singlefilefs image ./mount/
	
remove:
	rm Module.symvers
	rm modules.order
	rm singlefilefs.ko
	rm singlefilefs.mod
	rm singlefilefs.mod.c
	rm singlefilefs.mod.o
	rm singlefilefs.o
	rm singlefilefs_src.o
	rm singlefilemakefs
	rm image
	rm dir.o
	rm file.o
	rmdir mount
