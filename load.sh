#!/bin/bash

cd Linux-sys_call_table-discoverer
make all
insmod the_usctm.ko
cd ../singlefile-FS
make all
make load
make create
make mount-fs
cd ..
make all
make mount
./create_header.sh
