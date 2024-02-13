# Advance Operating System Project - Kernel Level Reference Monitor

## Getting started

To clone the repository and also the submodule run:

git clone --recurse-submodules https://github.com/martinalupini/progetto-SOA

## Implementation 

### reference_monitor.c

The file is divided into 4 main parts:
- The definition of the struct reference_monitor which represents the monitor itself.
- The definition of the kprobe and the pre-hanlder.
- The set of system calls used to reconfigure the monitor mode and to add/remove path.
- The init and cleanup function of the module

#### kprobe
The kprobe is done on the kernel function **do_filp_open**. The signature of this function is:

struct file *do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op)

If we reconstruct the flow of system calls from open() we will arrive to filp_open() which in turn calls file_open_name() which then calls do_filp_open(AT_FDCWD, name, &op) (AT_FDCWD equals to -100 and means that the system has to consider the pwd)

