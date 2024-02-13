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
The kprobe is done on the kernel function **do_open**, which, as we can read from the kernel source code, handles the last step of the system call open(). 
In particular, the signaure of the function is:

static int do_open(struct nameidata *nd, struct file *file, const struct open_flags *op)


