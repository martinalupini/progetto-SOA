# Advanced Operating Systems Project - Kernel Level Reference Monitor

## Getting started

To clone the repository and also the submodule run:

git clone --recurse-submodules https://github.com/martinalupini/progetto-SOA

## Preliminar steps

1. Install the module the_usctm.ko contained in the folder "Linux-sys_call_table-discoverer". To install it use the Makefile in that folder.
2. Install the filesystem contained in the folder "singlefile-FS". Follow the directions contained in the Makefile.
3. Install the module the_reference_monitor.ko following the directions of the Makefile of the main directory "Progetto-SOA".

## Project specification 

The project specification can be found at the link: https://francescoquaglia.github.io/TEACHING/AOS/CURRENT/PROJECTS/project-specification-2023-2024.html

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

If we reconstruct the flow of system calls from open() we will arrive to filp_open() which in turn calls file_open_name() which then calls do_filp_open(AT_FDCWD, name, &op) (AT_FDCWD equals to -100 and means that the system has to consider the pwd).

