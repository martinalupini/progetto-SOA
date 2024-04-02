# Advanced Operating Systems Project - Kernel Level Reference Monitor

## Getting started

> [!CAUTION]
>To clone the repository and also the submodule run:
>```
>git clone --recurse-submodules https://github.com/martinalupini/progetto-SOA
>```

After cloning the repository, open a terminal in the directory Progetto-SOA/. 
Execute the script **load.sh** as root user to mount the module.

```
./load.sh
```

After mounting the module, the monitor will be ON. At startup the monitor does not have paths to protect. The default password is **changeme**.

## Testing the reference monitor

> [!CAUTION]
> The entries of the syscall table used for the monitor syscalls differs from kernel to kernel. To find which entries are used in your case you can look at `dmesg` after mounting the module or you type `cat /sys/module/the_reference_monitor/parameters/entry1` (there are 7 entries so entry2, entry3, etc...). 
> 
> After that you have to write the correct entry for your kernel in the file progetto-SOA/user/syscallsCLI/lib/refmonitor.c. 

In the directory user/ you can find pieces of code for testing. After typing `make all` there will be different executables:
- **user** is purely demonstrative. I suggest to run it as first because it shows some of the reference monitor APIs, but is not mandatory.
The other executable are made to simulate shell commands.
- **change_pass** can be used to change the passsword. It takes as arguents the new password and the old password.
- **recon** changes the monitor status to REC-ON. It takes as argument the password.
- **recoff** changes the monitor status to REC-OFF. It takes as argument the password.
- **start_monitor** changes the monitor status to ON. It takes as argument the password.
- **stop_monitor** changes the monitor status to OFF. It takes as argument the password.
- **add_path** adds the path specified as argument to the reference monitor. The path can be absolute or relative. The other argument taken is the password.
- **rm_path** removes the path specified as argument to the reference monitor. The path can be absolute or relative. The other argument taken is the password.

## Project specification 

The project specification can be found at the link: https://francescoquaglia.github.io/TEACHING/AOS/CURRENT/PROJECTS/project-specification-2023-2024.html



