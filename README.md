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

In the directory test/ there is some code to stress out the module and see how it behaves.

## Removing the module

To remove the module execute as root user in the directory Progetto-SOA/:

```
make clean
```

## Project specification 

The project specification can be found at the link: https://francescoquaglia.github.io/TEACHING/AOS/CURRENT/PROJECTS/project-specification-2023-2024.html



