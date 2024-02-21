#ifndef _REFMON_

#define _REFMON_

int start_monitor(char *pass);
int stop_monitor(char *pass);
int recon(char *pass);
int recoff(char *pass);
int add_path(char *path, char *pass);
int rm_path(char *path, char *pass);
int change_pass(char *new_pass, char *old_pass);


#endif 
