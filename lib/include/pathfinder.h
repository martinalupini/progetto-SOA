#ifndef _PATHFIND_

#define _PATHFIND_

char *find_dir(char *path);
char *full_path_user(int dfd, const __user char *user_path);
char *full_path(struct path path_struct);
int isDir(const char *filename);
char *get_pwd(void);


#endif
