#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/random.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/fs_struct.h>
#include <linux/mm_types.h>


#define LIBNAME "PATHFINDER"


char *find_dir(char *path){

	int i= strlen(path)-1;
	char *new_string = kmalloc(strlen(path), GFP_KERNEL);
	if(new_string == NULL)  return "";
	
	while(i>=0){
		if(path[i] != '/'){ 
			new_string[i] = '\0'; 
		}
		else{
			new_string[i]='\0';
			i--;
		 	break;
		}
		i--;
	}
	
	while(i>=0){
		new_string[i] = path[i];
		i--;
	}
	
	return new_string;
}


char *full_path_user(int dfd, const __user char *user_path){
	struct path path_struct;
	char *tpath;
	char *path;
	int error = -EINVAL,flag=0;
	unsigned int lookup_flags = 0;

	tpath=kmalloc(1024,GFP_KERNEL);
	if(tpath == NULL)  return NULL;
	if (!(flag & AT_SYMLINK_NOFOLLOW))    lookup_flags |= LOOKUP_FOLLOW;
	error = user_path_at(dfd, user_path, lookup_flags, &path_struct);
	if(error){
		//printk("%s: File %s does not exist. Error is %d\n", MODNAME, user_path, error);
		kfree(tpath);
		return NULL;
	}
	
	path = d_path(&path_struct, tpath, 1024);
	kfree(tpath);		
	return path;

}


char *full_path_user_permanent(int dfd, const __user char *user_path){
	struct path path_struct;
	char *tpath;
	char *path;
	int error = -EINVAL,flag=0;
	unsigned int lookup_flags = 0;

	tpath=kmalloc(1024,GFP_KERNEL);
	if(tpath == NULL) return NULL;
	if (!(flag & AT_SYMLINK_NOFOLLOW))    lookup_flags |= LOOKUP_FOLLOW;
	error = user_path_at(dfd, user_path, lookup_flags, &path_struct);
	if(error){
		//printk("%s: File %s does not exist. Error is %d\n", MODNAME, user_path, error);
		kfree(tpath);
		return NULL;
	}
	
	path = d_path(&path_struct, tpath, 1024);		
	return path;

}


char *full_path(struct path path_struct){
	char *tpath;
	char *path;
	
	tpath=kmalloc(1024,GFP_KERNEL);
	if(tpath == NULL)  return "";
	path = d_path(&path_struct, tpath, 1024);
	
	return path;
}

int isDir(const char *filename){
	struct path path;
        int error;
        struct inode *inode;
        
        error=kern_path(filename,LOOKUP_FOLLOW, &path);
        if(error){
                return -1;
        }
        inode = path.dentry->d_inode;
        if(S_ISDIR(inode->i_mode)){
                return 0;
        }else{
                return -1;
        }


}

char *get_pwd(void){

	struct path abs_path;
    	char *buf, *full_path;

	buf = kmalloc(1024,GFP_KERNEL);
	if(buf == NULL) return "";

    	get_fs_pwd(current->fs, &abs_path);

    	full_path = dentry_path_raw(abs_path.dentry, buf, PATH_MAX);
    	
    	return full_path;

}

