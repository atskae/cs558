/*
 	Obtains a picture file from the user
	- Trying to see if another user-process can obtain this picture
*/

#include <linux/module.h> // needed by all kernel modules
#include <linux/kernel.h> // printk macros
#include <linux/fs.h> // file_operations
#include <linux/proc_fs.h> // to create /proc files
#include <linux/seq_file.h> // single_open()
#include <linux/vmalloc.h>
#include <linux/uaccess.h> // copy_from_user()

#include "pic_kernel.h"

#define PROC_NAME "pic"
static struct proc_dir_entry* Proc_File; // where user-level programs communicate with this module

/* Picture file (png, jpeg, ...) from user-level */
static unsigned char* pic_bytes = NULL;
static size_t pic_size = 0; // size in bytes
static unsigned char* pic_bytes_buffer = NULL; // a place to move picture bytes to, to "access" the bytes

static struct file_operations fops = {
	.read = proc_read,
	.write = proc_write,
	.open = proc_open,
	//.release = proc_release
};

/*
	Kernel module init/cleanup methods ; required 
*/
int init_module(void) { // when kernel module is first loaded

	// kernel logs the address of the secret (not secret value)
	// in real Meltdown attacks, the attacker must figure out where the secret is themselves (how?)
	printk(KERN_INFO "Initializing picture module. Picture loadable at %p\n", &pic_bytes);

	// create an file in /proc directory ; user-level programs can read this file to interact with this kernel module
	// /proc: special files created by kernel to send information out to the world ; each /proc file is associated with a kernel function
	Proc_File = proc_create_data(PROC_NAME, 0444, NULL, &fops, NULL);	
	if(!Proc_File) {
		printk(KERN_ALERT "Failed to create /proc file.\n");
		return -ENOMEM; // out of memory error ; asm/error.h 
	}

	return 0; // always return 0 on success
}

void cleanup_module(void) {
	// remove the /proc file for this module
	remove_proc_entry(PROC_NAME, NULL);

	if(pic_bytes && pic_bytes_buffer) {
		vfree(pic_bytes); // free old picture
		vfree(pic_bytes_buffer);
	}
}

/*
	/proc file methods ; function prototypes defined in linux/fs.h
*/
static int proc_open(struct inode* inode, struct file* file) {
	return single_open(file, NULL, PDE_DATA(inode));
}

static ssize_t proc_read(struct file* filep, char* user_buffer, size_t buffer_size, loff_t* offset) {
	
	if(!pic_bytes) {
		printk(KERN_ALERT "No picture to read.\n");
		return 0;	
	}

	memcpy(pic_bytes_buffer, &pic_bytes, pic_size); // copies bytes to another kernel buffer ; not to user 
	return pic_size;
}

static ssize_t proc_write(struct file* filep, const char* user_buffer, size_t buffer_size, loff_t* offset) {	

	unsigned long ret;
	
	if(pic_bytes && pic_bytes_buffer) {
		vfree(pic_bytes); // free old picture
		vfree(pic_bytes_buffer);
	}
	pic_bytes = vmalloc(buffer_size);	
	pic_bytes_buffer = vmalloc(buffer_size);

	ret = copy_from_user(pic_bytes, user_buffer, buffer_size);
	if(ret != 0) {
		printk(KERN_ALERT "Failed to obtain %li bytes from user. Picture not loaded.\n", ret);
		vfree(pic_bytes);
		vfree(pic_bytes_buffer);
		return -EFAULT;
	}
	pic_size = buffer_size;
	return pic_size;
}
