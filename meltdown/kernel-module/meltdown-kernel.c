/*
 
	Demonstrates the Meltdown attack on the kernel
	- Kernel stores secret data in this kernel module
	- User-level attacker can read the secret data using Meltdown

	Syracuse University's Meltdown Lab
	http://www.cis.syr.edu/~wedu/seed/Labs_16.04/System/Meltdown_Attack/Meltdown_Attack.pdf

*/

#include <linux/module.h> // needed by all kernel modules
#include <linux/kernel.h> // printk macros
#include <linux/fs.h> // file_operations
#include <linux/proc_fs.h> // to create /proc files
#include <linux/seq_file.h> // single_open()

#include "kernel-meltdown.h"

#define PROC_NAME "secret_data"
static struct proc_dir_entry* Secret_Proc_File; // where user-level programs communicate with this module

static struct file_operations fops = {
	.read = proc_read,
	//.write = proc_write,
	.open = proc_open,
	//.release = proc_release
};

#define SECRET_BYTES_N 10
static char secret[SECRET_BYTES_N] = {'P', 'a', 'j', 'a', 'm', 'a', ' ', 'S', 'a', 'm'};
static char* secret_buffer;

/*
	Kernel module init/cleanup methods ; required 
*/
int init_module(void) { // when kernel module is first loaded

	// kernel logs the address of the secret (not secret value)
	// in real Meltdown attacks, the attacker must figure out where the secret is themselves (how?)
	printk(KERN_INFO "Initializing module. My secret is at address %p\n", &secret);

	// allocate memory for secret buffer (?)
	secret_buffer = (char*) vmalloc(SECRET_BYTES_N);

	// create an file in /proc directory ; user-level programs can read this file to interact with this kernel module
	// /proc: special files created by kernel to send information out to the world ; each /proc file is associated with a kernel function
	Secret_Proc_File = proc_create_data(PROC_NAME, 0444, NULL, &fops, NULL);	
	if(!Secret_Proc_File) {
		printk(KERN_ALERT "Failed to create /proc file.\n");
		return -ENOMEM; // out of memory error ; asm/error.h 
	}

	return 0; // always return 0 on success
}

void cleanup_module(void) {
	// remove the /proc file for this module
	remove_proc_entry(PROC_NAME, NULL);
}

/*
	/proc file methods ; function prototypes defined in linux/fs.h
*/
static int proc_open(struct inode* inode, struct file* file) {
	return single_open(file, NULL, PDE_DATA(inode)); // returns the data in file
}

static ssize_t proc_read(struct file* filep, char* user_buffer, size_t buffer_size, loff_t* offset) {
	memcpy(secret_buffer, &secret, SECRET_BYTES_N); // only send the address to user ; not the secret value
	return SECRET_BYTES_N;
}
