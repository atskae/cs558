/*
	https://www.tldp.org/LDP/lkmpg/2.6/html/x569.html#FTN.AEN630
	Simple character devices that tells user how many times the device file has been read
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h> // definition of file_operations struct (function ptrs of device functions)
#include <linux/sched.h>
#include <asm/uaccess.h> // put_user() ; for kernel to write to a user-provided buffer
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "pic_kernel_char.h"

/* Global variables defined as static */
static int Major; // Major number assigned to device driver ; indicates which driver handles which device file

/* Meltdown related */
static unsigned char* pic_bytes = NULL;
static unsigned char* pic_bytes_buffer = NULL;
static int pic_size = 0;

// defined in linux/fs.h
static struct file_operations fops = {
	.read = device_read,
	.write = device_write,
	.open = device_open,
	.release = device_release	
};

// when device is first loaded into the kernel
int init_module(void) {

	// adding driver to the system
	Major = register_chrdev(0, DEVICE_NAME, &fops); // 0: kernel assigns a free major number for this device
	if(Major < 0) {
		printk(KERN_ALERT "Failed to register device with %i\n", Major);
		return Major; // non-zero return value prevents loading this module
	}

	// kernel logs the address of the secret (not secret value)
	// in real Meltdown attacks, the attacker must figure out where the secret is themselves (how?)
	printk(KERN_INFO "Initializing picture module. Major %i. Picture loadable at %p\n", Major, &pic_bytes);

	return 0; // always return 0 on success
}

// right before device is unloaded from kernel
void cleanup_module(void) {
	unregister_chrdev(Major, DEVICE_NAME); // no return value...
	
	if(pic_bytes && pic_bytes_buffer) {
		vfree(pic_bytes); // free old picture
		vfree(pic_bytes_buffer);
	}
}

/*
	Character driver methods
*/

// called when process opens the device file ; ex) cat /dev/mycharfile
static int device_open(struct inode* inode, struct file* file) {
	try_module_get(THIS_MODULE); // increments usage count ; ensures that module cannot be removed if users are currently using it
	// must call module_put() when closing device to decrement usage count
	
	return SUCCESS;
}

// called when user closes device file
static int device_release(struct inode* inode, struct file* file) {
	module_put(THIS_MODULE); // decrements current usage count ; if this never reaches 0, the module can never be removed	
	
	return SUCCESS;
}

// called when user attempts to read device file
static ssize_t device_read(struct file* filep, char* buffer, size_t length, loff_t* offset) {
	if(!pic_bytes) {
		printk(KERN_ALERT "No picture to read.\n");
		return 0;	
	}

	memcpy(pic_bytes_buffer, pic_bytes, pic_size); // copies bytes to another kernel buffer ; not to user 
	return pic_size;
}

// called when user attempts to write to device file ; ex) echo "hi" > /dev/hello
// user sends picture bytes to kernel
static ssize_t device_write(struct file* filep, const char* buffer, size_t buffer_size, loff_t* offset) {
	
	unsigned long ret;	
	printk(KERN_ALERT "Preparing to write to kernel.\n");
	
	if(pic_bytes && pic_bytes_buffer) {
		vfree(pic_bytes); // free old picture
		vfree(pic_bytes_buffer);
	}
	pic_bytes = vmalloc(buffer_size);	
	pic_bytes_buffer = vmalloc(buffer_size);
	if(!pic_bytes || !pic_bytes_buffer) {
		printk(KERN_ALERT "Failed to allocate space.\n");
		return -ENOMEM;
	}

	ret = copy_from_user(pic_bytes, buffer, buffer_size);
	if(ret != 0) {
		printk(KERN_ALERT "Failed to obtain %li bytes from user. Picture not loaded.\n", ret);
		vfree(pic_bytes);
		vfree(pic_bytes_buffer);
		return -EFAULT;
	}
	pic_size = buffer_size;	
	printk(KERN_ALERT "Image size %i bytes ; the last byte: %02x\n", pic_size, pic_bytes[pic_size-1]);
	
	return pic_size;
	
} 
