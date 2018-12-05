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

#include "pic_kernel.h"

/* Global variables defined as static */
static int Major; // Major number assigned to device driver ; indicates which driver handles which device file

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

	printk(KERN_INFO "Initializing module with major %i\n", Major);

	return 0; // always return 0 on success
}

// right before device is unloaded from kernel
void cleanup_module(void) {
	unregister_chrdev(Major, DEVICE_NAME); // no return value...
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
	printk(KERN_ALERT "Nothing to read.\n");
	return 0;
}

// called when user attempts to write to device file ; ex) echo "hi" > /dev/hello
// kernel simply accesses the address sent by user ; nothing is written or sent
static ssize_t device_write(struct file* filep, const char* buffer, size_t buffer_size, loff_t* offset) {
	
	uint64_t addr;
	unsigned char c = 0;

	addr = copy_from_user(&addr, buffer, buffer_size);
	if(addr != 0) {
		printk(KERN_ALERT "Failed to obtain buffer from user. ret=%i\n", addr);
		return -EFAULT;
	}
		
	if(virt_addr_valid(addr)) {
		c = *(char*)addr;
		printk(KERN_ALERT "I got this %02x, did you?\n", c);
	} else {
		printk(KERN_ALERT "Invalid addr: %p\n", addr);
	}
	
	return 0; // kernel did not write anything	
} 
