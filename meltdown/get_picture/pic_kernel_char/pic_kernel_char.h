#ifndef CHARDEV_H
#define CHARDEV_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h> // definition of file_operations struct (function ptrs of device functions)
#include <asm/uaccess.h> // put_user() ; for kernel to write to a user-provided buffer

#define SUCCESS 0
#define DEVICE_NAME "chardev"
#define BUF_LEN 128

// necessary enter/exit functions of kernel module
int init_module(void);
void cleanup_module(void);

// device driver functions
static int device_open(struct inode*, struct file*);
static int device_release(struct inode*, struct file*);
static ssize_t device_read(struct file*, char*, size_t, loff_t*); 
static ssize_t device_write(struct file*, const char*, size_t, loff_t*); 

#endif // CHARDEV_H
