#ifndef KERNEL_MELTDOWN_H
#define KERNEL_MELTDOWN_H

#include <linux/module.h> // needed by all kernel modules
#include <linux/kernel.h> // printk macros
#include <linux/fs.h> // file_operations
#include <linux/proc_fs.h> // to create /proc files

// required functions by all kernel modules
int init_module(void); // when kernel module is first loaded
void cleanup_module(void);

// /proc functions
static int proc_open(struct inode* inode, struct file* file);
static ssize_t proc_read(struct file* filep, char* user_buffer, size_t buffer_size, loff_t* offset);

#endif // KERENL_MELTDOWN_H
