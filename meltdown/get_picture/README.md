# Attempting to Read Bytes from Another Process

## Build kernel module
1. Change directory to `pic_kernel` and type `make`
```
cd pic_kernel
make
```
(Do not build the other directory `pic_kernel`. That is an old, more unfunctional version....)

2. Load the kernel module
```
sudo insmod pic_kernel.ko
```
pic\_kernel\_char should appear in the list of loaded modules. You can check by typing `lsmod`.

3. Read the Major number assigned to this kernel module
```
dmesg | grep picture
```

It should print out a prompt:
```
Initializing picture module. Major 247. Picture loadable at ffffffffc017e490
```
The address printed out is our target address. We want to read bytes from this address.

4. Create a device file for this kernel module. Set device file to be readable and writable.
```
sudo mknod /dev/pic_kernel c <Major number> 0
sudo chmod 666 /dev/pic_kernel
```

## Build victim and attacker programs
5. Go back to the main directory `get_picture` and type `make`
```
cd ../
make
```

## Run the victim and attacker
6. Pass an image file (.png, .jpeg, etc.) to the victim program as a command line argument.
```
./victim <image.png>
```
The victim sends the image bytes to the kernel module that we loaded in Step 2. The victim remains in a while loop,
constantly causing the kernel to read the picture bytes (thus, keeping the bytes in the cache, I hope).
Leave the victim running.

7. Run the attacker using the address from Step 3.
```
./attacker <address>
```
The goal is to get the attacker's printed bytes to match the bytes printed by the victim. It doesn't seem to work right now...

