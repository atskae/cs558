all: vuln_program exploit

vuln_program: prog.c
	gcc prog.c -fno-stack-protector -z execstack -static -o prog

exploit: exploit.c
	gcc exploit.c -o exploit

clean:
	rm *.input prog exploit
