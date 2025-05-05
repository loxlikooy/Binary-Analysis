CC = gcc
CFLAGS_VULN = -m32 -fno-stack-protector -z execstack
CFLAGS_PROTECTED = -m32 -fstack-protector-all

all: vuln vuln_protected

vuln: vuln.c
	$(CC) $(CFLAGS_VULN) vuln.c -o vuln

vuln_protected: vuln.c
	$(CC) $(CFLAGS_PROTECTED) vuln.c -o vuln_protected

clean:
	rm -f vuln vuln_protected *.o exploit_input exploit_output

.PHONY: all clean 