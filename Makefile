all: libcslob.h libcslob.c cslob.c 
	$(CC) -I. -o cslob libcslob.c cslob.c

debug: libcslob.h libcslob.c cslob.c 
	$(CC) -I. -DDEBUG -o cslob libcslob.c cslob.c
