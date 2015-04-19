debug: libcslob.h libcslob.c cslob.c 
	$(CC) -Wall -I. -g -DDEBUG -o cslob libcslob.c cslob.c -licui18n

all: libcslob.h libcslob.c cslob.c 
	$(CC) -Wall -I. -o cslob libcslob.c cslob.c -licui18n

clean:
	-rm cslob
