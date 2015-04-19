debug: libcslob.h libcslob.c cslob.c 
	$(CC) -Wall -I. -g -DDEBUG -o cslob libcslob.c cslob.c

all: libcslob.h libcslob.c cslob.c 
	$(CC) -Wall -I. -o cslob libcslob.c cslob.c

clean:
	-rm cslob
