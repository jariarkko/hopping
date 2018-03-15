
PROGRAMS=	hopping

SOURCES=	hopping.c \
		Makefile \
		hopping-tests.sh

OBJECTS=	hopping.o

CFLAGS=		-g

CC=		cc
LD=		cc

all:	$(PROGRAMS)

hopping:	$(SOURCES) $(OBJECTS)
	$(LD) $(CFLAGS) hopping.o -o hopping

hopping.o:	$(SOURCES)
	$(CC) $(CFLAGS) -c hopping.c

test:	$(PROGRAMS)
	bash ./hopping-tests.sh

install:	$(PROGRAMS)
	cp hopping /usr/bin/hopping

wc:
	wc -l $(SOURCES)

clean:
	-rm hopping.o
	-rm hopping
	-rm *~
