
PROGRAMS=	hopping

SOURCES=	hopping.c \
		Makefile

OBJECTS=	hopping.o

CFLAGS=		-g

CC=		cc
LD=		cc

all:	$(PROGRAMS)

hopping:	$(SOURCES) $(OBJECTS)
	$(LD) $(CFLAGS) hopping.o -o hopping

hopping.o:	$(SOURCES)
	$(CC) $(CFLAGS) -c hopping.c

install:	$(PROGRAMS)
	cp hopping /usr/bin/hopping

wc:
	wc -l $(SOURCES)

clean:
	-rm *~
