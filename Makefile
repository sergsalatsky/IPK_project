CC=gcc
CFLAGS= -std=gnu99 -pedantic -Wno-unused -Wall -Wextra -lpcap
all:
	$(CC) $(CFLAGS) ipk-sniffer.c -o  ipk-sniffer -lpcap

doc:
	cd doc && make pdflatex

clean:
	rm -f ipk-sniffer
