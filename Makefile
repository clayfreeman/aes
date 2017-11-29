TARGETS		:= main

.PHONY: all archive clean

all: $(TARGETS)

archive:
	git archive -o archive.zip HEAD

clean:
	rm -rf archive.zip $(TARGETS) *.o

main: main.o aes.o aes128.o aes128ctr.o
	gcc -o $@ $^ -lpthread

%.o: %.c
	gcc -Ofast -c -g -o $@ -std=c11 -Wall -Wextra -pedantic -fPIC $^
