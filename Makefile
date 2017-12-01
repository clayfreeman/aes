WORKER_COUNT		:= 8
WORKER_BLOCK_COUNT	:= 4096

TARGETS			:= main_${WORKER_COUNT}w_${WORKER_BLOCK_COUNT}b

.PHONY: all archive clean

all: $(TARGETS)

archive:
	git archive -o archive.zip HEAD

clean:
	rm -rf archive.zip main_*w_*b *.o

main_${WORKER_COUNT}w_${WORKER_BLOCK_COUNT}b: main_${WORKER_COUNT}w_${WORKER_BLOCK_COUNT}b.o aes_${WORKER_COUNT}w_${WORKER_BLOCK_COUNT}b.o aes128_${WORKER_COUNT}w_${WORKER_BLOCK_COUNT}b.o aes128ctr_${WORKER_COUNT}w_${WORKER_BLOCK_COUNT}b.o
	gcc -o $@ $^ -lpthread

%_${WORKER_COUNT}w_${WORKER_BLOCK_COUNT}b.o: %.c
	gcc -Ofast -c -g -o $@ -std=c11 -Wall -Wextra -pedantic -fPIC \
		-DAES128CTR_WORKER_COUNT=${WORKER_COUNT} \
		-DAES128CTR_WORKER_BLOCK_COUNT=${WORKER_BLOCK_COUNT} $^
