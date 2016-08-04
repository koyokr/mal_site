drop: drop.c struct.h
	gcc -std=c99 -O2 -o drop drop.c -lnetfilter_queue -lpthread

clean:
	rm drop

