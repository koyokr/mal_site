drop: drop.c struct.h
	gcc -std=c11 -O2 -o drop drop.c -lnetfilter_queue

clean:
	rm drop

