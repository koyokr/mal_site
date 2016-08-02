drop: drop.c
	gcc -std=c11 -o drop drop.c -lnetfilter_queue

clean:
	rm drop

