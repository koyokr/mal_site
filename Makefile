drop: drop.o func.o
	gcc -o drop drop.o func.o -lnetfilter_queue -lpthread

drop.o: drop.c struct.h
	gcc -O2 -c drop.c

func.o: func.c struct.h
	gcc -O2 -c func.c

clean:
	rm drop.o func.o drop

