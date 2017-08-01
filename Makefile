all : output

output : main.o
	gcc -o output main.o -lpcap

main.o : main.c
	gcc -c -o main.o main.c

clean :
	rm -f *.o output