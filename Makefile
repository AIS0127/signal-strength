CC = gcc

all: signal-strength
	
signal-strength: main.o 
	gcc -o signal-strength main.o -lpcap 
main.o: main.c 
	gcc -c -o main.o main.c
clean:
	rm -f *.o deauth-attack
