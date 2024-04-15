
all:
	gcc -o test test.c ../user/syscallsCLI/lib/refmonitor.o
	gcc -o thread thread.c -pthread ../user/syscallsCLI/lib/refmonitor.o
	gcc -o stress_open stress_open.c -pthread ../user/syscallsCLI/lib/refmonitor.o
