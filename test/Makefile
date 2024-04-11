
all:
	gcc -c syscallsCLI/lib/refmonitor.c -o syscallsCLI/lib/refmonitor.o
	gcc -o test test.c syscallsCLI/lib/refmonitor.o
	gcc -o thread thread.c -pthread syscallsCLI/lib/refmonitor.o
	gcc -o stress_open stress_open.c -pthread syscallsCLI/lib/refmonitor.o
