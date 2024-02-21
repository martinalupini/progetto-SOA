
all:
	gcc -c syscallsCLI/lib/refmonitor.c -o syscallsCLI/lib/refmonitor.o
	gcc -o user user.c syscallsCLI/lib/refmonitor.o
	gcc -o add_path syscallsCLI/add_path.c syscallsCLI/lib/refmonitor.o
	gcc -o rm_path syscallsCLI/rm_path.c syscallsCLI/lib/refmonitor.o
	gcc -o change_pass syscallsCLI/change_pass.c syscallsCLI/lib/refmonitor.o
	gcc -o recon syscallsCLI/recon.c syscallsCLI/lib/refmonitor.o
	gcc -o recoff syscallsCLI/recoff.c syscallsCLI/lib/refmonitor.o
	gcc -o start_monitor syscallsCLI/start_monitor.c syscallsCLI/lib/refmonitor.o
	gcc -o stop_monitor syscallsCLI/stop_monitor.c syscallsCLI/lib/refmonitor.o

test:
	./user
	
	
rm:
	rm user
	rm add_path
	rm rm_path
	rm change_pass
	rm recoff
	rm recon
	rm start_monitor
	rm stop_monitor
	
