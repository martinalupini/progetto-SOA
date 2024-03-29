#!/bin/bash


entry1=$(cat "/sys/module/the_reference_monitor/parameters/entry1")
entry2=$(cat "/sys/module/the_reference_monitor/parameters/entry2")
entry3=$(cat "/sys/module/the_reference_monitor/parameters/entry3")
entry4=$(cat "/sys/module/the_reference_monitor/parameters/entry4")
entry5=$(cat "/sys/module/the_reference_monitor/parameters/entry5")
entry6=$(cat "/sys/module/the_reference_monitor/parameters/entry6")
entry7=$(cat "/sys/module/the_reference_monitor/parameters/entry7")

output="entries.h"

content="#ifndef _ENTRIES_\n\n#define _ENTRIES_\n\n#define ENTRY1 $entry1\n#define ENTRY2 $entry2\n#define ENTRY3 $entry3\n#define ENTRY4 $entry4\n#define ENTRY5 $entry5\n#define ENTRY6 $entry6\n#define ENTRY7 $entry7\n\n#endif"


if ! test user/syscallsCLI/lib/include/entries.h; then 
	echo -e "$content" > user/syscallsCLI/lib/include/entries.h 
	echo "The header file has been written"
fi
