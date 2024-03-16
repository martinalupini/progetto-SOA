#!/bin/bash

entry1=$( cat "/sys/module/the_reference_monitor/parameters/entry1" )
entry2=$(cat "/sys/module/the_reference_monitor/parameters/entry2")
entry3=$(cat "/sys/module/the_reference_monitor/parameters/entry3")
entry4=$(cat "/sys/module/the_reference_monitor/parameters/entry4")
entry5=$(cat "/sys/module/the_reference_monitor/parameters/entry5")
entry6=$(cat "/sys/module/the_reference_monitor/parameters/entry6")
entry7=$(cat "/sys/module/the_reference_monitor/parameters/entry7")

cd user/syscallsCLI/lib/include
echo "#ifndef _ENTRIES_" > entries.h
echo " " >> entries.h
echo "#define _ENTRIES_" >> entries.h
echo " " >> entries.h
echo "#define ENTRY1 $entry1" >> entries.h
echo "#define ENTRY2 $entry2" >> entries.h
echo "#define ENTRY3 $entry3" >> entries.h
echo "#define ENTRY4 $entry4" >> entries.h
echo "#define ENTRY5 $entry5" >> entries.h
echo "#define ENTRY6 $entry6" >> entries.h
echo "#define ENTRY7 $entry7" >> entries.h
echo " " >> entries.h
echo "#endif" >> entries.h
