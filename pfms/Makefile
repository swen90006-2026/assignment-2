SHELL:=/bin/bash

normal:
	gcc -g -o pfms pfms.c
	gcc -g -o service service.c

gcov:
	gcc -fprofile-arcs -ftest-coverage -g -o pfms-gcov pfms.c

fuzzing:
	afl-clang-fast -g -o pfms-fuzz pfms.c

asan:
	clang -fsanitize=address -g -o pfms-asan pfms.c

all: normal gcov asan fuzzing

clean:
	rm -f service pfms pfms-gcov pfms-fuzz pfms-asan pfms.gcno pfms.gcda
