all: myELF

task1: myELF.c
	gcc -m32 -g myELF.c -o myELF

.PHONY: clean

clean:
	rm -f myELF