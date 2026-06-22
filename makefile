all: myELF

myELF: myELF.c
	gcc -m32 -g myELF.c -o myELF

.PHONY: all clean

clean:
	rm -f myELF