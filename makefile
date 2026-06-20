all: task0

task1: task0.c
	gcc -m32 -g task0.c -o task0

.PHONY: clean

clean:
	rm -f task0