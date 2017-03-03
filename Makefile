install:
	gcc main.c aes256.c file.c -o izi-locker -w

run:
	./izi-locker
