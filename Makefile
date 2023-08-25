.PHONY : build clean

CC=gcc
PROGRAM_NAME=app
SOURCE=main.c
LIBS=-lcrypto

build:
	$(CC) $(SOURCE) -o $(PROGRAM_NAME) $(LIBS)

clean:
	rm -f $(PROGRAM_NAME)