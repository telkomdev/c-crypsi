.PHONY : build clean

CC=gcc
GPP=g++
PROGRAM_NAME=app
SOURCE=main.c
SOURCE_CPP=Main.cpp
LIBS=-lcrypto

build:
	$(CC) $(SOURCE) -o $(PROGRAM_NAME) $(LIBS)

buildcpp:
	$(GPP) -o $(PROGRAM_NAME) -std=c++14 $(SOURCE_CPP) $(LIBS)

comp:
	$(GPP) -o app.o -std=c++14 -Wall -Wextra -pedantic $(SOURCE_CPP) $(LIBS)

clean:
	rm -f $(PROGRAM_NAME)