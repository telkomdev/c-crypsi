.PHONY : build clean

CC=gcc
GPP=g++
PROGRAM_NAME=app
PROGRAM_NAME_TEST=test
SOURCE=main.c
SOURCE_TEST=./tests/test.c
SOURCE_CPP=Main.cpp
LIBS=-lcrypto

build:
	$(CC) $(SOURCE) -o $(PROGRAM_NAME) $(LIBS)

buildtest:
	$(CC) $(SOURCE_TEST) -o $(PROGRAM_NAME_TEST) $(LIBS)

buildcpp:
	$(GPP) -o $(PROGRAM_NAME) -std=c++14 $(SOURCE_CPP) $(LIBS)

comp:
	$(GPP) -o app.o -std=c++14 -Wall -Wextra -pedantic $(SOURCE_CPP) $(LIBS)

clean:
	rm -f $(PROGRAM_NAME)