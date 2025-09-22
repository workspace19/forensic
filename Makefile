CC=gcc
CFLAGS=-Wall -Wextra -std=c99
LIBS=-lGL -lGLU -lglut -lm
TARGET=charon_forensics
SOURCE=forensics.c

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)

clean:
	rm -f $(TARGET)

install-deps:
	sudo apt-get update
	sudo apt-get install -y freeglut3-dev libgl1-mesa-dev libglu1-mesa-dev

.PHONY: clean install-deps