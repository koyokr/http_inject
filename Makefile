TARGET  = http_inject
SOURCES = http_inject.c
HEADERS = http_inject.h

LIBS = -lpcap

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	gcc -O2 -o $(TARGET) $(SOURCES) $(LIBS)

clean:
	rm -f $(TARGET) *.o *.gch
