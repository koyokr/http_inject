RESULT  = http_inject
SOURCES = http_inject.c
HEADERS = http_inject.h

$(RESULT): $(SOURCES) $(HEADERS)
	gcc -O2 -o $(RESULT) $(SOURCES) -lpcap

clean:
	rm -f $(RESULT) *.o *.gch
