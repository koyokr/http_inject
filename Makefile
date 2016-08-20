RESULT  = http_inject
SOURCES = http_inject.o
#HEADERS =

$(RESULT): $(SOURCES)
	gcc -o $(RESULT) $(SOURCES) -lpcap

http_inject.o: http_inject.c
	gcc -O2 -c http_inject.c

clean:
	rm -f $(RESULT) $(SOURCES) *.gch

