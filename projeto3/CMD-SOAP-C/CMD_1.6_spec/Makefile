CC = gcc 

CFLAGS = $(shell pkg-config --cflags glib-2.0) -ansi -Wunreachable-code -O2 -Wuninitialized -Wunused-parameter -Wall -Wextra

LIBS = $(shell pkg-config --libs glib-2.0) -lcurl -lssl -lcrypto

OBJECTS = obj/main.o obj/cmd_config.o obj/cmd_soap_msg.o
 
DOC = doc/Doxyfile

compile: $(OBJECTS)
	$(CC) $(CFLAGS) -o program $(OBJECTS) $(LIBS)

obj/%.o: src/%.c
	@mkdir -p obj
	$(CC) $(CFLAGS) -o $@ -c $<	

obj/main.o: src/headers/cmd_config.h
obj/cmd_config.o: src/headers/cmd_config.h
obj/cmd_soap_msg.o: src/headers/cmd_soap_msg.h

run_gc: $(OBJECTS)
	$(CC) $(CFLAGS) -o program $(OBJECTS) $(LIBS)
	./program gc -prod '+351 123456789'

run_ms: $(OBJECTS)
	$(CC) $(CFLAGS) -o program $(OBJECTS) $(LIBS)
	./program ms -prod '+351 123456789' 1234

run_mms: $(OBJECTS)
	$(CC) $(CFLAGS) -o program $(OBJECTS) $(LIBS)
	./program mms -prod '+351 123456789' 1234

run_otp: $(OBJECTS)
	$(CC) $(CFLAGS) -o program $(OBJECTS) $(LIBS)
	./program otp -prod 123456

run_test: $(OBJECTS)
	$(CC) $(CFLAGS) -o program $(OBJECTS) $(LIBS)
	./program test -prod ../LICENSE '+351 123456789' 1234

clean:
	rm -f program
	rm -f debug 
	rm -f $(OBJECTS)

debug: $(OBJECTS)
	$(CC) $(OBJECTS) -g -o debug $(LIBS)
	gdb debug

.PHONY: doc
doc:$(OBJECTS)
		doxygen $(DOC)
