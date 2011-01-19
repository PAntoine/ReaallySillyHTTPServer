ifdef SHEEVA_BUILD
include sheeva_tools.mak

export CC = mips-linux-gnu-gcc
export CFLAGS=-EL

endif

HEADER_FILES = $(wildcard *.h)
SOURCE_FILES = $(wildcard *.c)
OBJECT_FILES = $(subst .c,.o,$(wildcard *.c))

BUILD_TARGETS = $(subst src,object,$(OBJECT_FILES))

server: $(OBJECT_FILES)
	@echo $(OBJECT_FILES)
	$(CC) $(CFLAGS) -o server $(OBJECT_FILES) -lpthread -lm

.c.o: $(OBJECT_FILES) $(HEADER_FILES)
	@$(CC) $(CFLAGS) -c $< -o $(@) -I include $(INCDIRS)

clean:
	-@$(RM)	*.o
	-@$(RM) *.obj
	-@$(RM) server
