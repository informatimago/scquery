OBJECTS=\
	buffer.o \
	certificate-list.o \
	certificate.o \
	error.o \
	pkcs11errors.o \
	pkcs11module.o \
	smartcard-certificate.o \
	string.o
CFLAGS_DEBUG=-g3 -ggdb
CFLAGS=--std=c11 $(CFLAGS_DEBUG)
LDFLAGS=-ldl

all:scquery

scquery:scquery.o $(OBJECTS)
	@printf "# Link   executable %s\n" $@
	@$(CC) $(CFLAGS) $(OBJECTS) $(LDFLAGS) -o $@

clean:
	rm -f *.d *.o scquery core


DEPFLAGS = -MT $@ -MMD -MP -MF $*.Td

COMPILE.c  = $(CC)  $(DEPFLAGS) $(CFLAGS)   $(CPPFLAGS) $(TARGET_ARCH) -c
COMPILE.cc = $(CXX) $(DEPFLAGS) $(CXXFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
POSTCOMPILE = mv -f $*.Td $*.d && touch $@

%.o : %.c
%.o : %.c %.d
	@printf "# Compile C  source %s\n" $<
	@$(COMPILE.c) $(OUTPUT_OPTION) $<
	@$(POSTCOMPILE)

%.o : %.cc
%.o : %.cc %.d
	@printf "# Compile C++ source %s\n" $<
	@$(COMPILE.cc) $(OUTPUT_OPTION) $<
	@$(POSTCOMPILE)

%.o : %.cxx
%.o : %.cxx %.d
	@printf "# Compile C++ source %s\n" $<
	@$(COMPILE.cc) $(OUTPUT_OPTION) $<
	@$(POSTCOMPILE)

%.d: ;
.PRECIOUS: %.d

include $(wildcard $(patsubst %.o,%.d,$(basename $(OBJECTS))))
