# Description : Simple makefile to build program

# can be changed to desired filename
TARGET_PROGRAM = TArp.out
T2 = T2.out
COMPILER = gcc

#ensures verbose output during compilation
CCFLAGS = -Wall -std=c11
LDFLAGS = -lrt

$(TARGET_PROGRAM) : TArp.o
	$(COMPILER) -o $(TARGET_PROGRAM) TArp.o $(LDFLAGS)

TArp.o : 
	$(COMPILER) -c TArp.c $(CCFLAGS)

clean :
	rm -f *.o $(TARGET_PROGRAM) $(T2)

debug : CCFLAGS += -DDEBUG -g
debug : $(TARGET_PROGRAM)
