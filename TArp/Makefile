# Description : Simple makefile to build program

# can be changed to desired filename
TARGET_PROGRAM = TArp.out
COMPILER = gcc

#ensures verbose output during compilation
CCFLAGS = -Wall -std=c11

$(TARGET_PROGRAM) : TArp.o
	$(COMPILER) -o $(TARGET_PROGRAM) TArp.o

TArp.o : 
	$(COMPILER) -c TArp.c $(CCFLAGS)

clean :
	rm -f *.o $(TARGET_PROGRAM)

debug : CCFLAGS += -DDEBUG -g
debug : $(TARGET_PROGRAM)
