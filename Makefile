CC = gcc
CCFLAGS = -Wall
DFLAGS = -MD
LD = $(CC)
LDFLAGS =
OFILES = main.o udp.o
RM = rm -f
TARGET = test

all: $(TARGET)

$(TARGET): $(OFILES)
	$(LD) $(LDFLAGS) $(OFILES) -o $(TARGET) -lpcap

-include $(OFILES:.o=.d)

%.o : %.c
	$(CC) -c $(DFLAGS) $(CXXFLAGS) $< -o $@

clean:
	$(RM) $(TARGET) *.o *.d *.bak
