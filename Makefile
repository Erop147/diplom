CC = gcc
CCFLAGS = -Wall
DFLAGS = -MD -g
LD = $(CC)
LDFLAGS =
OFILES = main.o udp.o ts_util.o tests.o dictionary.o iniparser.o config.o
RM = rm -f
TARGET = nettest

all: $(TARGET)

$(TARGET): $(OFILES)
	$(LD) $(LDFLAGS) $(OFILES) -o $(TARGET) -lpcap -lrt

-include $(OFILES:.o=.d)

%.o : %.c
	$(CC) -c $(DFLAGS) $(CXXFLAGS) $< -o $@

clean:
	$(RM) $(TARGET) *.o *.d *.bak
