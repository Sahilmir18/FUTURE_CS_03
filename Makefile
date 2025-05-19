CXX = g++
CXXFLAGS = -Wall -std=c++11
LDFLAGS = -lpcap

OBJS = main.o packet_sniffer.o detection.o logger.o

nids: $(OBJS)
	$(CXX) $(OBJS) -o nids $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

clean:
	rm -f *.o nids
