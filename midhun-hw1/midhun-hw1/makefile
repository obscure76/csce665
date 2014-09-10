all: midhun-session

midhun-session: midhun-session.o 
	g++ midhun-session.o -lpcap -o midhun-session

midhun-session.o: midhun-session.cpp
	g++ -I . -c midhun-session.cpp -lpcap -std=c++11
 
              

