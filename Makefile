all: tcp_block

tcp_block: tcp_block.cpp
	gcc -o tcp_block tcp_block.cpp -lpcap

clean:
	rm -f tcp_block
