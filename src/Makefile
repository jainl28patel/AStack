test:
	g++ test.cpp -o test
	if ! iptables -C OUTPUT -p tcp --tcp-flags RST RST -j DROP; then
    	iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
	fi
	sudo ./test hue hue

clean:
	rm -rf test
	clear