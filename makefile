default: ttcp

ttcp: ttcp.c
	gcc -Wall -O3 ttcp.c -o ttcp -static

clean:
	rm ttcp.o ttcp



