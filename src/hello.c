// hello.c by Bill Weinman <http://bw.org/>
#include <stdio.h>
#include "hash_t.h"

int main( int argc, char ** argv ) {
	
	int a = 6, b = 4;

	struct element one = {((char *) "192.168.1.40"), ((char *) "6"), &a};

	struct element two = {((char *) "192.168.1.22"), ((char *) "3"), &b};

	add_element(&one);

	add_element(&two);

	printf("Hello, World! The index of the element one is: %d\n", indexOf((char *) "192.168.1.40"));


	printf("Hello, World! The index of the element two is: %d\n", indexOf((char *) "192.168.1.22"));

	remove_element(&one);

	printf("Hello, World! The index of the element two is: %d\n", indexOf((char *) "192.168.1.22"));

	return 0;

}

