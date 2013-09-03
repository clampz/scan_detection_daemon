// hello.c by Bill Weinman <http://bw.org/>
#include <stdio.h>
#include "hash_t.h"

int main( int argc, char ** argv ) {
	
	int a = 6, b = 4, c = 0;

	struct element one = {((char *) "192.168.1.40"), ((char *) "6"), &a, &c};

	struct element two = {((char *) "192.168.1.22"), ((char *) "3"), &b, &c};

	struct element three = {((char *) "152.168.1.32"), ((char *) "8"), &b, &c};

	struct element four = {((char *) "192.168.1.1"), ((char *) "3"), &b, &c};

	add_element(&one);

	add_element(&four);

	add_element(&three);

	add_element(&two);

	printf("2 Hello, World! The index of the element two is: %d\n", indexOf((char *) "192.168.1.22"));

	printf("1 Hello, World! The index of the element four is: %d\n", indexOf((char *) "192.168.1.1"));

	printf("1 Hello, World! The index of the element three is: %d\n", indexOf((char *) "152.168.1.32"));

	printf("1 Hello, World! The index of the element one is: %d\n", indexOf((char *) "192.168.1.40"));

	remove_element(&three);

puts("removed three");

	printf("2 Hello, World! The index of the element four is: %d\n", indexOf((char *) "192.168.1.1"));

	printf("2 Hello, World! The index of the element one is: %d\n", indexOf((char *) "192.168.1.40"));

	printf("2 Hello, World! The index of the element two is: %d\n", indexOf((char *) "192.168.1.22"));

	remove_element(&one);

puts("removed one");

	printf("3 Hello, World! The index of the element two is: %d\n", indexOf((char *) "192.168.1.22"));

	printf("3 Hello, World! The index of the element four is: %d\n", indexOf((char *) "192.168.1.1"));

	return 0;

}

