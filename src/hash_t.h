/* hash_t.h
 * written by: David Weinman
 * last update: 09/01/13
 * */


/*

add elements, remove elements, search by key, get element


*/

#include <stdlib.h> // free
#include <string.h> // memcpy
#include "malloc_dump.h" // ec_malloc, fatal, equals 


struct element {

	char *ip_addr, *type;
	int size;

};

// -- global vars

int table_size;

struct element **extra_table_ptr;
struct element **table_ptr;

// -- prototypes

void add_element(struct element*);
void remove_element(struct element*);
int indexOf(char *);
struct element *getElement(char *);

// -- definitions

int indexOf(char *key) {

	int i;

	for (i = 0; i < table_size; i++) {

		if (equals(key, *table_ptr[i])) return i;

	}

	return -1;

}

struct element *getElement(char *target_name) {

	if (indexOf(target_name) == -1) fatal("hash_t.h 53: index out of range");

	return *table_ptr[indexOf(target_name)];

}

void add_element(struct element *new_element) {

	if (table_ptr == NULL) {

		table_size = 1;
		table_ptr = (struct element *) malloc(1);
		*table_ptr[0] = new_element;
		return;

	}

	// copy current table to extra table ptr, free table_ptr
	extra_table_ptr = (struct element *)  ec_malloc(table_size);
	memcpy(table_ptr, extra_table_ptr, table_size * sizeof(struct element *));
	free(table_ptr);

	// copy extra table back to current, add new element, and free extra_table_ptr
	table_ptr = (struct element *) ec_malloc(++table_size);
	memcpy(extra_table_ptr, table_ptr, table_size * sizeof(struct element *));
	*table_ptr[table_size - 1] = new_element;
	free(extra_table_ptr);
	return;

}

void remove_element(struct element *target) {

	int i;
	//if (table_ptr == NULL) { printf(); return;}

	// copy current table to extra table ptr, free table_ptr
	extra_table_ptr = (struct element *)  ec_malloc(table_size);
	memcpy(table_ptr, extra_table_ptr, table_size * sizeof(struct element *));
	free(table_ptr);

	// copy extra table back to current, add new element, and free extra_table_ptr
	table_ptr = (struct element *) ec_malloc(--table_size);

/*
for every element in the new table
check if the name in the current element in the extra table ptr is the same as the name in the target
if it is then ignore it
else copy an element from extra table back
*/
	for (i = 0; i < table_size; i++) {

		if (equals(target->ip_addr, *extra_table_ptr[i]->ip_addr)) continue;
		*table_ptr[i] = *extra_table_ptr[i];

	}

	free(extra_table_ptr);
	return;


}

/* DEBUG:

[05:12][Inspector_Detector@detection-squad:~/Desktop/stealth_scan_detector/src]$ cat hello.c
// hello.c by Bill Weinman <http://bw.org/>
#include <stdio.h>
#include "hash_t.h"

int main( int argc, char ** argv ) {
	printf("Hello, World!\n");
	return 0;
}
[05:13][Inspector_Detector@detection-squad:~/Desktop/stealth_scan_detector/src]$


[05:12][Inspector_Detector@detection-squad:~/Desktop/stealth_scan_detector/src]$ gcc -o hello hello.c
In file included from hello.c:3:
hash_t.h: In function ‘indexOf’:
hash_t.h:48: error: incompatible type for argument 2 of ‘equals’
hash_t.h: In function ‘getElement’:
hash_t.h:60: error: incompatible types in return
hash_t.h: In function ‘add_element’:
hash_t.h:69: warning: assignment from incompatible pointer type
hash_t.h:70: error: incompatible types in assignment
hash_t.h:76: warning: assignment from incompatible pointer type
hash_t.h:81: warning: assignment from incompatible pointer type
hash_t.h:83: error: incompatible types in assignment
hash_t.h: In function ‘remove_element’:
hash_t.h:95: warning: assignment from incompatible pointer type
hash_t.h:100: warning: assignment from incompatible pointer type
hash_t.h:110: warning: passing argument 2 of ‘equals’ makes pointer from integer without a cast
[05:12][Inspector_Detector@detection-squad:~/Desktop/stealth_scan_detector/src]$




*/

