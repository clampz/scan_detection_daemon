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
	int *size;

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

	for (i = 0; i <= (table_size - 1); i++) {

		if (equals(key, table_ptr[i]->ip_addr)) return i;

	}

	return -1;

}

struct element *getElement(char *target_name) {

	if (indexOf(target_name) == -1) fatal("hash_t.h 53: index out of range");

	return table_ptr[indexOf(target_name)];

}

void add_element(struct element *new_element) {

	if (table_ptr == NULL) {

		table_size = 1;
		table_ptr = (struct element **) ec_malloc(1);
		table_ptr[0] = new_element;
		return;

	}

	// copy current table to extra table ptr, free table_ptr
	extra_table_ptr = (struct element **)  ec_malloc(table_size);
	memcpy(extra_table_ptr, table_ptr, table_size * sizeof(struct element *));
	free(table_ptr);

	// copy extra table back to current, add new element, and free extra_table_ptr
	table_ptr = (struct element **) ec_malloc(++table_size);
	memcpy(table_ptr, extra_table_ptr, (table_size - 1) * sizeof(struct element *));
	table_ptr[table_size - 1] = new_element;
	free(extra_table_ptr);
	return;

}

void remove_element(struct element *target) {

	int j, i;
	//if (table_ptr == NULL) { printf(); return;}

	// copy current table to extra table ptr, free table_ptr
	*extra_table_ptr = (struct element *)  ec_malloc(table_size);
	memcpy(extra_table_ptr, table_ptr, table_size * sizeof(struct element *));
	free(table_ptr);

	// copy extra table back to current, add new element, and free extra_table_ptr
	*table_ptr = (struct element *) ec_malloc(--table_size);

	printf("table size is: %d\n\n", table_size);

/*
for every element in the new table
check if the name in the current element in the extra table ptr is the same as the name in the target
if it is then ignore it
else copy an element from extra table back
*/

	for (i, j = 0; i < (table_size + 1); i++) {

		if (equals(target->ip_addr, extra_table_ptr[i]->ip_addr)) continue;

		table_ptr[j++] = extra_table_ptr[i];
//		memcpy(table_ptr[j++], extra_table_ptr[i], sizeof(struct element *)); // produces segfault

	}

	free(extra_table_ptr);
	return;


}



