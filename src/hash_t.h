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
	int *size, *count;

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

// searches by ip_addr member
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

// added below at work
		printf("equals(target: %s, extra_table[%d]: %s) = %d", target->ip_addr, i, extra_table_ptr[i]->ip_addr,
			equals(target->ip_addr, extra_table_ptr[i]->ip_addr));

		if (equals(target->ip_addr, extra_table_ptr[i]->ip_addr)) continue;

		table_ptr[j++] = extra_table_ptr[i];
//		memcpy(table_ptr[j++], extra_table_ptr[i], sizeof(struct element *)); // produces segfault

	}

	free(extra_table_ptr);
	return;


}


/*

[20:41][Inspector_Detector@detection-squad:~]$ cd Desktop/stealth_scan_detector/src/
[20:41][Inspector_Detector@detection-squad:~/Desktop/stealth_scan_detector/src]$ gdb -q
(gdb) file hello
Reading symbols for shared libraries .. done
Reading symbols from /Users/Inspector_Detector/Desktop/stealth_scan_detector/src/hello...Reading symbols from /Users/Inspector_Detector/Desktop/stealth_scan_detector/src/hello.dSYM/Contents/Resources/DWARF/hello...done.
done.
(gdb) list main
1	// hello.c by Bill Weinman <http://bw.org/>
2	#include <stdio.h>
3	#include "hash_t.h"
4
5	int main( int argc, char ** argv ) {
6
7		int a = 6, b = 4, c = 0;
8
9		struct element one = {((char *) "192.168.1.40"), ((char *) "6"), &a, &c};
10
(gdb) list main, 60
5	int main( int argc, char ** argv ) {
6
7		int a = 6, b = 4, c = 0;
8
9		struct element one = {((char *) "192.168.1.40"), ((char *) "6"), &a, &c};
10
11		struct element two = {((char *) "192.168.1.22"), ((char *) "3"), &b, &c};
12
13		struct element three = {((char *) "152.168.1.32"), ((char *) "8"), &b, &c};
14
15		struct element four = {((char *) "192.168.1.1"), ((char *) "3"), &b, &c};
16
17		add_element(&one);
18
19		add_element(&four);
20
21		add_element(&three);
22
23		add_element(&two);
24
25		printf("2 Hello, World! The index of the element two is: %d\n", indexOf((char *) "192.168.1.22"));
26
27		printf("1 Hello, World! The index of the element four is: %d\n", indexOf((char *) "192.168.1.1"));
28
29		printf("1 Hello, World! The index of the element three is: %d\n", indexOf((char *) "152.168.1.32"));
30
31		printf("1 Hello, World! The index of the element one is: %d\n", indexOf((char *) "192.168.1.40"));
32
33		remove_element(&three);
34
35	puts("removed three");
36
37		printf("2 Hello, World! The index of the element four is: %d\n", indexOf((char *) "192.168.1.1"));
38
39		printf("2 Hello, World! The index of the element one is: %d\n", indexOf((char *) "192.168.1.40"));
40
41		printf("2 Hello, World! The index of the element two is: %d\n", indexOf((char *) "192.168.1.22"));
42
43		remove_element(&one);
44
45	puts("removed one");
46
47		printf("3 Hello, World! The index of the element two is: %d\n", indexOf((char *) "192.168.1.22"));
48
49		printf("3 Hello, World! The index of the element four is: %d\n", indexOf((char *) "192.168.1.1"));
50
51		return 0;
52
53	}
54
(gdb) break 33
Breakpoint 1 at 0x100001978: file hello.c, line 33.
(gdb) break 43
Breakpoint 2 at 0x1000019ef: file hello.c, line 43.
(gdb) list remove_element
85		free(extra_table_ptr);
86		return;
87
88	}
89
90	void remove_element(struct element *target) {
91
92		int j, i;
93		//if (table_ptr == NULL) { printf(); return;}
94
(gdb) list remove_element, 130
90	void remove_element(struct element *target) {
91
92		int j, i;
93		//if (table_ptr == NULL) { printf(); return;}
94
95		// copy current table to extra table ptr, free table_ptr
96		*extra_table_ptr = (struct element *)  ec_malloc(table_size);
97		memcpy(extra_table_ptr, table_ptr, table_size * sizeof(struct element *));
98		free(table_ptr);
99
100		// copy extra table back to current, add new element, and free extra_table_ptr
101		*table_ptr = (struct element *) ec_malloc(--table_size);
102
103		printf("table size is: %d\n\n", table_size);
104
105
106	for every element in the new table
107	check if the name in the current element in the extra table ptr is the same as the name in the target
108	if it is then ignore it
109	else copy an element from extra table back
110	
111
112		for (i, j = 0; i < (table_size + 1); i++) {
113
114			if (equals(target->ip_addr, extra_table_ptr[i]->ip_addr)) continue;
115
116			table_ptr[j++] = extra_table_ptr[i];
117	//		memcpy(table_ptr[j++], extra_table_ptr[i], sizeof(struct element *)); // produces segfault
118
119		}
120
121		free(extra_table_ptr);
122		return;
123
124
125	}
126
127
128
(gdb) break 111
Breakpoint 3 at 0x100001716: file hash_t.h, line 111.
(gdb) break 125
No line 125 in file "hash_t.h".
(gdb) break 115
Breakpoint 4 at 0x10000174f: file hash_t.h, line 115.
(gdb) break 116
Note: breakpoint 4 also set at pc 0x10000174f.
Breakpoint 5 at 0x10000174f: file hash_t.h, line 116.
(gdb) run
Starting program: /Users/Inspector_Detector/Desktop/stealth_scan_detector/src/hello
Reading symbols for shared libraries +.............................. done
2 Hello, World! The index of the element two is: 3
1 Hello, World! The index of the element four is: 1
1 Hello, World! The index of the element three is: 2
1 Hello, World! The index of the element one is: 0

Breakpoint 1, main (argc=1, argv=0x7fff5fbffac8) at hello.c:33
33		remove_element(&three);
(gdb) print table_ptr[0]
$1 = (struct element *) 0x7fff5fbffa40
(gdb) print table_ptr[1]
$2 = (struct element *) 0x7fff5fbff9e0
(gdb) print table_ptr[2]
$3 = (struct element *) 0x7fff5fbffa00
(gdb) print table_ptr[0]->ip_addr
$4 = 0x100001b84 "192.168.1.40"
(gdb) print table_ptr[1]->ip_addr
$5 = 0x100001bb1 "192.168.1.1"
(gdb) print table_ptr[2]->ip_addr
$6 = 0x100001ba2 "152.168.1.32"
(gdb) print table_ptr[3]->ip_addr
$7 = 0x100001b93 "192.168.1.22"
(gdb) cont
Continuing.
table size is: 3


Breakpoint 3, remove_element (target=0x7fff5fbffa00) at hash_t.h:112
112		for (i, j = 0; i < (table_size + 1); i++) {
(gdb) print table_ptr[0]->ip_addr
$8 = 0x1001000e0 "�"
(gdb) print table_ptr[1]->ip_addr
$9 = 0x100001bb1 "192.168.1.1"
(gdb) print table_ptr[2]->ip_addr
$10 = 0x100001ba2 "152.168.1.32"
(gdb) print table_ptr[3]->ip_addr
$11 = 0x100001b93 "192.168.1.22"
(gdb) cont
Continuing.
removed three
2 Hello, World! The index of the element four is: 1
2 Hello, World! The index of the element one is: -1
2 Hello, World! The index of the element two is: -1

Breakpoint 2, main (argc=1, argv=0x7fff5fbffac8) at hello.c:43
43		remove_element(&one);
(gdb) print table_ptr[0]->ip_addr
$12 = 0x1001000e0 "�"
(gdb) print table_ptr[1]->ip_addr
$13 = 0x100001bb1 "192.168.1.1"
(gdb) print table_ptr[2]->ip_addr
$14 = 0x100001ba2 "152.168.1.32"
(gdb) print table_ptr[3]->ip_addr
$15 = 0x100001b93 "192.168.1.22"
(gdb) quit
The program is running.  Exit anyway? (y or n) y
[21:21][Inspector_Detector@detection-squad:~/Desktop/stealth_scan_detector/src]$

*/
