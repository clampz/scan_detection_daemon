/* malloc_dump.h
 * written by: David Weinman
 * last update: 08/21/13
 * */

/* note: this code was heavily influenced by the book 'Hacking:
 * The Art of Exploitation' by Jon Erikson */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

// A function to display an error message and then exit
void fatal(char *message) {
   char error_message[100];

   strcpy(error_message, "[!!] Fatal Error ");
   strncat(error_message, message, 83);
   perror(error_message);
   exit(-1);
}

// An error checked malloc() wrapper function
void *ec_malloc(unsigned int size) {
   void *ptr;
   ptr = malloc(size);
   if(ptr == NULL)
      fatal("in ec_malloc() on memory allocation");
   return ptr;
}

// dumps raw memory in hex byte and printable split format
void dump(const unsigned char *data_buffer, const unsigned int length) {
	unsigned char byte;
	unsigned int i, j;
	for(i=0; i < length; i++) {
		byte = data_buffer[i];
		printf("%02x ", data_buffer[i]);  // display byte in hex
		if(((i%16)==15) || (i==length-1)) {
			for(j=0; j < 15-(i%16); j++)
				printf("   ");
			printf("| ");
			for(j=(i-(i%16)); j <= i; j++) {  // display printable bytes from line
				byte = data_buffer[j];
				if((byte > 31) && (byte < 127)) // outside printable char range
					printf("%c", byte);
				else
					printf(".");
			}
			printf("\n"); // end of the dump line (each line 16 bytes)
		} // end if
	} // end for
}

/* This function is a printf styled wrapper function for my use of file
 * descriptors in global & main in the scan detection daemon.
*/
int fdprintf ( int fd, size_t bufmax, const char * fmt, ... ) {

	char * buffer;
	int n;
	va_list ap;

	buffer = ( char * ) malloc ( bufmax );
	if ( !buffer )
		return 0;

	va_start ( ap, fmt );
	n = vsnprintf ( buffer, bufmax, fmt, ap );
	va_end ( ap );

	write ( fd, buffer, n );
	free ( buffer );
	return n;

}

// returns 0 if the strings that str1 and str2 point to are not the same.
int equals(char * str1, char * str2) {

	while (*str1 == *str2) {
		str1++;
		str2++;
		if ((*str1 == '\0') && (*str2 == '\0')) return 1;
	}
	return 0;

}

/* This function writes a timestamp string to the open file descriptor
 * passed to it.
 */
void timestamp(int fd) {

	time_t now;
	struct tm *time_struct;
	int length;
	char time_buffer[40];

	time(&now);  // get number of seconds since epoch
	time_struct = localtime((const time_t *)&now); // convert to tm struct
	length = strftime(time_buffer, 40, "%m/%d/%Y %H:%M:%S> ", time_struct);
	write(fd, time_buffer, length); // write timestamp string to log

}

/* This function accepts an open file descriptor and returns
 * the size of the associated file. Returns -1 on failure.
 */
int get_file_size(int fd) {

	struct stat stat_struct;

	if(fstat(fd, &stat_struct) == -1)
		return -1;

	return (int) stat_struct.st_size;

}

