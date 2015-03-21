#include <stdlib.h>
#include <stdio.h>

#include <malloc.h>

#include <libcslob.h>


void print_hex(const char* input, size_t size)
{
	int i; 

	for(i = 0; i < size; i++)	
	{
		printf("%02x", (unsigned int) (unsigned char) input[i]);
	}
}


/**
 * Print command usage to stdout
 */
void print_usage()
{
	printf("Usage: cslob <command>\n\n");
	printf("    info      Inspect SLOB and print basic information\n");
}


/**
 * Handle the "info" command
 */
int command_info(int argc, char** argv)
{
	cslob_file* file = NULL;
	int error;
	int i;

	if(argc != 3)
	{
		printf("Usage: cslob info <filename>\n");
		return EXIT_FAILURE;
	}


	// Open the file
	if(!(file = cslob_open(argv[2], &error)))
	{
		cslob_printerror(error);
		return EXIT_FAILURE;
	} 


	// Print header information
	printf("%s\n", argv[2]);
	printf("---------------------------------------------------------\n\n");

	printf("         id: ");
	print_hex(cslob_get_uuid(file), 16);
	printf("\n");

	printf("   encoding: %s\n", cslob_get_encoding(file));
	printf("compression: %s\n", cslob_get_compression(file));


	// Print tags
	printf("\n\nTAGS\n");
	printf("----\n\n");

	for(i = 0; i < cslob_get_tag_count(file); i++)
	{
		printf("%s : %s\n",
			cslob_get_tag_key(file, i),
			cslob_get_tag_value(file, i));
	}


	// Print content types
	printf("\n\nCONTENT TYPES\n");
	printf("----\n\n");

	for(i = 0; i < cslob_get_content_type_count(file); i++)
	{
		printf("%s\n",
			cslob_get_content_type(file, i));
	}


	// Close file
	cslob_close(file);

	return EXIT_SUCCESS;	
}



/**
 * Main routine
 */
int main(int argc, char** argv)
{
	// Check command line arguments
	if(argc < 2)
	{
		print_usage();
		return EXIT_FAILURE;
	}


	// Handle "info" command
	if(0 == strcmp("info", argv[1], 4))
	{
		return command_info(argc, argv);
	} 



	return EXIT_SUCCESS;
}

