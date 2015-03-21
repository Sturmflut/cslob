#include <stdio.h>

#include <string.h>

#include <malloc.h>

#include <libcslob.h>

#ifdef DEBUG
	#define CSLOB_DEBUG(x, ...) printf(x, ## __VA_ARGS__)
#else
	#define CSLOB_DEBUG(x, ...)
#endif


// Internal SLOB file data structures
typedef char cslob_string[256];

struct cslob_content_types {
	unsigned char count;

	cslob_string* values;
};

struct cslob_tags {
	unsigned char count;

	cslob_string* keys;
	cslob_string* values;
};


struct cslob_file_internal {
	FILE*     file;
	char      uuid[17];
	cslob_string encoding[256];
	cslob_string compression[256];

	struct cslob_tags tags;
	struct cslob_content_types content_types;

	uint32_t  blobcount;
	uint32_t  refcount;
};


// Header magic constant
const static char CONST_MAGIC[8] = { 0x21, 0x2d, 0x31, 0x53, 0x4c, 0x4f, 0x42, 0x1f };


// Error messages
#define CONST_ERRSTRING_COUNT	4

const static char* CONST_ERRSTRING[CONST_ERRSTRING_COUNT] = {
	"calloc() failed",
	"fopen() failed",
	"fread() failed",
	"header magic not found"
};


/**
 * Read a sequence of bytes into the buffer. In contrast to fread(3), cslob_read
 * will only return if all bytes have been read or an actual error occured.
 *
 * @return 1 on success, 0 on error
 */
static char cslob_read(FILE* file, char* buffer, size_t count)
{
	char* curp = buffer;
	size_t retval;
	int i;
	size_t bytes_read = 0;

	CSLOB_DEBUG("cslob_read, count = %li\n", count);

	while((count - bytes_read) > 0
		&& (retval = fread((void* ) curp, 1, count - bytes_read, file)) > 0)
	{
		CSLOB_DEBUG("cslob_read, retval = %li\n", retval);
		
		curp += retval;
		bytes_read += retval;
	}

	if(0 == retval)
	{
		CSLOB_DEBUG("cslob_read, retval = 0\n");
		return 0;
	}

	return 1;
}


/**
 * Read a string field (length field and content) from the given file
 *
 * @return 1 on success, 0 on error
 */
static int cslob_read_string(FILE* file, cslob_string* string)
{
	unsigned char string_len;

	CSLOB_DEBUG("cslob_read_string, read length\n");
	if(!cslob_read(file, &string_len, 1))
		return 1;

	CSLOB_DEBUG("cslob_read_string, read string\n");
	if(!cslob_read(file, (char *) string, string_len))
		return 0;

	return 1;
}


/**
 * Free all memory allocated for tags
 */
static void cslob_free_tags(struct cslob_tags* tags)
{
	if(tags)
	{
		if(tags->keys)
			free(tags->keys);

		if(tags->values)
			free(tags->values);
	}
}


/**
 * Read the sequence of tags
 * 
 * @return 1 on success, 0 on error
 */
static int cslob_read_tags(FILE* file, struct cslob_tags* tags)
{
	int i;
	
	CSLOB_DEBUG("cslob_read_tags\n");

	// Read the number of tags
	if(!cslob_read(file, &tags->count, 1))
	{
		return 0;
	}

	CSLOB_DEBUG("cslob_read_tags, tags->count = %i\n", tags->count);


	// Allocate memory for keys
	tags->keys = (cslob_string*) calloc(tags->count, sizeof(cslob_string));

	if(!tags->keys)
		return 0;


	// Allocate memory for values
	tags->values = (cslob_string*) calloc(tags->count, sizeof(cslob_string));

	if(!tags->values)
	{
		cslob_free_tags(tags);
		return 0;
	}


	// Read keys and values
	for(i = 0; i < tags->count; i++)
	{
		CSLOB_DEBUG("cslob_read_tags, reading key/value pair %i\n", i);

		if(!cslob_read_string(file, &tags->keys[i])
			|| !cslob_read_string(file, &tags->values[i]))
		{
			cslob_free_tags(tags);

			return 0;
		}
	}


	return 1;
}


/**
 * Free all memory allocated for content types
 */
static void cslob_free_content_types(struct cslob_content_types* types)
{
	if(types)
	{
		if(types->values)
			free(types->values);
	}
}


/**
 * Read the sequence of content types 
 * 
 * @return 1 on success, 0 on error
 */
static int cslob_read_content_types(FILE* file, struct cslob_content_types* types)
{
	int i;
	char unknown;

	CSLOB_DEBUG("cslob_read_content_types\n");

	// Read the number of content types
	if(!cslob_read(file, &types->count, 1))
	{
		return 0;
	}

	CSLOB_DEBUG("cslob_read_content_types, types->count = %i\n", types->count);


	// Allocate memory for values
	types->values = (cslob_string*) calloc(types->count, sizeof(cslob_string));

	if(!types->values)
	{
		return 0;
	}


	// Read values
	for(i = 0; i < types->count; i++)
	{
		// There seems to be an unknown zero byte in front of every actual length byte?
		if(!cslob_read(file, &unknown, 1))
		{
			return 0;
		}

		// Read the string
		if(!cslob_read_string(file, &types->values[i]))
		{
			cslob_free_content_types(types);

			return 0;
		}
	}


	return 1;
}


/**
 * Open a SLOB file, checking basic integrity on the fly.
 */
cslob_file* cslob_open(const char* filename, int* error)
{
	// Allocate internal data structure
	cslob_file* tmp_slob = (cslob_file*) calloc(1, sizeof(cslob_file));

	// Allocation failed
	if(!tmp_slob)
	{
		*error = CSLOB_ERR_ALLOC;
		return NULL;
	}


	// Open the file
	tmp_slob->file = fopen(filename, "r");

	if(!tmp_slob->file)
	{
		*error = CSLOB_ERR_OPEN;

		free(tmp_slob);

		return NULL;
	}


	// Check magic
	char magic_buffer[9];

	if(!cslob_read(tmp_slob->file, (char *) &magic_buffer, 8))
	{
		*error = CSLOB_ERR_READ;

		free(tmp_slob);

		return NULL;
	}

	if(0 != memcmp(&magic_buffer, &CONST_MAGIC, 8))
	{
		*error = CSLOB_ERR_MAGIC;

		free(tmp_slob);

		return NULL;
	}


	// Read the UUID
	if(!cslob_read(tmp_slob->file, tmp_slob->uuid, 16))
	{
		*error = CSLOB_ERR_READ;

		free(tmp_slob);

		return NULL;
	}


	// Read the encoding
	CSLOB_DEBUG("Reading encoding\n");
	if(!cslob_read_string(tmp_slob->file, tmp_slob->encoding))
	{
		*error = CSLOB_ERR_READ;

		free(tmp_slob);

		return NULL;
	}


	// Read the compression
	CSLOB_DEBUG("Reading compression\n");
	if(!cslob_read_string(tmp_slob->file, tmp_slob->compression))
	{
		*error = CSLOB_ERR_READ;

		free(tmp_slob);

		return NULL;
	}


	// Read the tags
	if(!cslob_read_tags(tmp_slob->file, &tmp_slob->tags))
	{
		*error = CSLOB_ERR_READ;

		cslob_free_tags(&tmp_slob->tags);
		free(tmp_slob);

		return NULL;
	}


	// Read the content types
	if(!cslob_read_content_types(tmp_slob->file, &tmp_slob->content_types))
	{
		*error = CSLOB_ERR_READ;

		cslob_free_content_types(&tmp_slob->content_types);
		free(tmp_slob);

		return NULL;
	}
	

	return tmp_slob;
}


void cslob_close(cslob_file* slob)
{
	if(slob)
	{
		fclose(slob->file);

		free(slob);
	}

}


/**
 * Return the file UUID
 */
const char* cslob_get_uuid(const cslob_file* slob)
{
	if(slob)
		return slob->uuid;
}


/**
 * Return the file encoding
 */
const char* cslob_get_encoding(const cslob_file* slob)
{
	if(slob)
		return (char *) slob->encoding;
}


/**
 * Return blob compression algorithm
 */
const char* cslob_get_compression(const cslob_file* slob)
{
	if(slob)
		return (char *) slob->compression;
}


/**
 * Get the number of declared tags
 */
uint32_t cslob_get_tag_count(const cslob_file* slob)
{
	if(slob)
		return slob->tags.count;
}


/**
 * Get the tag key at the given index
 */
const char* cslob_get_tag_key(const cslob_file* slob, unsigned char index)
{
	if(slob)
		if(index >= 0 && index < slob->tags.count)
			return (char *) slob->tags.keys[index];	
}


/**
 * Get the tag value at the given index
 */
const char* cslob_get_tag_value(const cslob_file* slob, unsigned char index)
{
	if(slob)
		if(index >= 0 && index < slob->tags.count)
			return (char *) slob->tags.values[index];	
}


/**
 * Get the number of declared content types
 */
uint32_t cslob_get_content_type_count(const cslob_file* slob)
{
	if(slob)
		return slob->content_types.count;
}


/**
 * Get the content type value at the given index
 */
const char* cslob_get_content_type(const cslob_file* slob, unsigned char index)
{
	if(slob)
		if(index >= 0 && index < slob->content_types.count)
			return (char *) slob->content_types.values[index];	
}


/**
 * Return the blob count
 */
uint32_t cslob_get_blobcount(const cslob_file* slob)
{
	if(slob)
		return slob->blobcount;
}


/**
 * Return the reference count
 */
uint32_t cslob_get_refcount(const cslob_file* slob)
{
	if(slob)
		return slob->refcount;
}


/**
 * Decode the given error number into a string
 */
const char* cslob_errstring(int error)
{
	if(error >= 0 && error < CONST_ERRSTRING_COUNT)
		return CONST_ERRSTRING[error];
}


/**
 * Decode the given error number and print an error message
 */
void cslob_printerror(int error)
{
	printf("cslob error: %s\n", cslob_errstring(error));
}

