#include <stdio.h>

#include <string.h>

#include <malloc.h>

#include <unicode/ucol.h>

#include "libcslob.h"


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

struct cslob_ref {
    char* key;

    uint32_t bin_index;
    uint16_t item_index;

    char* fragment;
};


struct cslob_file_internal {
    FILE*        file;
    char         uuid[17];
    cslob_string encoding;
    cslob_string compression;

    struct cslob_tags tags;
    struct cslob_content_types content_types;

    uint32_t  blob_count;
    uint64_t  store_offset;
    uint64_t  file_size;
    size_t    ref_offset;
    uint32_t  ref_count;
};


struct cslob_result_internal {
    char* key;
    uint64_t blob_id;
};



// Header magic constant
const static char CONST_MAGIC[8] = { 0x21, 0x2d, 0x31, 0x53, 0x4c, 0x4f, 0x42, 0x1f };


// Error messages
#define CONST_ERRSTRING_COUNT	5

const static char* CONST_ERRSTRING[CONST_ERRSTRING_COUNT] = {
    "calloc() failed",
    "fopen() failed",
    "fread() failed",
    "header magic not found",
    "truncated file"
};


/**
 * Convert byte ordering, if necessary
 */
static void convert_be_to_local(char* buffer, size_t length)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    CSLOB_DEBUG("convert_be_to_local has to convert!\n");

    size_t i;
    char tmp;

    for(i = 0; i < (length / 2); i++)
    {
        tmp = buffer[i];
        buffer[i] = buffer[length - 1 - i];
        buffer[length - 1 - i] = tmp;
    }
#endif
}


/**
 * @brief Return the minimum of two integers
 * @param a Integer A
 * @param b Integer B
 * @return Minimum of A and B
 */
static int inline min(int a, int b)
{
    if(a < b)
        return a;

    return b;
}


/**
 * Read a sequence of bytes into the buffer. In contrast to fread(3), cslob_read
 * will only return if all bytes have been read or an actual error occured.
 *
 * @return 1 on success, 0 on error
 */
static char cslob_read(FILE* file, void* buffer, size_t count)
{
    char* curp = (char *)buffer;
    size_t retval;
    size_t bytes_read = 0;

    CSLOB_DEBUG("cslob_read, offset %li, count = %li\n", ftell(file), count);

    if(0 == count)
        return 1;

    // Loop until all data is read or an error occurs
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
 * Read a string field (char-sized length field and content) from the
 * given file into the pre-allocated buffer
 *
 * @return 1 on success, 0 on error
 */
static int cslob_read_stringc(FILE* file, char* string)
{
    unsigned char string_len;

    CSLOB_DEBUG("cslob_read_stringc, read length\n");
    if(!cslob_read(file, &string_len, 1))
        return 1;

    CSLOB_DEBUG("cslob_read_stringc, length = %i\n", string_len);

    if(string_len > 0)
    {
        CSLOB_DEBUG("cslob_read_stringc, read string\n");
        if(!cslob_read(file, (char *) string, string_len))
            return 0;
    }

    return 1;
}


/**
 * Read a string field (char-sized length field and content) from the
 * given file into a newly allocated buffer
 *
 * @return 1 on success, 0 on error
 */
static char* cslob_read_astringc(FILE* file)
{
    unsigned char string_len;
    char* p;

    CSLOB_DEBUG("cslob_read_astringc, read length\n");
    if(!cslob_read(file, &string_len, 1))
        return NULL;

    CSLOB_DEBUG("cslob_read_astringc, allocate size %i\n", string_len + 1);
    p = (char *) calloc(1, string_len + 1);

    if(!p)
        return NULL;

    CSLOB_DEBUG("cslob_read_astringc, read string\n");
    if(!cslob_read(file, p, string_len))
        return NULL;

    return p;
}


/**
 * Read a string field (short-sized length field and content) from the
 * given file into a newly allocated buffer
 *
 * @return 1 on success, 0 on error
 */
static char* cslob_read_astrings(FILE* file)
{
    uint16_t string_len;
    char* p;

    CSLOB_DEBUG("cslob_read_astrings, read length\n");
    if(!cslob_read(file, &string_len, 2))
        return NULL;

    convert_be_to_local((char *) &(string_len), sizeof(string_len));

    CSLOB_DEBUG("cslob_read_astrings, allocate size %i\n", string_len + 1);
    p = (char *) calloc(1, string_len + 1);

    if(!p)
        return NULL;

    CSLOB_DEBUG("cslob_read_astrings, read string\n");
    if(!cslob_read(file, p, string_len))
        return NULL;

    return p;
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
 * @brief Read the sequence of tags
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

        if(!cslob_read_stringc(file, (char *) &tags->keys[i])
                || !cslob_read_stringc(file, (char *) &tags->values[i]))
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
 * @brief Read the sequence of content types
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
        if(!cslob_read_stringc(file, (char *) &types->values[i]))
        {
            cslob_free_content_types(types);

            return 0;
        }
    }


    return 1;
}


/**
 * @brief Free a reference entry
 * @param ref Pointer to the reference
 */
static void cslob_free_ref(struct cslob_ref* ref)
{
    if(ref)
    {
        if(ref->key)
            free(ref->key);

        if(ref->fragment)
            free(ref->fragment);
    }
}


/**
 * @brief Load a single ref
 *
 * @return 0 on error, 1 on success
 */
static struct cslob_ref* cslob_read_ref(cslob_file* slob, uint64_t index)
{
    uint64_t ref_offset = 0;


    if(!slob)
        return 0;


    // Allocate memory
    struct cslob_ref* ref = calloc(1, sizeof(struct cslob_ref));

    if(!ref)
        return NULL;


    CSLOB_DEBUG("cslob_load_ref, index = %li\n", index);


    // Seek to the start of the references
    CSLOB_DEBUG("cslob_load_refs, seeking to %li\n", slob->ref_offset);
    fseek(slob->file, slob->ref_offset, SEEK_SET);


    // Seek to the reference
    CSLOB_DEBUG("cslob_load_refs, seeking to lookup entry at offset %li\n", index * sizeof(uint64_t));
    fseek(slob->file, index * sizeof(uint64_t), SEEK_CUR);


    // Read the true offset of the reference
    cslob_read(slob->file, &ref_offset, 8);
    convert_be_to_local((char*) &ref_offset, sizeof(ref_offset));


    // Seek to the actual reference entry
    CSLOB_DEBUG("cslob_load_refs, seeking to true reference at offset %li\n", slob->ref_offset + (slob->ref_count * 8) + ref_offset);
    fseek(slob->file, slob->ref_offset + (slob->ref_count * 8) + ref_offset, SEEK_SET);

    if(!(ref->key = cslob_read_astrings(slob->file))
            || !cslob_read(slob->file, &(ref->bin_index), 4)
            || !cslob_read(slob->file, &(ref->item_index), 2)
            || !(ref->fragment = cslob_read_astringc(slob->file)))
    {
        cslob_free_ref(ref);

        return NULL;
    }

    // Convert numbers
    convert_be_to_local((char *) &(ref->bin_index), sizeof(ref->bin_index));
    convert_be_to_local((char *) &(ref->item_index), sizeof(ref->item_index));


    return ref;
}


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
    if(!cslob_read_stringc(tmp_slob->file, tmp_slob->encoding))
    {
        *error = CSLOB_ERR_READ;

        free(tmp_slob);

        return NULL;
    }


    // Read the compression
    CSLOB_DEBUG("Reading compression\n");
    if(!cslob_read_stringc(tmp_slob->file, tmp_slob->compression))
    {
        *error = CSLOB_ERR_READ;

        free(tmp_slob);

        return NULL;
    }


    // Read the tags
    CSLOB_DEBUG("Reading tags\n");
    if(!cslob_read_tags(tmp_slob->file, &tmp_slob->tags))
    {
        *error = CSLOB_ERR_READ;

        cslob_free_tags(&tmp_slob->tags);
        free(tmp_slob);

        return NULL;
    }


    // Read the content types
    CSLOB_DEBUG("Reading content types\n");
    if(!cslob_read_content_types(tmp_slob->file, &tmp_slob->content_types))
    {
        *error = CSLOB_ERR_READ;

        cslob_free_tags(&tmp_slob->tags);
        cslob_free_content_types(&tmp_slob->content_types);
        free(tmp_slob);

        return NULL;
    }


    // Read the blob count
    CSLOB_DEBUG("Reading blob count\n");
    if(!cslob_read(tmp_slob->file, &tmp_slob->blob_count, 4))
    {
        *error = CSLOB_ERR_READ;

        cslob_free_tags(&tmp_slob->tags);
        cslob_free_content_types(&tmp_slob->content_types);
        free(tmp_slob);

        return NULL;
    }

    convert_be_to_local((char *) &tmp_slob->blob_count, sizeof(tmp_slob->blob_count));


    // Read the store offset
    CSLOB_DEBUG("Reading store offset\n");
    if(!cslob_read(tmp_slob->file, &tmp_slob->store_offset, 8))
    {
        *error = CSLOB_ERR_READ;

        cslob_free_tags(&tmp_slob->tags);
        cslob_free_content_types(&tmp_slob->content_types);
        free(tmp_slob);

        return NULL;
    }

    convert_be_to_local((char *) &tmp_slob->store_offset, sizeof(tmp_slob->store_offset));


    // Read the file size
    CSLOB_DEBUG("Reading file size\n");
    if(!cslob_read(tmp_slob->file, &tmp_slob->file_size, 8))
    {
        *error = CSLOB_ERR_READ;

        cslob_free_tags(&tmp_slob->tags);
        cslob_free_content_types(&tmp_slob->content_types);
        free(tmp_slob);

        return NULL;
    }

    convert_be_to_local((char *) &(tmp_slob->file_size), sizeof(tmp_slob->file_size));


    // Check file size
    CSLOB_DEBUG("Checking file size\n");
    int old_pos = ftell(tmp_slob->file);

    fseek(tmp_slob->file, 0, SEEK_END);
    int file_size = ftell(tmp_slob->file);

    fseek(tmp_slob->file, old_pos, SEEK_SET);

    if(file_size < tmp_slob->file_size)
    {
        CSLOB_DEBUG("file_size (%i) < tmp_slob->file_size (%li)\n",
                    file_size,
                    tmp_slob->file_size);

        *error = CSLOB_ERR_TRUNCATED;

        cslob_free_tags(&tmp_slob->tags);
        cslob_free_content_types(&tmp_slob->content_types);
        free(tmp_slob);

        return NULL;
    }


    // Read the reference count
    CSLOB_DEBUG("Reading reference count\n");
    if(!cslob_read(tmp_slob->file, &tmp_slob->ref_count, 4))
    {
        *error = CSLOB_ERR_READ;

        cslob_free_tags(&tmp_slob->tags);
        cslob_free_content_types(&tmp_slob->content_types);
        free(tmp_slob);

        return NULL;
    }

    convert_be_to_local((char *) &tmp_slob->ref_count, sizeof(tmp_slob->ref_count));


    // Store ref offset
    tmp_slob->ref_offset = ftell(tmp_slob->file);


    return tmp_slob;
}


void cslob_close(cslob_file* slob)
{
    if(slob)
    {
        fclose(slob->file);

        cslob_free_content_types(&(slob->content_types));
        cslob_free_tags(&(slob->tags));

        free(slob);
    }
}


const char* cslob_get_uuid(const cslob_file* slob)
{
    if(slob)
        return slob->uuid;

    return NULL;
}


const char* cslob_get_encoding(const cslob_file* slob)
{
    if(slob)
        return (char *) slob->encoding;

    return NULL;
}


const char* cslob_get_compression(const cslob_file* slob)
{
    if(slob)
        return (char *) slob->compression;

    return NULL;
}


uint32_t cslob_get_tag_count(const cslob_file* slob)
{
    if(slob)
        return slob->tags.count;

    return 0;
}


/**
 * @brief Get the tag key at the given index
 */
const char* cslob_get_tag_key(const cslob_file* slob, unsigned char index)
{
    if(slob)
        if(index >= 0 && index < slob->tags.count)
            return (char *) slob->tags.keys[index];

    return NULL;
}


const char* cslob_get_tag_value(const cslob_file* slob, unsigned char index)
{
    if(slob)
        if(index >= 0 && index < slob->tags.count)
            return (char *) slob->tags.values[index];

    return NULL;
}


uint32_t cslob_get_content_type_count(const cslob_file* slob)
{
    if(slob)
        return slob->content_types.count;

    return 0;
}


const char* cslob_get_content_type(const cslob_file* slob, unsigned char index)
{
    if(slob)
        if(index >= 0 && index < slob->content_types.count)
            return (char *) slob->content_types.values[index];

    return NULL;
}


uint32_t cslob_get_blob_count(const cslob_file* slob)
{
    if(slob)
        return slob->blob_count;

    return 0;
}


uint64_t cslob_get_store_offset(const cslob_file* slob)
{
    if(slob)
        return slob->store_offset;

    return 0;
}


uint64_t cslob_get_file_size(const cslob_file* slob)
{
    if(slob)
        return slob->file_size;

    return 0;
}


uint32_t cslob_get_ref_count(const cslob_file* slob)
{
    if(slob)
        return slob->ref_count;

    return 0;
}


cslob_result* cslob_find(cslob_file* slob, char* term, uint64_t* numresults)
{
    uint64_t i;
    uint64_t cur;

    char* markers = NULL;


    if(!slob)
        return NULL;


    CSLOB_DEBUG("cslob_find, term = \"%s\"\n", term);


    // Allocate collator
    UErrorCode status = U_ZERO_ERROR;
    UCollator *coll = ucol_open("en_US", &status);
    ucol_setAttribute(coll, UCOL_STRENGTH, UCOL_PRIMARY, &status);

    if(!U_SUCCESS(status))
    {
        CSLOB_DEBUG("cslob_find, ICU collator not initialized\n");

        return NULL;
    }



    // Allocate memory for the markers
    markers = (char*) calloc(1, slob->ref_count * sizeof(char));

    if(!markers)
    {
        return NULL;
    }


    // Walk through all the refs and mark which fit the term
    *numresults = 0;
    for(i = 0; i < slob->ref_count; i++)
    {
        struct cslob_ref* ref = cslob_read_ref(slob, i);

        if(!ref)
            return NULL;


        CSLOB_DEBUG("cslob_find ref->key = \"%s\", ref->bin_index = %i, ref->item_index = %i, ref->fragment = \"%s\"\n",
                    ref->key,
                    ref->bin_index,
                    ref->item_index,
                    ref->fragment);

        // Find minimum length
        int len = min(strlen(term), strlen(ref->key));


        if(ucol_strcollUTF8(coll, term, len, ref->key, len, &status) == UCOL_EQUAL)
        {
            CSLOB_DEBUG("cslob_find found a match!\n");

            markers[i] = 1;
            (*numresults)++;
        }

        cslob_free_ref(ref);
    }


    // Close the collator
    ucol_close(coll);


    // Build the result list from the markers

    // Allocate memory
    cslob_result* results = (cslob_result*) calloc(*numresults, sizeof(cslob_result));

    if(!results)
    {
        free(markers);
        *numresults = 0;
        return NULL;
    }


    // Re-read the matching refs
    cur = 0;
    for(i = 0; i < slob->ref_count; i++)
    {
        if(markers[i])
        {
            struct cslob_ref* ref = cslob_read_ref(slob, i);

            if(!ref)
            {
                cslob_free_results(results, *numresults);
                *numresults = 0;
                return NULL;
            }

            // Recycle the existing string!
            results[cur].key = ref->key;
            results[cur].blob_id = (ref->bin_index << 16) + ref->item_index;

            // Free only the fragement and the struct, not the key
            free(ref->fragment);
            free(ref);

            cur++;
        }
    }


    // Free markers
    free(markers);

    // Return results
    return results;
}


void cslob_free_results(cslob_result* results, uint64_t numresults)
{
    uint64_t i;

    if(results)
    {
        // Free the key strings
        for(i = 0; i < numresults; i++)
            if(results[i].key)
                free(results[i].key);

        free(results);
    }
}


uint64_t cslob_result_get_blob_id(const cslob_result* result, uint32_t index)
{
    if(result)
        return result[index].blob_id;

    return 0;
}


const char* cslob_result_get_key(const cslob_result* result, uint32_t index)
{
    if(result)
        return result[index].key;

    return NULL;
}


const char* cslob_errstring(int error)
{
    if(error >= 0 && error < CONST_ERRSTRING_COUNT)
        return CONST_ERRSTRING[error];

    return NULL;
}


void cslob_printerror(int error)
{
    printf("cslob error: %s\n", cslob_errstring(error));
}
