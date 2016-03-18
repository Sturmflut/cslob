#ifndef LIBSLOB_H_
#define LIBSLOB_H_

#include <stdint.h>


#define CSLOB_ERR_ALLOC     0
#define CSLOB_ERR_OPEN      1
#define CSLOB_ERR_READ      2
#define CSLOB_ERR_MAGIC     3
#define CSLOB_ERR_TRUNCATED 4


typedef struct cslob_file_internal cslob_file;

typedef struct cslob_result_internal cslob_result;

/**
 * @brief Open a SLOB file, checking basic integrity on the fly.
 */
cslob_file* cslob_open(const char* filename, int* error);


/**
 * @brief Close an open SLOB file
 */
void cslob_close(cslob_file* slob);


/**
 * @brief Return the file UUID
 */
const char* cslob_get_uuid(const cslob_file* slob);


/**
 * @brief Return the file encoding
 */
const char* cslob_get_encoding(const cslob_file* slob);


/**
 * @brief Return blob compression algorithm
 */
const char* cslob_get_compression(const cslob_file* slob);


/**
 * @brief Return the blob count
 */
uint32_t cslob_get_blob_count(const cslob_file* slob);


/**
 * @brief Return the store offset
 */
uint64_t cslob_get_store_offset(const cslob_file* slob);


/**
 * @brief Return the file size
 */
uint64_t cslob_get_file_size(const cslob_file* slob);


/**
 * @brief Return the reference count
 */
uint32_t cslob_get_ref_count(const cslob_file* slob);


/**
 * @brief Return the compressed bin count
 */
uint32_t cslob_get_bin_count(const cslob_file* slob);


/**
 * @brief Get the number of declared tags
 */
uint32_t cslob_get_tag_count(const cslob_file* slob);


/**
 * @brief Get the tag key at the given index
 */
const char* cslob_get_tag_key(const cslob_file* slob, unsigned char index);


/**
 * @brief Get the tag value at the given index
 */
const char* cslob_get_tag_value(const cslob_file* slob, unsigned char index);


/**
 * @brief Get the number of declared content types
 */
uint32_t cslob_get_content_type_count(const cslob_file* slob);


/**
 * @brief Get the content type value at the given index
 */
const char* cslob_get_content_type(const cslob_file* slob, unsigned char index);

/**
 * @brief Find a key
 */
cslob_result* cslob_find(cslob_file* slob, char* term, uint64_t* numresults);


/**
 * @brief Free a list of results returned by cslob_find
 */
void cslob_free_results(cslob_result* results, uint64_t numresults);


/**
 * @brief Get the blob id from a result
 * @param result Search result from a previous call to cslob_find()
 * @return Blob id
 */
uint64_t cslob_result_get_blob_id(const cslob_result* results, uint32_t index);


/**
 * @brief Get the key string from a result
 * @param result Search result from a previous call to cslob_find()
 * @return Key string
 */
const char* cslob_result_get_key(const cslob_result* results, uint32_t index);


/**
 * @brief Decode the given error number into a string
 */
const char* cslob_errstring(int error);


/**
 * @brief Decode the given error number and print an error message
 */
void cslob_printerror(int error);

#endif
