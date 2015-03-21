#ifndef LIBSLOB_H_
#define LIBSLOB_H_

#include <stdint.h>


#define CSLOB_ERR_ALLOC    0
#define CSLOB_ERR_OPEN     1
#define CSLOB_ERR_READ     2
#define CSLOB_ERR_MAGIC    3


struct internal_slob_t;
typedef struct cslob_file_internal cslob_file;

cslob_file* cslob_open(const char* filename, int* error);
void cslob_close(cslob_file* slob);

const char* cslob_get_uuid(const cslob_file* slob);
const char* cslob_get_encoding(const cslob_file* slob);
const char* cslob_get_compression(const cslob_file* slob);

uint32_t cslob_get_tag_count(const cslob_file* slob);
const char* cslob_get_tag_key(const cslob_file* slob, unsigned char index);
const char* cslob_get_tag_value(const cslob_file* slob, unsigned char index);

uint32_t cslob_get_content_type_count(const cslob_file* slob);
const char* cslob_get_content_type(const cslob_file* slob, unsigned char index);

uint32_t    cslob_get_blobcount(const cslob_file* slob);
uint32_t    cslob_get_refcount(const cslob_file* slob);

const char* cslob_errstring(int error);
void cslob_printerror(int error);

#endif
