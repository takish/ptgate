/*
 * FILE:    asarray.c
 *
 * AUTHORS: Orion Hodson
 *
 * Copyright (c) 1999-2000 University College London
 * All rights reserved.
 */
 
#ifndef HIDE_SOURCE_STRINGS
static const char cvsid[] = 
	"$Id: asarray.c,v 1.2 2005/01/20 12:45:06 takashi Exp $";
#endif /* HIDE_SOURCE_STRINGS */

#include <stdio.h>
#include "includes.h"
//#include "config_unix.h"
//#include "config_win32.h"

//#include "debug.h"
//#include "memory.h"
//#include "util.h"

#include "asarray.h"

#define TRUE 1
#define FALSE 0

typedef struct s_hash_tuple {
        unsigned int hash;
        char *key;
        char *value;
        struct s_hash_tuple *next;
} hash_tuple;

#define ASARRAY_SIZE 11

struct _asarray {
        hash_tuple *table[ASARRAY_SIZE];
        int     nitems[ASARRAY_SIZE];
};

PRIVATE unsigned int 
asarray_hash(const char *key)
{
        unsigned int hash = 0;

        while(*key != '\0') {
                hash = hash * 31;
                hash += ((unsigned int)*key) + 1;
                key++;
        }

        return hash;
}

PUBLIC int
asarray_add(asarray *pa, const char *key, const char *value)
{
        hash_tuple *t;
        int row;

        t = (hash_tuple*)malloc(sizeof(hash_tuple));
        if (t) {
                /* transfer values */
                t->hash  = asarray_hash(key);
                t->key   = (char *)strdup(key);
                t->value = (char *)strdup(value);
                /* Add to table */
                row            = t->hash % ASARRAY_SIZE;
                t->next        = pa->table[row];
                pa->table[row] = t;
                pa->nitems[row]++;
                return TRUE;
        }
        return FALSE;
}

PUBLIC void
asarray_remove(asarray *pa, const char *key)
{
        hash_tuple **t, *e;
        unsigned int hash;
        int row;

        hash = asarray_hash(key);
        row  = hash % ASARRAY_SIZE;
        t    = &pa->table[row];
        while((*t) != NULL) {
                if ((hash == (*t)->hash) && 
                    (strcmp(key, (*t)->key) == 0)) {
                        e = *t;
                        *t = e->next;
                        free(e->key);
                        free(e->value);
                        free(e);
                        pa->nitems[row]--;
//                        assert(pa->nitems[row] >= 0);
                        break;
                } else {
                        t = &(*t)->next;
                }
        }
}

const char* 
asarray_get_key_no(asarray *pa, int index)
{
        int row = 0;

        index += 1;
        while (row < ASARRAY_SIZE && index > pa->nitems[row]) {
                index -= pa->nitems[row];
                row++;
        }

        if (row < ASARRAY_SIZE) {
                hash_tuple *t;
                t = pa->table[row];
                while(--index > 0) {
//                        assert(t->next != NULL);
                        t = t->next;
                }
                return t->key;
        }
        return NULL;
}

/* asarray_lookup points value at actual value        */
/* and return TRUE if key found.                      */
PUBLIC int
asarray_lookup(asarray *pa, const char *key, char **value)
{
        hash_tuple *t;
        int          row;
        unsigned int     hash;

        hash = asarray_hash(key);
        row  = hash % ASARRAY_SIZE;

        t = pa->table[row];
        while(t != NULL) {
                if (t->hash == hash && strcmp(key, t->key) == 0) {
                        *value = t->value;
                        return TRUE;
                }
                t = t->next;
        }
        *value = NULL;
        return FALSE;
}

PUBLIC int
asarray_create(asarray **ppa)
{
        asarray *pa;
        pa = (asarray*)malloc(sizeof(asarray));
        if (pa != NULL) {
                memset(pa, 0, sizeof(asarray));
                *ppa = pa;
                return TRUE;
        }
        return FALSE;
}

PUBLIC void
asarray_destroy(asarray **ppa)
{
        asarray    *pa;
        const char *key;

        pa = *ppa;
//        assert(pa != NULL);

        while ((key = asarray_get_key_no(pa, 0)) != NULL) {
                asarray_remove(pa, key);
        }

        free(pa);
        *ppa = NULL;
//        memchk();
}
