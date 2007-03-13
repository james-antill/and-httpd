#ifndef BAG_H
#define BAG_H
/* general utilities for C */


#include <vstr.h>
#include "compiler.h"

typedef struct Bag_obj
{
 const char *key;
 void *val;
} Bag_obj;

typedef struct Bag
{
 size_t num;
 size_t sz;
 void (*free_key_func)(void *);
 void (*free_val_func)(void *);

 unsigned int can_resize : 1;

 Bag_obj VSTR__STRUCT_HACK_ARRAY(data);
} Bag;

typedef struct Bag_iter
{
 Bag *bag;
 size_t num;
} Bag_iter;

extern Bag *bag_make(size_t, void (*)(void *), void (*)(void *))
    COMPILE_ATTR_WARN_UNUSED_RET() COMPILE_ATTR_NONNULL_A();
extern void bag_free(Bag *);

extern Bag *bag_add_obj(Bag *, const char *, void *)
    COMPILE_ATTR_WARN_UNUSED_RET() COMPILE_ATTR_NONNULL_L((1));
extern Bag *bag_add_cstr(Bag *, const char *, char *)
    COMPILE_ATTR_WARN_UNUSED_RET() COMPILE_ATTR_NONNULL_L((1));

extern void bag_set_obj(Bag *, size_t, const char *, void *)
    COMPILE_ATTR_NONNULL_L((1));

extern void bag_del(Bag *, unsigned int)
    COMPILE_ATTR_NONNULL_A();
extern void bag_del_all(Bag *);

extern void bag_sort(Bag *, int (*)(const void *, const void *))
     COMPILE_ATTR_NONNULL_A();
extern int bag_cb_sort_key_coll(const void *, const void *)
    COMPILE_ATTR_WARN_UNUSED_RET();
extern int bag_cb_sort_key_case(const void *, const void *)
    COMPILE_ATTR_WARN_UNUSED_RET();
extern int bag_cb_sort_key_vers(const void *, const void *)
    COMPILE_ATTR_WARN_UNUSED_RET();
extern int bag_cb_sort_key_cmp(const void *, const void *)
    COMPILE_ATTR_WARN_UNUSED_RET();

extern const Bag_obj *bag_iter_beg(Bag *, Bag_iter *)
    COMPILE_ATTR_WARN_UNUSED_RET() COMPILE_ATTR_NONNULL_A();
extern const Bag_obj *bag_iter_nxt(Bag_iter *)
    COMPILE_ATTR_WARN_UNUSED_RET() COMPILE_ATTR_NONNULL_A();

extern const Bag_obj *bag_srch_eq(Bag *, Bag_iter *,
                                  int (*)(const Bag_obj *, const void *),
                                  const void *)
    COMPILE_ATTR_WARN_UNUSED_RET() COMPILE_ATTR_NONNULL_L((1, 2, 3));
extern const Bag_obj *bag_sc_srch_eq(Bag *,
                                     int (*)(const Bag_obj *, const void *),
                                     const void *)
    COMPILE_ATTR_WARN_UNUSED_RET() COMPILE_ATTR_NONNULL_L((1, 2));
extern size_t bag_sc_srch_num_eq(Bag *,
                                 int (*)(const Bag_obj *, const void *),
                                 const void *)
    COMPILE_ATTR_WARN_UNUSED_RET() COMPILE_ATTR_NONNULL_L((1, 2));
extern int bag_cb_srch_eq_key_ptr(const Bag_obj *, const void *)
    COMPILE_ATTR_WARN_UNUSED_RET() COMPILE_ATTR_NONNULL_L((1));
extern int bag_cb_srch_eq_val_ptr(const Bag_obj *, const void *)
    COMPILE_ATTR_WARN_UNUSED_RET() COMPILE_ATTR_NONNULL_L((1));

extern void bag_cb_free_nothing(void *);
extern void bag_cb_free_ref(void *);
extern void bag_cb_free_malloc(void *);

#endif
