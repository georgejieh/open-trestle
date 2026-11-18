/* Macro-heavy code: what the syntax shows is recorded, the rest is left out. */
#include <linux/module.h>
#include "list.h"

#define DEFINE_OP(name, expr) \
    static int op_##name(int a, int b) { return (expr); }

#define FOR_EACH(i, n) for (int i = 0; i < (n); i++)

DEFINE_OP(add, a + b)
DEFINE_OP(sub, a - b)

MODULE_LICENSE("GPL");
EXPORT_SYMBOL(op_table);
static DEFINE_MUTEX(table_lock);
LIST_HEAD(global_list);

struct op {
    const char *name;
    int (*fn)(int, int);
};

static const struct op op_table[] = {
    { "add", op_add },
    { "sub", op_sub },
};

#ifdef CONFIG_DEBUG
static int debug_level = 1;
#else
static int debug_level = 0;
#endif

int apply(const char *name, int a, int b)
{
    int result = 0;
#ifdef CONFIG_DEBUG
    int traced = debug_level;
#endif
    FOR_EACH(i, 2) {
        int local = i * 2;
        result += local;
    }
    for (unsigned k = 0; k < sizeof(op_table) / sizeof(op_table[0]); k++) {
        if (strcmp(op_table[k].name, name) == 0) {
            return op_table[k].fn(a, b) + result;
        }
    }
    return -1;
}

FOR_EACH(j, 3) {
    int hidden = j;
}

static int __init macros_init(void)
{
    list_add(&global_list, NULL);
    return 0;
}
module_init(macros_init);
