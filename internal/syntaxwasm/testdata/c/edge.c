#include <stdarg.h>

typedef struct {
    int x, y;
} point_t, *point_ptr;

typedef union value {
    long l;
    double d;
    struct {
        int lo;
        int hi;
    } parts;
} value_t;

struct list {
    struct list *next;
    void (*visit)(struct list *self, void *ctx);
    char name[16];
    int (*table[4])(int);
};

enum flags { F_NONE = 0, F_READ = 1 << 0, F_WRITE = 1 << 1 };

typedef int (*handler_fn)(int);
typedef char buffer_t[64];

static int counters[8], total = 0, *last;
const double ratio = 0.5;
static const char *const greetings[] = { "hi", "hello" };
const char *mutable_text = "x";
char *const fixed_ptr = 0;
extern int (*callback)(int);
volatile int ticks;

int (*select_handler(int id))(int);
int (*select_handler(int id))(int)
{
    return 0;
}

static inline long scale(long v, ...)
{
    va_list ap;
    va_start(ap, v);
    va_end(ap);
    return v * 2;
}

void visit_all(struct list *head, void *ctx)
{
    static int calls;
    struct list *cur = head;
    point_t p = { .x = 1, .y = 2 };
    value_t v = (value_t){ .l = 3 };
    while (cur) {
        cur->visit(cur, ctx);
        (*cur->table[0])(p.x);
        calls++;
        cur = cur->next;
    }
    (void)v;
}

__attribute__((noreturn)) void fatal(const char *msg);
[[nodiscard]] int checked(void);

int old_style(a, b)
    int a;
    int b;
{
    return a + b;
}
