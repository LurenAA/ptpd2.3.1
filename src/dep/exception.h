#ifndef EXCEPTION_INCLUDE
#define EXCEPTION_INCLUDE
#include <setjmp.h>
#include <threads.h>
#include <assert.h>
#include <stdlib.h>

#undef assert
#ifdef NDEBUG
#define assert(x) 
#else
#define assert(x) \
    (void)((x) || (exception_raise(&ASSERT_ERROR, __LINE__, __FILE__, NULL), 0))
#endif


typedef struct Exception {
    const char* info;
} Exception;
 
typedef struct ExceptionStack_t
{
    /* data */
    const char * file;
    int line;
    jmp_buf jmpbuf;
    const Exception* exp;
    struct ExceptionStack_t* prev;
} ExceptionStack_t;

extern thread_local ExceptionStack_t* stack;
extern int error_state;

enum {
    ERROR_START = 0,
    ERROR_RAISE,
    ERROR_FINAL,
    ERROR_HANDLE
};

#ifdef __GNUC__
#define PUSH(x)  \
    typeof(x)* _x; \
    _x = (ExceptionStack_t*)NULL;\
    (void)_x; \
    (x).prev = stack; \
    stack = &(x) 
#else 
#define PUSH(x)  \
    (x)->prev = stack; \
    stack = x         
#endif  
    

#define POP \
    stack = stack->prev

#define TRY \
    do { \
    volatile int error_state = ERROR_START; \
    ExceptionStack_t current_exception; \
    PUSH(current_exception); \
    if(!setjmp(current_exception.jmpbuf)) { 

#define EXCEPT(x) \
    if(error_state == ERROR_START) \
        POP; \
    } else if (&x == current_exception.exp && error_state == ERROR_RAISE) { \
        error_state = ERROR_HANDLE;

#define FINAL \
    if(error_state == ERROR_START) \
        POP; \
    } { error_state = ERROR_FINAL; 

#define END_TRY \
    if(error_state == ERROR_START) \
        POP; \
    } if(error_state == ERROR_RAISE) \
        RERAISE; \
    } while(0);

#define RERAISE exception_raise(current_exception.exp, current_exception.line,current_exception.file, &error_state)
#define RAISE(x) exception_raise(&x, __LINE__, __FILE__,&error_state)
#define RETURN switch(POP, 0) default: return 

void exception_raise(const Exception* exp, int line, const char* file, volatile int* error_state_ptr);

extern const Exception GENER_ERROR;
extern const Exception WWN_ERROR;
extern const Exception ASSERT_ERROR;
extern const Exception CLOSE_ERROR;
extern const Exception CLOSEDIR_ERROR;
extern const Exception PTHREAD_CANCEL_ERROR;
extern const Exception PTHREAD_JOIN_ERROR;
extern const Exception PTHREAD_MUTEX_DESTROY_ERROR;
extern const Exception OPEN_ERROR;
extern const Exception OPENDIR_ERROR;
extern const Exception SCST_USER_REGISTER_DEVICE_ERROR;
extern const Exception PTHREAD_MUTEX_ATTR_INIT_ERROR;
extern const Exception STRTOUL_ERROR;
extern const Exception READ_ERROR;
extern const Exception PTHREAD_MUTEX_INIT_ERROR;
extern const Exception PTHREAD_MUTEX_ATTR_DESTROY_ERROR;
extern const Exception PTHREAD_CREATE_ERROR;
extern const Exception PTHREAD_COND_INIT_ERROR;
extern const Exception PTHREAD_COND_DESTROY_ERROR;
extern const Exception POPEN_ERROR;
extern const Exception SCSTADMIN_ERROR;
extern const Exception PCLOSE_ERROR;
extern const Exception MALLOC_ERROR;
extern const Exception REALLOC_ERROR;
extern const Exception CALLOC_ERROR;
extern const Exception POLLHUP_ERROR;
extern const Exception EINVAL_ERROR;
extern const Exception PTHREAD_RWLOCK_INIT_ERROR;
extern const Exception PTHREAD_RWLOCK_DESTROY_ERROR;
extern const Exception PTHREAD_WRLOCK_ERROR;
extern const Exception PTHREAD_RDLOCK_ERROR;
extern const Exception PTHREAD_UNLOCK_ERROR;
extern const Exception SIG_EMPTY_SET_ERROR;
extern const Exception SIG_ADD_SET_ERROR;
extern const Exception SIG_MASK_ERROR;
extern const Exception PTHREAD_MUTEX_ERROR;
#endif