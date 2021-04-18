#include "exception.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
thread_local ExceptionStack_t* stack = NULL;
int error_state;

const Exception ASSERT_ERROR = {"ASSERT_ERROR"};
const Exception CLOSE_ERROR = {"CLOSE_ERROR"};
const Exception PTHREAD_CANCEL_ERROR = {"PTHREAD_CANCEL_ERROR"};
const Exception PTHREAD_JOIN_ERROR = {"PTHREAD_JOIN_ERROR"};
const Exception PTHREAD_MUTEX_DESTROY_ERROR = {"PTHREAD_MUTEX_DESTROY_ERROR"};
const Exception OPEN_ERROR = {"OPEN_ERROR"};
const Exception SCST_USER_REGISTER_DEVICE_ERROR = {"SCST_USER_REGISTER_DEVICE_ERROR"};
const Exception PTHREAD_MUTEX_ATTR_INIT_ERROR = {"PTHREAD_MUTEX_ATTR_INIT_ERROR"};
const Exception GENER_ERROR = {"GENERAL_ERROR"};
const Exception WWN_ERROR = {"WWN_ERROR"};
const Exception STRTOUL_ERROR = {"STRTOUL_ERROR"};
const Exception READ_ERROR = {"READ_ERROR"};
const Exception OPENDIR_ERROR = {"OPENDIR_ERROR"};
const Exception CLOSEDIR_ERROR = {"CLOSEDIR_ERROR"};
const Exception PTHREAD_MUTEX_INIT_ERROR = {"PTHREAD_MUTEX_INIT_ERROR"};
const Exception PTHREAD_MUTEX_ATTR_DESTROY_ERROR = {"PTHREAD_MUTEX_ATTR_DESTROY_ERROR"};
const Exception PTHREAD_CREATE_ERROR = {"PTHREAD_CREATE_ERROR"};
const Exception PTHREAD_COND_INIT_ERROR = {"PTHREAD_COND_INIT_ERROR"};
const Exception PTHREAD_COND_DESTROY_ERROR = { "PTHREAD_COND_INIT_ERROR"};
const Exception POPEN_ERROR = {"POPEN_ERROR"};
const Exception SCSTADMIN_ERROR = {"SCSTADMIN_ERROR"};
const Exception PCLOSE_ERROR = {"PCLOSE_ERROR"};
const Exception MALLOC_ERROR = {"MALLOC_ERROR"};
const Exception REALLOC_ERROR = {"REALLOC_ERROR"};
const Exception CALLOC_ERROR = {"CALLOC_ERROR"};
const Exception POLLHUP_ERROR = {"POLLHUP_ERROR"};
const Exception EINVAL_ERROR = {"EINVAL_ERROR"};
const Exception PTHREAD_RWLOCK_INIT_ERROR = {"PTHREAD_RWLOCK_INIT_ERROR"};
const Exception PTHREAD_RWLOCK_DESTROY_ERROR = {"PTHREAD_RWLOCK_DESTROY_ERROR"};
const Exception PTHREAD_WRLOCK_ERROR = {"PTHREAD_WRLOCK_ERROR"};
const Exception PTHREAD_UNLOCK_ERROR = {"PTHREAD_UNLOCK_ERROR"};
const Exception PTHREAD_RDLOCK_ERROR = {"PTHREAD_RDLOCK_ERROR"};
const Exception SIG_EMPTY_SET_ERROR = {"SIG_EMPTY_SET_ERROR"};
const Exception SIG_ADD_SET_ERROR = {"SIG_ADD_SET_ERROR"};
const Exception SIG_MASK_ERROR = {"SIG_MASK_ERROR"};
const Exception PTHREAD_MUTEX_ERROR = {"PTHREAD_MUTEX_ERROR"};
void exception_raise(const Exception* exp, int line, const char* file, volatile int* error_state_ptr)
{
    assert(exp);
    assert(file);

    ExceptionStack_t* ptr = stack;
    if(!ptr) {
        printf("!@: Uncatched Error\n"
               "exp:  %s \n"
               "line:  %d \n"
               "file:  %s \n"
               "errno: %d\n"
               "errno_str: %s \n"
               , exp->info, line, file,errno,  strerror(errno));
        abort();
    }

    ptr->exp = exp;
    ptr->line = line;
    ptr->file = file;

    if(error_state_ptr) 
        *error_state_ptr = ERROR_RAISE;
    
    POP;
    longjmp(ptr->jmpbuf, ERROR_RAISE);
    assert(0);
}