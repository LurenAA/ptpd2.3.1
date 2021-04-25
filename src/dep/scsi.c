#include "../ptpd.h"
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#ifdef SDEBUG
static const char * scsi_opcode_string[] = {
    "TEST_UNIT_READY      ",
   "REZERO_UNIT           ",
   "REQUEST_SENSE         ",
   "FORMAT_UNIT           ",
   "READ_BLOCK_LIMITS     ",
   "REASSIGN_BLOCKS       ",
   "READ_6                ",
   "WRITE_6               ",
   "SEEK_6                ",
   "READ_REVERSE          ",
   "WRITE_FILEMARKS       ",
   "SPACE                 ",
   "INQUIRY               ",
   "RECOVER_BUFFERED_DATA ",
   "MODE_SELECT           ",
   "RESERVE               ",
   "RELEASE               ",
   "COPY                  ",
   "ERASE                 ",
   "MODE_SENSE            ",
   "START_STOP            ",
   "RECEIVE_DIAGNOSTIC    ",
   "SEND_DIAGNOSTIC       ",
   "ALLOW_MEDIUM_REMOVA  ", 
   "SET_WINDOW            ",
   "READ_CAPACITY         ",
   "READ_10               ",
   "WRITE_10              ",
   "SEEK_10               ",
   "WRITE_VERIFY          ",
   "VERIFY                ",
   "SEARCH_HIGH           ",
   "SEARCH_EQUAL          ",
   "SEARCH_LOW            ",
   "SET_LIMITS            ",
   "PRE_FETCH             ",
   "READ_POSITION         ",
   "SYNCHRONIZE_CACHE     ",
   "LOCK_UNLOCK_CACHE     ",
   "READ_DEFECT_DATA      ",
   "MEDIUM_SCAN           ",
   "COMPARE               ",
   "COPY_VERIFY           ",
   "WRITE_BUFFER          ",
   "READ_BUFFER           ",
   "UPDATE_BLOCK          ",
   "READ_LONG             ",
   "WRITE_LONG            ",
   "CHANGE_DEFINITION     ",
   "WRITE_SAME            ",
   "READ_TOC              ",
   "LOG_SELECT            ",
   "LOG_SENSE             ",
   "MODE_SELECT_10        ",
   "RESERVE_10            ",
   "RELEASE_10            ",
   "MODE_SENSE_10         ",
   "PERSISTENT_RESERVE_IN ",
   "PERSISTENT_RESERVE_OUT",
   "MOVE_MEDIUM           ",
   "READ_12               ",
   "WRITE_12              ",
   "WRITE_VERIFY_12       ",
   "SEARCH_HIGH_12        ",
   "SEARCH_EQUAL_12       ",
   "SEARCH_LOW_12         ",
   "READ_ELEMENT_STATUS   ",
   "SEND_VOLUME_TAG       ",
   "WRITE_LONG_2",
   "READ_16               ",
   "WRITE_16              ",
   "VERIFY_16	         ", 
   "REPORT_LUNS           ",
   "WRITE_SAME_16	     ", 
   "EXTENDED_COPY	     ", 
   "RECEIVE_COPY_RESULTS  ",
   "SYNCHRONIZE_CACHE_16  " 
};

static unsigned int scsi_opcode[] = {
0x00,
0x01,
0x03,
0x04,
0x05,
0x07,
0x08,
0x0a,
0x0b,
0x0f,
0x10,
0x11,
0x12,
0x14,
0x15,
0x16,
0x17,
0x18,
0x19,
0x1a,
0x1b,
0x1c,
0x1d,
0x1e,
0x24,
0x25,
0x28,
0x2a,
0x2b,
0x2e,
0x2f,
0x30,
0x31,
0x32,
0x33,
0x34,
0x34,
0x35,
0x36,
0x37,
0x38,
0x39,
0x3a,
0x3b,
0x3c,
0x3d,
0x3e,
0x3f,
0x40,
0x41,
0x43,
0x4c,
0x4d,
0x55,
0x56,
0x57,
0x5a,
0x5e,
0x5f,
0xa5,
0xa8,
0xaa,
0xae,
0xb0,
0xb1,
0xb2,
0xb8,
0xb6,
0xea,
0x88,
0x8a,
0x8f,
0xa0,
0x93,
0x83,
0x84,
0x91
};
#endif

//static variable
static 
thread_local char strerror_buf[STR_ERROR_STR_BUF_LENGTH]; 
static thread_local unsigned char cmdp[INQ_CMD_LEN];
static thread_local unsigned char sbp[MX_SB_LEN];
static thread_local unsigned char dxferp[INQ_REPLY_LEN];
static void* align_alloc(size_t size );

//macro
#define CREATE_NEW -1
#define STRERROR(x) strerror_r(x, strerror_buf, STR_ERROR_STR_BUF_LENGTH)
#define CINQUIRY(fd) Command(scsi, fd, INQUIRY, NULL, 0, NULL)
#define PLREAD(res) (res & POLLIN)
#define PLWRITE(res) (res & POLLOUT)
#define PLHUP(res) (res & POLLHUP)
#define PLERROR(res) (res & POLLERR)
#define SHELLSCRIPT "\
#/bin/bash \n\
for m in scst qla2xxx_scst qla2x00tgt scst_vdisk scst_user scst_disk ; do modprobe $m; done\
"


//enum
typedef enum {
    END_FD, END_STR, END_WWN, END_SESS, END_DEV_STR_CAPACITY
}END_VALUE_TYPE;
typedef enum {
    VALID_ARRAY = 101, INVALID_ARRAY 
} END_ARRAY_TYPE;
typedef enum {
    END_MALLOC_NEW, END_ADD_TO_VALID 
} END_ADD_TYPE;
typedef enum {
    TGT_WWN, TGT_SESS, TGT_STR
} TGT_TYPE;

//function
static Boolean Command(SCSIPath* scsi, int fd, int type, const unsigned char* str, int len, struct timespec* ntime);
static void readFromTarget(SCSIPath* scsi);
static int checkPollSingle(int fd, short flags);
static void setEndValue(SCSIPath* scsi, SCSIEnd* end_ptr, END_VALUE_TYPE type,...);
static SCSIEnd* removeEnd(SCSIPath* scsi, END_ARRAY_TYPE type, int index, Boolean freeSource);
static int readSCSI(SCSIPath* scsi, int fd, sg_io_hdr_t* io);
vdisk_tgt_dev* findtgtDev(SCSIPath* scsi, TGT_TYPE type, uint64_t x);
vdisk_tgt_dev* createNewTgtDev(SCSIPath* scsi);
void setTgtValue(vdisk_tgt_dev* dsk, TGT_TYPE type, ...);
static void checkDioCapacity(SCSIPath* scsi );

// static 
// int setPthreadCancelState(int state) {
//     int res, oldState;
//     res = pthread_setcancelstate(state, &oldState);
//     if(res) {
//         res = errno;
//         DBG("%s\n", STRERROR(res));
//         abort();
//     }
//     return oldState;
// }

// static 
// int setPthreadCancelType(int type) {
//     int res, oldType;
//     res = pthread_setcanceltype(type, &oldType);
//     if(res) {
//         res = errno;
//         DBG("%s\n", STRERROR(res));
//         abort();
//     }
//     return oldType;
// }

static 
void getClockTime(struct timespec* ntime) {
    assert(ntime);
    int res;

    res = clock_gettime(CLOCK_REALTIME, ntime);
    if(res == -1) {
        res = errno;
        DBG("%s\n", STRERROR(res));
        RAISE(GENER_ERROR);
    }
}

static void cleanUpWRLock(void* arg) {
    assert(arg);
    int res;
    pthread_rwlock_t* fd_rwlock = (pthread_rwlock_t* )arg;
    res = pthread_rwlock_unlock(fd_rwlock);
    if(res) 
        RAISE(PTHREAD_UNLOCK_ERROR);
}

static void cleanUpMutex(void* arg) {
    assert(arg);
    int res;
    pthread_mutex_t * mx = (pthread_mutex_t*) arg;
    res = pthread_mutex_unlock(mx);
    if(res)
        RAISE(PTHREAD_MUTEX_ERROR);
}

static 
SCSIEnd* removeEnd(SCSIPath* scsi, END_ARRAY_TYPE type, int index, Boolean freeSource) {
    assert(scsi);
    assert(index >= 0);
    SCSIEnd* end_ptr;

    int res = pthread_rwlock_wrlock(&scsi->fd_rwlock);
    if(res)
        RAISE(PTHREAD_WRLOCK_ERROR);
    pthread_cleanup_push(cleanUpWRLock, &scsi->fd_rwlock);

    switch(type) {
        case VALID_ARRAY:
            end_ptr = scsi->valid_end_array[index];
            scsi->valid_end_array_length--;
            scsi->valid_end_array[index] = NULL;
            break;
        case INVALID_ARRAY:
            end_ptr = scsi->invalid_end_array[index];
            scsi->invalid_end_array_length--;
            scsi->invalid_end_array[index] = NULL;
            break;
        default:
            RAISE(EINVAL_ERROR);
    }  
    
    if(freeSource) {
        if(end_ptr->fd) {
            res = close(end_ptr->fd);
            if(res == -1)
                RAISE(CLOSE_ERROR);
        }
        
        free(end_ptr);
        end_ptr = NULL;
    }

    pthread_cleanup_pop(1);
    return end_ptr;
}

static 
void setEndValue(SCSIPath* scsi, SCSIEnd* end_ptr, END_VALUE_TYPE type,...) {
    assert(end_ptr);
    int res;
    const char* str = NULL;
    int length = 0;
    va_list ap;
    va_start(ap, type);

    if(type == END_STR) {
        str = va_arg(ap, const char*);
        length = va_arg(ap, int);
    }
    
    switch(type) {
        case END_FD:
            if(!end_ptr->fd) 
                end_ptr->fd = va_arg(ap, int);
            else {
                res = pthread_rwlock_wrlock(&scsi->fd_rwlock);
                if(res) 
                    RAISE(PTHREAD_WRLOCK_ERROR);    
                pthread_cleanup_push(cleanUpWRLock, &scsi->fd_rwlock);

                res = close(end_ptr->fd);
                if(res == -1)
                    RAISE(CLOSE_ERROR);
                
                end_ptr->fd = va_arg(ap, int);

                pthread_cleanup_pop(1);
            }
            break;
        case END_STR:
            strncpy(end_ptr->dev_str, str, length);
            break;  
        case END_WWN:
            end_ptr->wwn = va_arg(ap, uint64_t);
            break;
        case END_SESS:
            end_ptr->sess_h = va_arg(ap, uint64_t);
            break;
        case END_DEV_STR_CAPACITY:
            end_ptr->dev_str_capacity = va_arg(ap, int);
            break;
        default:
            RAISE(EINVAL_ERROR);  
    }
    va_end(ap);
}

static 
SCSIEnd* findEndHelper(END_VALUE_TYPE type, SCSIEnd** array,int len, int capacity, va_list ap) {
    int i;
    const char* str;
    int fd;
    int str_len;
    uint64_t sess;

    switch(type) {
        case END_STR:
            str = va_arg(ap, const char*);
            str_len = va_arg(ap, int);
            assert(str_len >= 1);
            break;
        case END_FD:
            fd = va_arg(ap, int);
            break;
        case END_SESS:
            sess = va_arg(ap, uint64_t);
            break;
        default:
            RAISE(EINVAL_ERROR);
    }

    if(len) {
        assert(array);
        for(i = 0; i < capacity; ++i) {
            if(array[i]) {
                switch(type) {
                    case END_STR:
                        if(!strncmp(array[i]->dev_str, str, str_len))
                            return array[i];
                        break;
                    case END_FD:
                        if(array[i]->fd == fd) 
                            return array[i];
                        break;
                    case END_SESS:    
                        if(array[i]->sess_h == sess)
                            return array[i];
                        break;
                    default:
                        RAISE(EINVAL_ERROR);
                }
            }
        }
    }
    return NULL;
}

SCSIEnd* findEnd(SCSIPath* scsi, END_VALUE_TYPE type, ...) {
    assert(scsi);
    
    va_list ap, bp;
    SCSIEnd* end_ptr = NULL; 

    va_start(ap, type);
    va_copy(bp, ap);
    end_ptr = findEndHelper(type,  scsi->valid_end_array, scsi->valid_end_array_length, scsi->invalid_end_array_capacity, ap);
    if(end_ptr)
        return end_ptr;
    va_end(ap);

    end_ptr = findEndHelper(type, scsi->invalid_end_array,scsi->invalid_end_array_length, scsi->invalid_end_array_capacity,bp);
    va_end(bp);
    return end_ptr;
}

void checkEndArrayCapacity(SCSIPath* scsi, END_ARRAY_TYPE type) {
    assert(scsi);

    int *length = (type == INVALID_ARRAY ? &scsi->invalid_end_array_length : &scsi->valid_end_array_length);
    int *capacity = (type == INVALID_ARRAY? &scsi->invalid_end_array_capacity: &scsi->valid_end_array_capacity);
    SCSIEnd*** array = (type == INVALID_ARRAY? &scsi->invalid_end_array : &scsi->valid_end_array);

    if(*capacity == 0) {
        *array = calloc(1, sizeof((*array)[0]) * DEFAULT_SCSI_END_SIZE);
        if(!*array)
            RAISE(MALLOC_ERROR);
        *capacity = DEFAULT_SCSI_END_SIZE;
    } 
    else if (*length == *capacity) {
        *array = realloc(*array, (*capacity + DEFAULT_SCSI_END_SIZE) * sizeof((*array)[0]));
        if(!*array)
            RAISE(REALLOC_ERROR);
        *capacity += DEFAULT_SCSI_END_SIZE;
        for(int i = *length; i < *capacity; ++i) {
            (*array)[i] = NULL;
        }
    } else if(*length > *capacity)
        RAISE(EINVAL_ERROR); 
}

SCSIEnd* addEnd(SCSIPath* scsi, END_ADD_TYPE type, ...) {
    assert(scsi);
    SCSIEnd*  end_ptr = NULL;
    int i;
    va_list ap;
    va_start(ap, type);
    if(type == END_MALLOC_NEW) {
        int str_len = va_arg(ap, int);
        int alloc_len = str_len + 1 + sizeof(*end_ptr);

        checkEndArrayCapacity(scsi, INVALID_ARRAY);
    
        end_ptr = calloc(1, alloc_len);
        if(!end_ptr)
            RAISE(CALLOC_ERROR);
        setEndValue(scsi, end_ptr, END_DEV_STR_CAPACITY, str_len);

        for(i = 0; i < scsi->invalid_end_array_capacity; ++i) {
            if(!scsi->invalid_end_array[i]) {
                scsi->invalid_end_array[i] = end_ptr;
                break;
            }
        }
        scsi->invalid_end_array_length++;
    } 
    else if (type == END_ADD_TO_VALID) {
        end_ptr = va_arg(ap, SCSIEnd*);

        checkEndArrayCapacity(scsi, VALID_ARRAY);

        for(i = 0; i < scsi->valid_end_array_capacity; ++i) {
            if(!scsi->valid_end_array[i]) {
                scsi->valid_end_array[i] = end_ptr;
                break;
            }
        }
        ++scsi->valid_end_array_length;
    }
    va_end(ap);
    return end_ptr;
}

long myclock()
{
    static struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000000) + tv.tv_usec;
}

static void 
set_resp_data_len(struct vdisk_cmd *vcmd, int32_t resp_data_len)
{
	struct scst_user_scsi_cmd_reply_exec *reply = &vcmd->reply->exec_reply;

	if (vcmd->may_need_to_free_pbuf && (resp_data_len == 0)) {
		struct scst_user_scsi_cmd_exec *cmd = &vcmd->cmd->exec_cmd;
		free((void *)(unsigned long)cmd->pbuf);
		cmd->pbuf = 0;
		reply->pbuf = 0;
	}

	reply->resp_data_len = resp_data_len;

	return;
}

static int set_sense(uint8_t *buffer, int len, int key, int asc, int ascq)
{
	int res = 18;

	memset(buffer, 0, res);

	buffer[0] = 0x70;	/* Error Code			*/
	buffer[2] = key;	/* Sense Key			*/
	buffer[7] = 0x0a;	/* Additional Sense Length	*/
	buffer[12] = asc;	/* ASC				*/
	buffer[13] = ascq;	/* ASCQ				*/

	return res;
}

static
void set_cmd_error_status(struct vdisk_cmd *vcmd, int status) {
    struct scst_user_scsi_cmd_reply_exec *reply = &vcmd->reply->exec_reply;
	reply->status = status;
    set_resp_data_len(vcmd, 0);

    return ;
}

static void 
set_cmd_error(struct vdisk_cmd *vcmd, int key, int asc, int ascq)
{
	struct scst_user_scsi_cmd_reply_exec *reply = &vcmd->reply->exec_reply;

	set_cmd_error_status(vcmd, SAM_STAT_CHECK_CONDITION);
	reply->sense_len = set_sense(vcmd->sense, sizeof(vcmd->sense), key,
		asc, ascq);
	reply->psense_buffer = (unsigned long)vcmd->sense;

	return;
}

static
void set_busy(struct vdisk_cmd* vcmd) {
    set_cmd_error_status(vcmd, SAM_STAT_TASK_SET_FULL);
    return ;
}

static
Boolean isEndInSlash(const char* str) {
    int len = strlen(str);

    if(!len) return FALSE;

    return  str[len - 1] == '/'? TRUE : FALSE;
}

static 
Boolean scsiinterfaceExist(const char* ifaceName) {
    DIR* dirp;
    struct dirent* direntp = NULL;
    int node_name_number = 0, port_state_number = 0;

    if(!strlen(ifaceName)) 
        RAISE(GENER_ERROR);

    dirp = opendir(ifaceName);
    if(!dirp) 
        RAISE(OPENDIR_ERROR);

    for(direntp = readdir(dirp); 
    direntp != NULL; 
    direntp = readdir(dirp)) {
        if(!strcmp(&direntp->d_name[0], "port_name")) {
            ++node_name_number;
        }
        else if(!strcmp(&direntp->d_name[0], "port_state")) {
            ++port_state_number;
        }
        if(node_name_number == 1 && port_state_number == 1) 
            break;
    }

    if(node_name_number != 1 || port_state_number != 1) 
        RAISE(GENER_ERROR);

    if(-1 == closedir(dirp))
        RAISE(CLOSEDIR_ERROR);

    return TRUE;
}

static 
Boolean getSCSIInterfaceInfo(const char* ifaceName, SCSIInterfaceInfo* info) {
    if(!scsiinterfaceExist(ifaceName) || !info)
        return FALSE;
    
    int fd;
    Boolean ret = TRUE;
    char fileName[SCSI_NAME_MAX + 16];
    int len = strlen(ifaceName);
    char wwn[19] = {};
    ssize_t readN = 0;
    char* endptr = NULL;

    if(!len) 
        RAISE(GENER_ERROR);

    memset(&fileName[0], '\0', sizeof(fileName));
    strcpy(&fileName[0], ifaceName);
    if(isEndInSlash(ifaceName) == FALSE) {
        fileName[len] = '/';
        ++len;
    }
    strcat(&fileName[0], "port_name");

    fd = open(&fileName[0], O_RDONLY);
    if(fd == -1) 
        RAISE(OPEN_ERROR);

    readN = read(fd, &wwn[0], 18);
    if(readN == -1 || readN != 18) 
        RAISE(WWN_ERROR);

    wwn[readN] = '\0';
    info->wwn = strtoul(&wwn[0], &endptr, HEX);
    if(info->wwn == ULONG_MAX || endptr == &wwn[0]) 
        RAISE(STRTOUL_ERROR);
    strcpy(&info->wwn_str[0], &wwn[2]);
    

    if(-1 == close(fd))
        RAISE(CLOSE_ERROR);

    memset(&fileName[len], '\0', sizeof(fileName) - len);
    strcat(&fileName[0], "port_state");
    fd = open(&fileName[0], O_RDONLY);
    if(fd == -1) 
        RAISE(OPEN_ERROR);

    memset(&wwn[0], '\0', sizeof(wwn));
    readN = read(fd, &wwn[0], sizeof(wwn));
    if(readN == -1) 
        RAISE(READ_ERROR);

    if(!strncmp(&wwn[0], "Online", 6)) 
        info->online = TRUE;
    else 
        info->online = FALSE;

    if(-1 == close(fd))
        RAISE(CLOSE_ERROR);
    return ret;
}
 
Boolean testSCSIInterface(char * ifaceName, const RunTimeOpts* rtOpts, SCSIInterfaceInfo* info_ptr) {
    assert(rtOpts->transport == SCSI_FC); 
    if(info_ptr == NULL) {
        SCSIInterfaceInfo info;
    
        if(getSCSIInterfaceInfo(ifaceName, &info) == FALSE) 
            return FALSE;
    
        if(info.wwn == 0 || info.online != TRUE)
            return FALSE;

    } else {

        if(getSCSIInterfaceInfo(ifaceName, info_ptr) == FALSE) 
            return FALSE;

        if(info_ptr->wwn == 0 || info_ptr->online != TRUE)
            return FALSE;

    }
    
    return TRUE;
}

static 
void freeEndArray(SCSIEnd** array, int length, int capacity) {
    assert(array);
    assert(length >= 0);
    assert(capacity >= 0);

    int i;
    SCSIEnd* end_ptr;
    if(length && capacity) {
        for(i = 0; i < length; ++i) { 
            end_ptr = array[i];
            if(end_ptr) {
                if(end_ptr->fd) {
                    if(-1 == close(end_ptr->fd))
                        RAISE(CLOSE_ERROR);
                }
                free(end_ptr);
            }
            array[i] = NULL;
        }
    } 
}

Boolean scsiShutdown(SCSIPath* scsi) {
    int i, res;
    SCSIREC* recv_ptr, *recv_ptr_h;
    assert(scsi);
    
    if(scsi->end_refresh_thread) {
        res = pthread_cancel(scsi->end_refresh_thread);
        if(res && res != ESRCH)
            RAISE(PTHREAD_CANCEL_ERROR);
        res = pthread_join(scsi->end_refresh_thread, NULL);
        if(res) {
            DBG("pthread_join end_refresh_thread error: %s\n", STRERROR(res));
            RAISE(PTHREAD_JOIN_ERROR);
        }
    }

    for(i = 0; i < SCST_THREAD; ++i) {
        if(scsi->scst_thread[i]) {
            res = pthread_cancel(scsi->scst_thread[i]);
            if(res) {
                if(res == ESRCH) 
                    DBG("the thread %d has dead", scsi->scst_thread[i]);
                else 
                    RAISE(PTHREAD_CANCEL_ERROR);
            }
        }
    }
    for(i = 0; i < SCST_THREAD; ++i) {
        if(scsi->scst_thread[i]) {
            res = pthread_join(scsi->scst_thread[i], NULL);
            if(res) {
                RAISE(PTHREAD_JOIN_ERROR);
            }
        }
    }
    
    if(scsi->scst_usr_fd) {
        if(-1 == close(scsi->scst_usr_fd))
            RAISE(CLOSE_ERROR);
    }

    // res = pthread_cancel(scsi->receive_scsi_back_thread);
    // if(res && res != ESRCH) 
    //     RAISE(PTHREAD_CANCEL_ERROR);
    if(scsi->dio_array_capacity > 0) {
        if(scsi->dio_array_length > 0) {
            for(i = 0; i < scsi->dio_array_capacity; ++i) {
                if(scsi->dio_array[i]) {
                    if(scsi->dio_array[i]->hasInitMux) {
                        res = pthread_mutex_destroy(&scsi->dio_array[i]->mux);
                        if(res) 
                            RAISE(PTHREAD_MUTEX_DESTROY_ERROR);
                    }
                    if(scsi->dio_array[i]->buf)
                        free(scsi->dio_array[i]->buf);

                    free(scsi->dio_array[i]);
                    scsi->dio_array[i] = NULL;
                }
            }
        }

        if(scsi->dio_array) {
            free(scsi->dio_array);
            scsi->dio_array = NULL;
        }
    }
    scsi->dio_array_capacity = 0;
    scsi->dio_array_length = 0;
    
    if(scsi->sess_array_capacity > 0) {
        if(scsi->sess_array_length > 0) {
            for(i = 0; i < scsi->sess_array_capacity; ++i) {
                if(scsi->sess_array[i] && scsi->sess_array[i]->str)
                    free(scsi->sess_array[i]->str);
                free(scsi->sess_array[i]);
                scsi->sess_array[i] = NULL;
            }
        }

        free(scsi->sess_array);
    }
    // res = pthread_join(scsi->receive_scsi_back_thread, NULL);
    // if(res) 
    //     RAISE(PTHREAD_JOIN_ERROR);
    if(scsi->recv_mutex_init) {
        res = pthread_mutex_destroy(&scsi->recv_mutex);
        if(res) 
            RAISE(PTHREAD_MUTEX_DESTROY_ERROR);
        scsi->recv_mutex_init = FALSE;
    }

    recv_ptr = scsi->recv_event_head;
    while(recv_ptr != NULL) {
        recv_ptr_h = recv_ptr->next;
        free((void*)recv_ptr);
        recv_ptr = recv_ptr_h;
    }

    recv_ptr = scsi->recv_general_head;
    while(recv_ptr != NULL) {
        recv_ptr_h = recv_ptr->next;
        free((void*)recv_ptr);
        recv_ptr = recv_ptr_h;
    }
    if(scsi->valid_end_array)
        freeEndArray(scsi->valid_end_array, scsi->valid_end_array_length, scsi->valid_end_array_capacity);
    if(scsi->invalid_end_array)
        freeEndArray(scsi->invalid_end_array, scsi->invalid_end_array_length, scsi->invalid_end_array_capacity);

    if(scsi->fd_rwlock_init) {
        res = pthread_rwlock_destroy(&scsi->fd_rwlock);
        if(res)
            RAISE(PTHREAD_RWLOCK_DESTROY_ERROR);
        scsi->fd_rwlock_init = FALSE;
    }

    memset(scsi, 0, sizeof(* scsi));
    return TRUE;
}

//检查poll中一个对象的状态
static int 
checkPollSingle(int fd, short flags) {
    static thread_local struct pollfd plf;
    int n = 0;
    int res;

    memset(&plf, 0, sizeof(struct pollfd));
    plf.fd = fd;
    plf.events = flags | POLLHUP | POLLERR;
again:
    n = poll(&plf, 1, 0);
    if(n == 0) 
        return 0;
    if(n  == -1) {
        res = errno;
        if(res == EINTR)
            goto again;
        DBG("checkPollSingle error : %s", STRERROR(res));
        RAISE(GENER_ERROR);
    }

    return plf.revents;
}

//检测HBA设备是否在线 host_path = /sys/class/fc_host/host5
static Boolean
checkHBAPortState(const char* host_path) {
    Boolean res = TRUE;
    char fileName[MAX_FILENAME_LENGTH];
    char readBuf[PORT_STATE_LEN];
    int fd = 0;
    ssize_t rdnum = 0;

    memset(&fileName[0], '\0', MAX_FILENAME_LENGTH);
    if(strlen(host_path) >= MAX_FILENAME_LENGTH) {
        DBG("strlen(host_path) >= MAX_FILENAME_LENGTH\n");
        return FALSE;
    }
    strcpy(&fileName[0], host_path);
    strcat(&fileName[0], FC_STATE_NAME);

    fd = open(&fileName[0], O_RDONLY);
    if(fd == -1) {
        res = FALSE;
        goto out;
    }

    memset(&readBuf[0], '\0', PORT_STATE_LEN);
    rdnum = read(fd, &readBuf[0], PORT_STATE_LEN);
    if(rdnum == -1) {
        res = FALSE;
        goto out;
    }
    //delete '\n'
    if(readBuf[rdnum - 1] == '\n') 
        readBuf[rdnum - 1] = '\0';

    if(strcmp(&readBuf[0], "Online") == 0) {
        res = TRUE;
    } else 
        res = FALSE;
out:
    close(fd);

    return res;
}

//初始化sg_io_hdr_t
static Boolean
initSgIoHdr(sg_io_hdr_t *io, int dxfer_direction, unsigned char cmd_len, unsigned char mx_sb_len, 
unsigned int dxfer_len, void * dxferp, unsigned char * cmdp, unsigned char * sbp,
unsigned int flags) {
    Boolean res = TRUE;
    assert(io);

    memset(io, 0 ,sizeof(sg_io_hdr_t));
    io->interface_id = (int)'S';
    io->dxfer_direction = dxfer_direction;
    io->cmd_len = cmd_len;
    io->mx_sb_len = mx_sb_len;
    io->dxfer_len = dxfer_len;
    io->dxferp = dxferp;
    io->sbp = sbp;
    io->flags = flags;
    io->timeout = DEFAULT_TIME_OUT;
    io->cmdp = cmdp;

    return res;
}

//发送SCSI请求
static
Boolean sendSCSI(sg_io_hdr_t *io, int fd, struct timespec *ntime) {
    int res;

    assert(io && io->dxfer_len && io->dxferp && io->sbp);
    assert(io->cmd_len <= 16 && io->cmd_len >= 6 && io->cmdp);

    res = checkPollSingle(fd, POLLOUT);
    if(!PLWRITE(res)) {
        DBG("checkPollSingle fails\n");
        return FALSE;
    }
    if(ntime)
        getClockTime(ntime);
    res = write(fd, (void*)io, sizeof(sg_io_hdr_t));
    if(res != sizeof(sg_io_hdr_t) && errno != EDOM) {
        DBG("sendSCSI error size \n");
        return FALSE;
    }
    if(errno == EDOM) {
        DBG("EDOM \n");
        return FALSE;
    }

    return TRUE;
}

static Boolean 
sendSCSICommandByFd(SCSIPath* scsi,  int fd,  int dxfer_direction, unsigned char cmd_len,
unsigned char* cmdp, unsigned char* dxferp, unsigned char* sbp, struct timespec* ntime) {
    Boolean res = TRUE;
    static thread_local sg_io_hdr_t io;
    
    assert(scsi);
    res = initSgIoHdr(&io, dxfer_direction, cmd_len, MX_SB_LEN, INQ_REPLY_LEN,
    (void*)dxferp, cmdp, sbp, 0);
    if(scsi->dioEnabled)
        io.flags |= SG_FLAG_DIRECT_IO;
    if(res == FALSE)
        return FALSE;
    res = pthread_rwlock_rdlock(&scsi->fd_rwlock);
    if(res)
        RAISE(PTHREAD_RDLOCK_ERROR);
    pthread_cleanup_push(cleanUpWRLock, &scsi->fd_rwlock);
    res = sendSCSI(&io, fd, ntime);
    pthread_cleanup_pop(1);

    return res;
}


static Boolean
sendINQUIRYByFd(SCSIPath* scsi, int fd, unsigned char* cmdp, unsigned char* sbp,
unsigned char* dxferp, struct timespec* ntime) {
    assert(scsi);
    
    //cdb
    memset(cmdp, 0, INQ_CMD_LEN * sizeof(cmdp[0]));
    cmdp[0] = 0x12;
    cmdp[3] = INQ_REPLY_LEN >> 8; //ALLOCATION LENGTH
    cmdp[4] = INQ_REPLY_LEN & 0xff;

    if(!sendSCSICommandByFd(scsi, fd, SG_DXFER_FROM_DEV, 6, cmdp, dxferp, sbp, ntime))
        return FALSE;

    return TRUE;
}


//user initialize cmdp before call this function
static Boolean
sendWRITE16ByFd(SCSIPath* scsi, int fd, UInteger16 len,unsigned char* cmdp, unsigned char* sbp,
unsigned char* dxferp, struct timespec* ntime) {
    int i = 0;
    // memset(scsi->cmdp, 0, INQ_CMD_LEN);
    cmdp[0] = 0x8A;
    // scsi->cmdp[13] = 1;
    for(; i < 2; ++i) {
        cmdp[13 - i] = (0xff & (len >> (i * 8)));
    }
    
    if(!sendSCSICommandByFd(scsi, fd, SG_DXFER_TO_DEV, 16,cmdp, dxferp, sbp, ntime))
        return FALSE;

    return TRUE;
}

static void
refreshSGIO() {
    memset(cmdp, 0, sizeof(cmdp));
    memset(sbp, 0, sizeof(sbp));
    memset(dxferp,0, sizeof(dxferp));
}

static dioDxferp * createNewDioBuf(SCSIPath* scsi, int p) {
    int i, res;
    dioDxferp* ptr;
    if(p == CREATE_NEW) {
        checkDioCapacity(scsi);
        for(i = 0; i < scsi->dio_array_capacity; ++i) {
            if(scsi->dio_array[i] == NULL) {
                p = i;
                break;
            }
        }
    }
    //create new 
    ptr = calloc(1, sizeof(*scsi->dio_array[i]));
    if(!ptr)
        RAISE(MALLOC_ERROR);
    scsi->dio_array[p] = ptr;
    ptr->buf = (unsigned char*)align_alloc(BLK_SZ);
    memset(ptr->buf, 0, BLK_SZ);
    ptr->len = BLK_SZ;
    res = pthread_mutex_init(&ptr->mux, NULL);
    if(res) 
        RAISE(PTHREAD_MUTEX_ERROR);
    ptr->hasInitMux = TRUE;
    ptr->busy = FALSE;
    scsi->dio_array_length++;
    return ptr;
}

static void checkDioCapacity(SCSIPath* scsi ) {
    assert(scsi);

    if(scsi->dio_array_capacity == scsi->dio_array_length) {
        scsi->dio_array = realloc(scsi->dio_array, sizeof(scsi->dio_array[0]) * (scsi->dio_array_capacity + SCSIDIO_ARRAY_L));
        if(scsi->dio_array == NULL) 
            RAISE(REALLOC_ERROR);
        scsi->dio_array_capacity += SCSIDIO_ARRAY_L;
        for(int i = scsi->dio_array_length; i < scsi->dio_array_capacity; ++i) {
            scsi->dio_array[i] = NULL;
        }
    }
    
}

static unsigned char* getDioBuf(SCSIPath* scsi) {
    assert(scsi);
    int i, res;
    dioDxferp* tmp, *res_ptr = NULL;

    if(scsi->dio_array_length < scsi->dio_array_capacity) {
        for(i = 0; i < scsi->dio_array_capacity; ++i) {
            tmp = scsi->dio_array[i];
            if(!tmp) {
                res_ptr = createNewDioBuf(scsi, i);
                break;
            }
            res = pthread_mutex_lock(&tmp->mux);
            if(res)
                RAISE(PTHREAD_MUTEX_ERROR);
            pthread_cleanup_push(cleanUpMutex, &tmp->mux);
            if(!tmp->busy) {
                tmp->busy = TRUE;
                res_ptr = tmp;
                scsi->dio_array_length++;
            }
            pthread_cleanup_pop(1);
            if(res_ptr) 
                break;
        }
    } 
    else {
        res_ptr = createNewDioBuf(scsi, CREATE_NEW);
    }
    return res_ptr->buf;
}

static Boolean 
Command(SCSIPath* scsi, int fd, int type, const unsigned char* str, int len, struct timespec* ntime) {
    assert(scsi);
    assert(len >= 0);
    assert(len == 0 || (len > 0 && str));
    Boolean res;
    unsigned char* dxferp_l = NULL;

    
    if(scsi->dioEnabled)
        dxferp_l = getDioBuf(scsi);
    else 
        dxferp_l = dxferp;
    if(len && str) {
        memcpy(dxferp_l, str, len);
        // dxferp[len - 1] = '\0';
    }

    switch(type) {
        case INQUIRY:
            res = sendINQUIRYByFd(scsi, fd, cmdp, sbp, dxferp_l, ntime);
            break;
        case WRITE_16:
            res = sendWRITE16ByFd(scsi,fd,len,cmdp,sbp, dxferp_l, ntime);
            break;
        default:
            DBG("Send Ignored SCSI Command\n");
            RAISE(GENER_ERROR);
    }

    return res;
}

static
int readSCSI(SCSIPath* scsi, int fd, sg_io_hdr_t* io) {
    assert(scsi);
    assert(io);
    int res;
    Boolean ret = TRUE;
    memset(io->cmdp, 0, sizeof(INQ_CMD_LEN));
    if(io->dxferp)
        memset(io->dxferp, 0, sizeof(MX_SB_LEN));
    memset(io->sbp, 0, sizeof(INQ_REPLY_LEN));

    res = pthread_rwlock_rdlock(&scsi->fd_rwlock);
    if(res)
        RAISE(PTHREAD_RDLOCK_ERROR);
    pthread_cleanup_push(cleanUpWRLock, &scsi->fd_rwlock);

    int res = read(fd, io, sizeof(sg_io_hdr_t));
    if(res == -1) {
        res = errno;
        DBG("read failed : %s", STRERROR(res));
        ret = FALSE;
    }
    if(res != sizeof(sg_io_hdr_t)) {
        DBG("read failed : %s", STRERROR(EIO));
        ret = FALSE;
    }
    
    pthread_cleanup_pop(1);
    if(scsi->dioEnabled && !(io->info & SG_INFO_DIRECT_IO) )
        RAISE(GENER_ERROR);
    
    return ret;
}

//扫描本地scsi设备,发送请求
Boolean scanSCSIEquipmemt(SCSIPath* scsi) {
    DIR* dirp;
    struct dirent* direntp;
    int res = 0;
    char tmpName[5 * strlen(DEV_PREFIX)];
    int fd = 0;
    SCSIEnd* end_ptr = NULL;

    assert(scsi);
    dirp = opendir(DEV_PREFIX);
    if(dirp == NULL) {
        res = errno;
        DBG("scanSCSIEquipmemt open dir failed: %s\n", STRERROR(res));
        RAISE(OPENDIR_ERROR);
    }

    memset(&tmpName[0], '\0' ,sizeof(tmpName));
    strcpy(&tmpName[0], DEV_PREFIX);

    for(direntp = readdir(dirp); 
     direntp != NULL;
    direntp = readdir(dirp)
   ) {
        if(!strlen(direntp->d_name) || strcmp(&direntp->d_name[0], ".") == 0 || 
        strcmp(&direntp->d_name[0], "..") == 0 || strncmp(&direntp->d_name[0], "sg", 2) != 0) 
            continue;
        memset(&tmpName[0] + strlen(DEV_PREFIX), '\0', sizeof(tmpName) - strlen(DEV_PREFIX));
        strcat(&tmpName[0] + strlen(DEV_PREFIX), &direntp->d_name[0]);
        end_ptr = findEnd(scsi, END_STR,tmpName, strlen(tmpName));
        if(!end_ptr) {
            //no end there
            end_ptr = addEnd(scsi, END_MALLOC_NEW ,strlen(tmpName));
            setEndValue(scsi ,end_ptr, END_STR, &tmpName[0], strlen(tmpName));
        }
        if(!end_ptr->fd) {        
            fd = open(&tmpName[0], O_RDWR | O_NONBLOCK);
            if(fd == -1) {   
                res = errno;
                DBG("open %s fails\n", STRERROR(res));
                continue;
            }
            setEndValue(scsi ,end_ptr, END_FD, fd);
        }
        res = CINQUIRY(fd);
        if(!res) {
            DBG("sentINQUIRYByFd fails\n");
        }
    }

    return TRUE;
}

static 
void parseINQUIRY(SCSIPath* scsi, SCSIEnd* end_ptr, sg_io_hdr_t* io) {
    assert(scsi && end_ptr && io);

    int alloc_len;
    unsigned char* buf = (unsigned char*)io->dxferp;
    uint64_t wwn = 0;
    vdisk_tgt_dev* dsk_ptr = NULL;

    alloc_len = (int)buf[4] + 4;
    if(alloc_len < 31) {
        DBG("alloc_len error\n");
        return ;
    }

    for(int n =0 ; n < 8; ++n) 
        wwn = (wwn << 8) |  (buf[WWN_BEGIN + n] & 0xff);
    
    dsk_ptr = findtgtDev(scsi, TGT_WWN, wwn);
    if(dsk_ptr) {
        if(dsk_ptr->sess_h) 
            setEndValue(scsi, end_ptr, END_SESS, dsk_ptr->sess_h);
    }
    setEndValue(scsi, end_ptr, END_WWN, wwn);

    return ;
}

// static
// Boolean sendWWNtoDev(SCSIPath* scsi, int fd) {
//     Boolean res = TRUE;
//     int len = 0;
//     memset(&scsi->cmdp[0], 0, INQ_CMD_LEN);
//     memset(&scsi->dxferp[0], 0, INQ_REPLY_LEN);
//     scsi->cmdp[2] = 0xff;
//     scsi->cmdp[9] = 0xff;
//     len = snprintf(NULL,0,"%lu",scsi->info.wwn);
//     if(len <= 0) {
//         DBUGDF(errno);
//         return FALSE;
//     }
//     len = snprintf((char*)&scsi->dxferp[0], len, "%lu",scsi->info.wwn);
//     res = sentWRITE16ByFd(scsi, fd, len);
//     return res;
// }

static
void processInformation(SCSIPath* scsi, SCSIEnd* end_ptr, sg_io_hdr_t* io) {
    //INQUIRY return 
    unsigned char* dxferp = (unsigned char* )io->dxferp;
    if(!memcmp(&dxferp[18], WWN_INQ_ID, 6)) {
        parseINQUIRY(scsi, end_ptr, io);
    }

}

static 
dioDxferp * findDioByStr(SCSIPath* scsi, unsigned char* ptr) {
    for(int i = 0; i < scsi->dio_array_capacity; ++i) {
        if(scsi->dio_array[i]->buf == ptr)
            return scsi->dio_array[i];
    }
    return NULL;
}

static
void  releaseDioBuf(SCSIPath* scsi ,unsigned char* ptr) {
    assert(scsi);
    assert(ptr);
    int res;
    dioDxferp* rp = findDioByStr(scsi, ptr);
    if(!rp) 
        RAISE(GENER_ERROR);
    res = pthread_mutex_lock(&rp->mux);
    if(res)
        RAISE(PTHREAD_MUTEX_ERROR);
    pthread_cleanup_push(cleanUpMutex, &rp->mux);
    rp->busy = FALSE;
    memset(rp->buf, 0, rp->len);
    pthread_cleanup_pop(1);
    --scsi->dio_array_length;
}

static 
void readHelper(SCSIPath* scsi, SCSIEnd** array, int capacity,sg_io_hdr_t *io, END_ARRAY_TYPE type) {
    int i= 0;
    int poll = 0;
    int fd;
    for( ; i < capacity; ++i) {
        if(!array[i] || !array[i]->fd)
            continue;
        fd = array[i]->fd;
        
    again:
        poll = checkPollSingle(fd, POLLIN);

        if(PLERROR(poll) || PLHUP(poll)) {
            //error happen !!!!!
            DBG("remove one node: %s \n", array[i]->dev_str);
            removeEnd(scsi, type, i, TRUE);
            
            continue;
        } else if (!PLREAD(poll))
            continue;
        
        if(readSCSI(scsi, fd, io) == FALSE)
            continue;
        else 
            processInformation(scsi, array[i], io);
        
        if(scsi->dioEnabled)
            releaseDioBuf(scsi, io->dxferp);
        goto again;
    }
}

static
void readFromTarget(SCSIPath* scsi) {    
    static thread_local unsigned char cmdp[INQ_CMD_LEN];
    static thread_local unsigned char sbp[MX_SB_LEN];
    static thread_local unsigned char dxferp[INQ_REPLY_LEN];
    sg_io_hdr_t io = {
        .cmdp = cmdp,
        .sbp = sbp,
        .dxferp = dxferp,
    };
    if(scsi->dioEnabled)
        io.dxferp = NULL;

    readHelper(scsi, scsi->valid_end_array, scsi->valid_end_array_capacity, &io, VALID_ARRAY);
    readHelper(scsi, scsi->invalid_end_array, scsi->invalid_end_array_capacity, &io, INVALID_ARRAY);
}

// Boolean sentWRITE16ByFd(SCSIPath* scsi, int fd, const char* str, int len) {
//     Boolean res = TRUE;
//     if(!scsi || !str || len <= 0) {
//         DBUGDF(EINVAL);
//         return FALSE;
//     }
//     if(len > sizeof(scsi->dxferp)) {
//         DBUGDF(E2BIG);
//         return FALSE;
//     }

//     memset(&scsi->cmdp[0], 0, INQ_CMD_LEN);
//     scsi->cmdp[0] = 0x8A;
//     scsi->cmdp[13] = INQ_REPLY_LEN / 512;

//     memset(&scsi->dxferp[0], 0, INQ_REPLY_LEN);
//     memcpy(&scsi->dxferp[0], str, len); 

//     res = sendSCSICommandByFd(scsi, fd, SG_DXFER_TO_DEV, 16);

//     return res ;
// }

// static 
// struct vdisk_tgt_dev *find_tgt_dev(SCSIPath* scsi, uint64_t sess_h) {
//     unsigned int i;
//     struct vdisk_tgt_dev* res = NULL;
//     for(i = 0; i < ARRAY_SIZE(scsi->tgt_devs); ++i) {
//         if(scsi->tgt_devs[i].sess_h == sess_h) {
//             res = &scsi->tgt_devs[i];
//             break;
//         }
//     }
//     return res;
// }

// static struct vdisk_tgt_dev *
// find_empty_tgt_dev(SCSIPath* scsi)  {
//     return find_tgt_dev(scsi, 0);
// }

static int 
countNumberInString(const char* str, int len) {
    int num = 0;
    for(int i = 0; i < len; ++i) {
        if((str[i] >= '0' && str[i] <= '9') || (str[i] >= 'a' && str[i] <= 'f')) {
            ++num;
        }
    }
    return num;
}

static void 
removeTgtDev(SCSIPath* scsi, vdisk_tgt_dev* dsk) {
    assert(scsi && dsk);

    for(int i = 0; i < scsi->sess_array_capacity; ++i) {
        if(scsi->sess_array[i] == dsk) {
            if(dsk->str) 
                free(dsk->str);
            free(dsk);
            scsi->sess_array[i] = NULL;
            scsi->sess_array_length--;
            return ;
        }
    }
}

static 
Boolean do_sess(struct vdisk_cmd* vcmd) {
    Boolean res =  TRUE;
    struct scst_user_get_cmd *cmd = vcmd->cmd;
    struct scst_user_reply_cmd *reply = vcmd->reply;
    SCSIPath* scsi = vcmd->scsi;
    vdisk_tgt_dev* dsk_ptr;
    
    dsk_ptr = findtgtDev(scsi, TGT_SESS, cmd->sess.sess_h);
    if (cmd->subcode == SCST_USER_ATTACH_SESS) {
        DBG("sess initiator: %s \n", cmd->sess.initiator_name);
        if (dsk_ptr != NULL) {
            DBG("SCST_USER_ATTACH_SESS: %s\n", STRERROR(EEXIST));
            res = FALSE;
            goto reply1;
        }

        dsk_ptr = createNewTgtDev(scsi);
        setTgtValue(dsk_ptr, TGT_SESS, cmd->sess.sess_h);
        setTgtValue(dsk_ptr, TGT_STR, cmd->sess.initiator_name);

        if(countNumberInString(&cmd->sess.initiator_name[0], 
        strlen(&cmd->sess.initiator_name[0])) == 16) {
            char* pch;
            uint64_t wwn = 0;
            pch = strtok(&cmd->sess.initiator_name[0], ":");
            while(pch != NULL) {
                wwn <<= 8;
                wwn += strtoul(pch, NULL, 16);
                pch = strtok(NULL, ":");
            }
            setTgtValue(dsk_ptr, TGT_WWN, wwn);
        }
    } else {
        if(dsk_ptr == NULL) {
            DBG("SCST_USER_DETTACH_SESS: %s \n", STRERROR(ESRCH));
            res = FALSE;
            goto reply1;
        }
        removeTgtDev(scsi, dsk_ptr);
    }
reply1:
    memset(reply, 0, sizeof(*reply));
	reply->cmd_h = cmd->cmd_h;
	reply->subcode = cmd->subcode;
	reply->result = res == TRUE ? 0 : 1;  

	return res;
}

static Boolean
do_parse(struct vdisk_cmd *vcmd) {
    Boolean ret = FALSE;
    struct scst_user_scsi_cmd_parse *cmd = &vcmd->cmd->parse_cmd;
	struct scst_user_scsi_cmd_reply_parse *reply = &vcmd->reply->parse_reply;

    memset(reply, 0, sizeof(*reply));
	vcmd->reply->cmd_h = vcmd->cmd->cmd_h;
	vcmd->reply->subcode = vcmd->cmd->subcode;
    if (cmd->expected_values_set == 0) {
		reply->bufflen = -1; /* invalid value */
		return FALSE;
	}

    reply->queue_type = cmd->queue_type;
	reply->data_direction = cmd->expected_data_direction;
	reply->lba = cmd->lba;
	reply->data_len = cmd->expected_transfer_len;
	reply->bufflen = cmd->expected_transfer_len;
	reply->out_bufflen = cmd->expected_out_transfer_len;
	reply->cdb_len = cmd->cdb_len;
    
    if (cmd->op_flags & SCST_INFO_VALID)
		reply->op_flags = cmd->op_flags;
	else {
		if (reply->data_direction & SCST_DATA_WRITE)
			reply->op_flags |= SCST_WRITE_MEDIUM;
		reply->op_flags |= SCST_INFO_VALID;
	}

    return ret;
}

static
void* align_alloc(size_t size ) {
    static long page_size;
    assert(size > 0);
    if(page_size == 0) {
        page_size = sysconf(_SC_PAGE_SIZE);
        assert(page_size >= 1);
    }
    void* memptr = NULL;
    int res = posix_memalign(&memptr, page_size, size);
    if(res) {
        res = errno;
        RAISE(GENER_ERROR);
    }
    return memptr;
}

static Boolean 
do_alloc_mem(struct vdisk_cmd *vcmd) {
    struct scst_user_get_cmd *cmd = vcmd->cmd;
	struct scst_user_reply_cmd *reply = vcmd->reply;
	Boolean res = TRUE;

    memset(reply, 0, sizeof(*reply));
	reply->cmd_h = cmd->cmd_h;
	reply->subcode = cmd->subcode;

    reply->alloc_reply.pbuf = (unsigned long)align_alloc(cmd->alloc_cmd.alloc_len);
    if (reply->alloc_reply.pbuf == 0) {
        DBG("Unable to allocate buffer (len %d)",cmd->alloc_cmd.alloc_len);
        RAISE(MALLOC_ERROR);
    }
    memset((void*)reply->alloc_reply.pbuf,0, cmd->alloc_cmd.alloc_len);
    return res;
}

static Boolean
do_on_free_cmd(struct vdisk_cmd *vcmd) {
    struct scst_user_get_cmd *cmd = vcmd->cmd;
	struct scst_user_reply_cmd *reply = vcmd->reply;
	Boolean res = TRUE;

    if (!cmd->on_free_cmd.buffer_cached && (cmd->on_free_cmd.pbuf != 0)) {
		free((void *)(unsigned long)cmd->on_free_cmd.pbuf);
	}

    memset(reply, 0, sizeof(*reply));
	reply->cmd_h = cmd->cmd_h;
	reply->subcode = cmd->subcode;

	return res;
}

static Boolean 
do_cached_mem_free(struct vdisk_cmd *vcmd) {
    struct scst_user_get_cmd *cmd = vcmd->cmd;
	struct scst_user_reply_cmd *reply = vcmd->reply;
	Boolean res = TRUE;

    free((void *)(unsigned long)cmd->on_cached_mem_free.pbuf);

	memset(reply, 0, sizeof(*reply));
	reply->cmd_h = cmd->cmd_h;
	reply->subcode = cmd->subcode;

	return res;
}

static Boolean
do_tm(struct vdisk_cmd *vcmd, int done){
    struct scst_user_get_cmd *cmd = vcmd->cmd;
	struct scst_user_reply_cmd *reply = vcmd->reply;
	Boolean res = TRUE;

    memset(reply, 0, sizeof(*reply));
	reply->cmd_h = cmd->cmd_h;
	reply->subcode = cmd->subcode;
	reply->result = 0;

    return res;
}

vdisk_tgt_dev* findtgtDev(SCSIPath* scsi, TGT_TYPE type, uint64_t x) {
    assert(scsi);
    for(int i = 0; i < scsi->sess_array_capacity; ++i) {
        if(scsi->sess_array[i]) {
            if(type == TGT_WWN) {
                if(x == scsi->sess_array[i]->wwn) 
                    return scsi->sess_array[i];
            } else if(type == TGT_SESS) {
                if(x == scsi->sess_array[i]->sess_h)
                    return scsi->sess_array[i];
            } else {
                assert(0);
            }
        }    
    }
    return NULL;
}

vdisk_tgt_dev* createNewTgtDev(SCSIPath* scsi) {
    assert(scsi);

    if(scsi->sess_array_length == scsi->sess_array_capacity) {
        scsi->sess_array = realloc(scsi->sess_array,  sizeof(scsi->sess_array[0])*(scsi->sess_array_length + DEV_SESS_NUMBER));
        if(scsi->sess_array) 
            RAISE(REALLOC_ERROR);
        scsi->sess_array_capacity += DEV_SESS_NUMBER;
        for(int i = scsi->sess_array_length; i < scsi->sess_array_capacity; ++i) {
            scsi->sess_array[i] = NULL;
        }
    } else if( scsi->sess_array_length > scsi->sess_array_capacity)
        assert(0);

    for(int i = 0; i < scsi->sess_array_capacity; ++i) {
        if(!scsi->sess_array[i]) {
            scsi->sess_array[i] = calloc(1, sizeof(*scsi->sess_array[i]));
            ++scsi->sess_array_length;
            return scsi->sess_array[i];
        }
    }
    assert(0);
    return NULL;
}

void setTgtValue(vdisk_tgt_dev* dsk, TGT_TYPE type, ...) {
    assert(dsk);
    const char* rp;
    va_list ap;
    va_start(ap, type);
    switch(type) {
        case TGT_SESS:
            dsk->sess_h = va_arg(ap, uint64_t);
            break;
        case TGT_WWN:
            dsk->wwn = va_arg(ap, uint64_t);
            break;
        case TGT_STR:
            rp = va_arg(ap,const char*);
            dsk->str = strdup(rp);
            break;
        default:
            assert(0);
    }
    va_end(ap);
}

static void
saveMessageInReceiveList(SCSIPath* scsi, char* pbuf, int length, Boolean isEvent, uint64_t wwn, struct timespec ntime) {
    int res;
    SCSIREC* recv;
    if(!length) {
        return ;    
    }

    res = pthread_mutex_lock(&scsi->recv_mutex);
    if(res) {
        RAISE(PTHREAD_MUTEX_ERROR);
    }
    recv = isEvent ? scsi->recv_event_head: scsi->recv_general_head;
    while(recv != NULL) {
        if(recv->busy == FALSE || recv->next == NULL) {
            break;
        }
        recv = recv->next;
    }
    if(recv == NULL || (recv->next == NULL && recv->busy == TRUE)) {
        if(recv == NULL) {
            SCSIREC** hde = isEvent ? &scsi->recv_event_head : &scsi->recv_general_head;
            *hde = (SCSIREC*)calloc(1, sizeof(SCSIREC));
            if(!(*hde))
                RAISE(MALLOC_ERROR);
            recv = *hde;
        } else {
            recv->next = (SCSIREC*)calloc(1, sizeof(SCSIREC));
            if(!recv->next)
                RAISE(MALLOC_ERROR);
            recv = recv->next;
        }
    }
    memset(recv, 0, sizeof(SCSIREC) - sizeof(struct a *));
    recv->busy = TRUE;
    if(isEvent) {
        recv->ntime.tv_sec = ntime.tv_sec;
        recv->ntime.tv_nsec = ntime.tv_nsec;
        recv->isEvent = TRUE;
        scsi->recv_event_length++;
    } else {
        recv->isEvent = FALSE;
        scsi->recv_general_length++;
    }
    recv->wwn = wwn;
    recv->length = length;

    memcpy(recv->buf, pbuf, length);
        
    res = pthread_mutex_unlock(&scsi->recv_mutex);
    if(res) 
        RAISE(PTHREAD_MUTEX_ERROR);
}

/**
 *  obselete this : cdb[9] == 0xff && cdb[2] == 0xff  master -> slave wwn 
 *  cdb[9] == 0xfe && dfb[2] == 0xfe  ptpd   
 **/ 
static void exec_write(struct vdisk_cmd *vcmd, vdisk_tgt_dev* dsk_ptr) {
    struct scst_user_scsi_cmd_exec *cmd = &vcmd->cmd->exec_cmd;
    uint8_t *cdb = cmd->cdb;
    char* pbuf = (char*)cmd->pbuf;
    int res;
    SCSIPath* scsi = vcmd->scsi;

    if(cdb[2] == 0xfe && cdb[9] == 0xfe) {  //ptp
        Boolean isEvent = (((pbuf[0] & 0x0f) < 4) && ((pbuf[0] & 0x0f) >= 0));
        uint16_t length = (cdb[13] & 0xff)| (cdb[12] << 8); 
        if(!length) {
            return ;    
        }

        if(isEvent && vcmd->ntime.tv_sec == 0 && vcmd->ntime.tv_sec == 0) {
            res = clock_gettime(CLOCK_REALTIME, &vcmd->ntime);
            if(res == -1) {
                res = errno;
                DBG("exec_write->clock_gettime: %s", STRERROR(res));
                RAISE(GENER_ERROR);
            }
        }

        saveMessageInReceiveList(scsi, pbuf, length, isEvent, dsk_ptr->wwn, vcmd->ntime);
    } 
    return ;
}

static void exec_inquiry(struct vdisk_cmd *vcmd) {
    struct scst_user_scsi_cmd_exec *cmd = &vcmd->cmd->exec_cmd;
	struct scst_user_scsi_cmd_reply_exec *reply = &vcmd->reply->exec_reply;
	int resp_len = 0; //response length
    int length = cmd->bufflen; //command's buffer length
    uint8_t *cdb = cmd->cdb;
    uint8_t *address = (uint8_t*)(unsigned long)cmd->pbuf;
    uint8_t buf[INQ_BUF_SZ];
    SCSIPath* scsi = vcmd->scsi;
    uint64_t wwn = scsi->info.wwn;
    int i;

    if (cmd->cdb[1] & CMDDT) {
		set_cmd_error(vcmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
	    return ;
	}
    memset(buf, 0, sizeof(buf));
    buf[0] = TYPE_SCANNER; 
    if(cdb[1] & EVPD) {
        DBG("EVPD ingore\n");
    } else {
        buf[2] = 0x06; //SPC-4 
        buf[3] = 0x12; //hisup  rsp data
        buf[4] = 31;  //想要发送36btyes
        buf[6] = 1; /* MultiP 1 */
		buf[7] = 2;

        memcpy(&buf[8], VENDOR, 8); //T10 VENDOR IDENTIFICATION
        memset(&buf[16], 0 , 16); //PRODUCT IDENTIFICATION
        // int len = min(strlen(PRODUCT_IDENTIFICATION), (size_t)16);
        // memcpy(&buf[16], PRODUCT_IDENTIFICATION, len);
        memcpy(&buf[18], "ptpinq", 6);
        // buf[24] = 0x20; 
        // buf[25] = 0x00;
        // buf[26] = 0x00;
        // buf[27] = 0x24;
        // buf[28] = 0xff;
        // buf[29] = 0x9c;
        // buf[30] = 0xdc;
        // buf[31] = 0x8e;
        for(i = 0; i < 8; ++i) {
            buf[31 - i] = (wwn >> (i * 8)) & 0xff;
            // (wwn & (0xFF << (i * 8)));
        }

        memcpy(&buf[32], FIO_REV, 4); //PRODUCT REVISION LEVEL
        resp_len = buf[4] + 5;
    }

    if (length > resp_len)
		length = resp_len;
    memcpy(address, buf, length); // copy to reply.pbuf

    if (length < reply->resp_data_len)
		set_resp_data_len(vcmd, length);

    return ;
}

static Boolean 
do_exec(struct vdisk_cmd *vcmd) {
    Boolean res = TRUE;
    struct scst_user_scsi_cmd_reply_exec* reply_exec = &vcmd->reply->exec_reply;
    struct scst_user_scsi_cmd_exec* cmd = &vcmd->cmd->exec_cmd;
    uint8_t *cdb = cmd->cdb;
    unsigned int opcode = cdb[0];
    vdisk_tgt_dev* dsk_ptr;

    memset(vcmd->reply,0 , sizeof(*vcmd->reply));
    vcmd->reply->cmd_h = vcmd->cmd->cmd_h;
    vcmd->reply->subcode = vcmd->cmd->subcode;
    reply_exec->reply_type = SCST_EXEC_REPLY_COMPLETED;

    vcmd->may_need_to_free_pbuf = 0;

    if((cmd->pbuf == 0) && (cmd->alloc_len != 0)) {
        cmd->pbuf =(unsigned long)align_alloc(cmd->alloc_len);
        memset((void*)cmd->pbuf, 0, cmd->alloc_len);
        vcmd->may_need_to_free_pbuf = 1;
        reply_exec->pbuf = cmd->pbuf;
        if(cmd->pbuf == 0) {
            set_busy(vcmd);
            return res;
        }
    }

    if(cmd->data_direction & SCST_DATA_READ) {
        reply_exec->resp_data_len = cmd->bufflen;
    }
#ifdef PTPD_DBG
    //show opcode 
    unsigned int j = 0;
    
    // flockfile(stdout);
    for(; j < ARRAY_SIZE(scsi_opcode);++j) {
        if(opcode == scsi_opcode[j])
            break;
    }
    if(j >= ARRAY_SIZE(scsi_opcode)) {
        DBG(">>>>>>>>>>>>log: opcode out of range \n");
        abort();
    } else {
        DBG("@@@@@@@log: opcode = %s\n", scsi_opcode_string[j]);
    }
    // funlockfile(stdout);
#endif    
    switch (opcode) {
        case INQUIRY:
            exec_inquiry(vcmd);
            break;
        case WRITE_6:
        case WRITE_10:
        case WRITE_12:
        case WRITE_16:
            dsk_ptr = findtgtDev(vcmd->scsi, TGT_SESS, cmd->sess_h);
            if(dsk_ptr == NULL) {
                set_cmd_error(vcmd,
				    SCST_LOAD_SENSE(scst_sense_hardw_error));
				return res;
            }
            exec_write(vcmd, dsk_ptr);
            break;
    }
    return res;
}

static Boolean
process_cmd(struct vdisk_cmd *vcmd) {
    Boolean ret = TRUE;
    struct scst_user_get_cmd *cmd = vcmd->cmd;
	// struct scst_user_reply_cmd *reply = vcmd->reply;
    switch(cmd->subcode) {
        case SCST_USER_ATTACH_SESS:
        case SCST_USER_DETACH_SESS:
            ret = do_sess(vcmd);
            break;    
        case SCST_USER_PARSE:
            ret = do_parse(vcmd);
            break;
        case SCST_USER_ALLOC_MEM:
            ret = do_alloc_mem(vcmd);
            break;
        case SCST_USER_EXEC:
            ret = do_exec(vcmd);
            break;  
        case SCST_USER_ON_FREE_CMD:
            ret = do_on_free_cmd(vcmd);
            break;
        case SCST_USER_ON_CACHED_MEM_FREE:
            ret = do_cached_mem_free(vcmd);
            break;
        case SCST_USER_TASK_MGMT_RECEIVED:
            ret = do_tm(vcmd, 0);
            break;
        case SCST_USER_TASK_MGMT_DONE:
            ret = do_tm(vcmd, 1);
            break;  
        default:
            ret = FALSE;
    }
    return ret;
}
    
void* main_loop(void* arg) {
    sigset_t sigset;
    SCSIPath* scsi = (SCSIPath*)arg;
    struct pollfd pl;
    int res,i,j,res2 ;
    struct vdisk_cmd vcmd = {
        .scsi = scsi
    }; 
    Boolean ret = TRUE;
    
    res = sigemptyset(&sigset);
    if(res == -1) 
        RAISE(SIG_EMPTY_SET_ERROR);
    
    res = sigaddset(&sigset, SIGALRM);
    if(res == -1) 
        RAISE(SIG_ADD_SET_ERROR);
    
    res = sigaddset(&sigset, SIGPOLL);
    if(res == -1) 
        RAISE(SIG_ADD_SET_ERROR);

    res = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
    if(res == -1) RAISE(SIG_MASK_ERROR);

    // int oldState = setPthreadCancelState(PTHREAD_CANCEL_ENABLE);
    // if(oldState == PTHREAD_CANCEL_ENABLE) {
    //     DBG("a");
    // } else {
    //     DBG("b");
    // }
    // int oldType = setPthreadCancelType(PTHREAD_CANCEL_DEFERRED);
    // if(oldType == PTHREAD_CANCEL_DEFERRED) {
    //     DBG("C");
    // } else {
    //     DBG("d");
    // }


    memset(&pl, 0, sizeof(pl));
    pl.fd = scsi->scst_usr_fd;
    pl.events = POLLIN;
#define MULTI_CMDS_CNT 2
    struct 
    {
        struct scst_user_reply_cmd replies[MULTI_CMDS_CNT];
        struct scst_user_get_multi multi_cmd;
        struct scst_user_get_cmd cmds[MULTI_CMDS_CNT];
    } multi;
    memset(&multi, 0, sizeof(multi));
    multi.multi_cmd.preplies = (aligned_u64)&multi.replies[0];
    multi.multi_cmd.replies_cnt = 0;
    multi.multi_cmd.replies_done = 0;
    multi.multi_cmd.cmds_cnt = MULTI_CMDS_CNT;
    
    while(1) {
        res = ioctl(scsi->scst_usr_fd, SCST_USER_REPLY_AND_GET_MULTI, &multi.multi_cmd);
        if(res == -1) {
            res = errno;
            switch(res) {
                case ESRCH:
			    case EBUSY: 
                    DBG("main_loop: ESRCH/EBUSY\n");
                    multi.multi_cmd.preplies = (uintptr_t)&multi.replies[0];
                    multi.multi_cmd.replies_cnt = 0;
                    multi.multi_cmd.cmds_cnt = MULTI_CMDS_CNT;
                case EINTR:
                    // DBG("main_loop: EINTR\n");
                    // multi.multi_cmd.preplies = (uintptr_t)&multi.replies[0];
                    // multi.multi_cmd.replies_cnt = 0;
                    // multi.multi_cmd.cmds_cnt = MULTI_CMDS_CNT;
				    continue;
                case EAGAIN:
                    multi.multi_cmd.preplies = (uintptr_t)&multi.replies[0];
                    multi.multi_cmd.replies_cnt = 0;
                    multi.multi_cmd.cmds_cnt = MULTI_CMDS_CNT;
                    break;
                default:
                    multi.multi_cmd.preplies = (uintptr_t)&multi.replies[0];
                    multi.multi_cmd.replies_cnt = 0;
                    multi.multi_cmd.cmds_cnt = MULTI_CMDS_CNT;
                    continue;
            }
again_poll:
            res = poll(&pl, 1, 100);
            if(res > 0)
                continue;
            else if(res == 0) {
                goto again_poll;

            }else {
                res = errno;
                if(res != EINTR)
                    DBG("main_loop poll:%s\n", STRERROR(res));
                goto again_poll;
            }
        }
        if(multi.multi_cmd.cmds_cnt == 0) {
            multi.multi_cmd.preplies = (uintptr_t)&multi.replies[0];
            multi.multi_cmd.replies_cnt = 0;
            multi.multi_cmd.cmds_cnt = MULTI_CMDS_CNT;
            continue;
        }
        if (multi.multi_cmd.replies_done < multi.multi_cmd.replies_cnt) {
			multi.multi_cmd.preplies = (uintptr_t)&multi.replies[multi.multi_cmd.replies_done];
			multi.multi_cmd.replies_cnt = multi.multi_cmd.replies_cnt - multi.multi_cmd.replies_done;
			multi.multi_cmd.cmds_cnt = MULTI_CMDS_CNT;
			continue;
		}        
        multi.multi_cmd.preplies = (uintptr_t)&multi.replies[0];
        for (i = 0, j = 0; i < multi.multi_cmd.cmds_cnt; i++, j++) {
            res2 = clock_gettime(CLOCK_REALTIME, &vcmd.ntime);
            if(res2 == -1) {
                res2 = errno;
                DBG("error clock_gettime: %s\n", STRERROR(res2));
                // abort();
                vcmd.ntime.tv_sec = 0;
                vcmd.ntime.tv_nsec = 0;
            }
            vcmd.cmd = &multi.cmds[i];
			vcmd.reply = &multi.replies[j];
            ret = process_cmd(&vcmd);
            // if(ret == FALSE) {
            //     return (void*)ret;
            // }
        }
        multi.multi_cmd.replies_cnt = j;
		multi.multi_cmd.cmds_cnt = MULTI_CMDS_CNT;
    }
    assert(0);
    return (void*)(long)ret;
}


static 
void refresh(SCSIPath* scsi) {
    static char fileName[64] = {};
    static Boolean Ini = TRUE;
    if(Ini == TRUE) {
        Ini = FALSE;
        memset(&fileName[0], '\0', sizeof(fileName));
        strcpy(&fileName[0], "/sys/class/scsi_host/hostn");
        strcat(&fileName[0],"/scan");
    }
    int fd, n;
    int res;
    for(int i = 0; i < 6; ++i) {
        fileName[INDEXN] = 48 + i;
        fd = open(fileName, O_WRONLY);
        if(fd == -1) {
            res = errno;
            DBG("refresh open %s error: %s\n", fileName, STRERROR(res));
            continue;
        }
        n = write(fd, LOAD_, sizeof(LOAD_));
        if(n == -1) {
            DBG("refresh write %s error: %s\n", fileName, STRERROR(res));
        } else 
            fsync(fd);
        close(fd);
    }
}

static 
Boolean EndValid(SCSIEnd* end_ptr) {
    return end_ptr && end_ptr->fd && end_ptr->sess_h && end_ptr->dev_str && end_ptr->wwn ? TRUE : FALSE;
}

static 
void updateValidEnd(SCSIPath* scsi) {
    assert(scsi);
    int i;
    SCSIEnd** array = scsi->invalid_end_array;
    SCSIEnd* end_ptr;

    for(i = 0; i < scsi->invalid_end_array_capacity; ++i) {
        if(array[i] && EndValid(array[i])){
            end_ptr = removeEnd(scsi, INVALID_ARRAY, i, FALSE);
            addEnd(scsi, END_ADD_TO_VALID, end_ptr);
        }
    }    
}

void SendAllInquiry(SCSIPath* scsi) {
    int i = 0;
    int res;
    for(i = 0; i < scsi->invalid_end_array_capacity; ++i) {
        if(scsi->invalid_end_array[i] && scsi->invalid_end_array[i]->fd) {
            res = CINQUIRY(scsi->invalid_end_array[i]->fd);
            if(!res) {
                DBG("sentINQUIRYByFd fails\n");
        }
        } 
    }
    for(i = 0; i < scsi->valid_end_array_capacity; ++i) {
        if(scsi->valid_end_array[i] && scsi->valid_end_array[i]->fd) {
            res = CINQUIRY(scsi->valid_end_array[i]->fd);
            if(!res) {
                DBG("sentINQUIRYByFd fails\n");
            }
        } 
    }
}

void* end_fresh_loop(void* arg) {
    assert(arg);

    SCSIPath* scsi = (SCSIPath*)arg; 
    char buf[END_FRESH_BUF_SIZE] = {0};
    char* line;
    FILE* pp;
    long timenow, timeforinquiry;

    pp = popen("scstadmin -config /etc/scst.conf", "r");
    if(!pp)
        RAISE(POPEN_ERROR);
    while(1) {
        line = fgets(buf, END_FRESH_BUF_SIZE, pp);
        if(line == NULL) break;
        if(strstr(line, SCST_ADMIN_ERROR_INFO) != NULL) {
            DBG("scstadmin initialize fail\n");
            RAISE(SCSTADMIN_ERROR);
        }
    }
    if(pclose(pp) == -1)
        RAISE(PCLOSE_ERROR);

    refresh(scsi);
    scanSCSIEquipmemt(scsi);
    timenow = myclock();
    timeforinquiry = myclock();
    while(1) {
        pthread_testcancel();

        if(myclock() - timenow >= END_FRESH_TIME_INTERVAL) {
            refresh(scsi);
            scanSCSIEquipmemt(scsi);
            timenow = myclock();
        }

        if(myclock() - timeforinquiry >= (END_FRESH_TIME_INTERVAL / 4)) {
            SendAllInquiry(scsi);
            timeforinquiry = myclock();
        }

        readFromTarget(scsi);
        updateValidEnd(scsi);
    }
    assert(0);
}

static
uint64_t translateStrToUl(const char* str) {
    char *end_ptr;
    uint64_t res = strtoul(str, &end_ptr, HEX);
    if(end_ptr == str || res == ULONG_MAX) 
        RAISE(EINVAL_ERROR);
    return res;
}

Boolean 
SCSIInit(SCSIPath* scsi, RunTimeOpts * rtOpts, PtpClock * ptpClock) {
    assert(scsi);
    assert(rtOpts);
    assert(ptpClock);

    int j = 0, i = 0;
    pthread_mutexattr_t attr;
    int res = 0;
    int retryTime = 0;

    if(rtOpts->unicastDestinationsSet) {
        if(strlen(rtOpts->unicastDestinations) > 0) {
            int found = 0;
            char* token, *save_ptr;
            char* tex__;
            char* tex_ = strdup(rtOpts->unicastDestinations);
            if(!tex_)
                RAISE(MALLOC_ERROR);
            for(tex__ = tex_; found < UNICAST_MAX_DESTINATIONS; tex__ = NULL) {
                token = strtok_r(tex__, ",;\t", &save_ptr);
                if(token == NULL)
                    break;
                ptpClock->unicastDestinations[found].transportAddressSCSI = translateStrToUl(token);
                ++found;
            }

            if(tex_) 
                free(tex_);
            
            ptpClock->unicastDestinationCount = found;
        }
    }

    if(rtOpts->delayMechanism==P2P && rtOpts->ipMode==IPMODE_UNICAST) {
        ptpClock->unicastPeerDestination.transportAddressSCSI = translateStrToUl(rtOpts->unicastPeerDestination);
    }

    if(rtOpts->directIOEnabled)
        scsi->dioEnabled = TRUE;
    else 
        scsi->dioEnabled = FALSE;

    if(!testSCSIInterface(rtOpts->ifaceName, rtOpts,&scsi->info))
        return FALSE;

    if(!checkHBAPortState(rtOpts->ifaceName))
        return FALSE; 

    scsi->scst_usr_fd = open(SCST_USER_DEV, O_RDWR | O_NONBLOCK);
    if(scsi->scst_usr_fd == -1) {
        if(errno == ENOENT) {
            system(SHELLSCRIPT);
            usleep(10 * 1000);
            scsi->scst_usr_fd = open(SCST_USER_DEV, O_RDWR | O_NONBLOCK);
            if(scsi->scst_usr_fd == -1) 
                RAISE(OPEN_ERROR);
        } else 
            RAISE(OPEN_ERROR);
    }
    
    scsi->sess_array = calloc(1, sizeof(*scsi->sess_array) * DEV_SESS_NUMBER);
    if(!scsi->sess_array)
        RAISE(MALLOC_ERROR);
    scsi->sess_array_capacity = DEV_SESS_NUMBER;

    memset(&scsi->desc, 0, sizeof(scsi->desc));
    scsi->desc.version_str = (unsigned long)DEV_USER_VERSION;
    scsi->desc.license_str = (unsigned long)"GPL";
    strncpy(scsi->desc.name, DEVICE_NAME, sizeof(scsi->desc.name) - 1);
    scsi->desc.name[sizeof(scsi->desc.name) - 1] = '\0';
    scsi->desc.type = TYPE_SCANNER;
    scsi->desc.block_size = (1 << 9);
    scsi->desc.opt.parse_type = SCST_USER_PARSE_STANDARD;
    scsi->desc.opt.on_free_cmd_type = SCST_USER_ON_FREE_CMD_IGNORE;
    scsi->desc.opt.memory_reuse_type = SCST_USER_MEM_REUSE_ALL;
    scsi->desc.opt.tst = SCST_TST_1_SEP_TASK_SETS;
	scsi->desc.opt.tmf_only = 0;
	scsi->desc.opt.queue_alg = SCST_QUEUE_ALG_1_UNRESTRICTED_REORDER;
	scsi->desc.opt.qerr = SCST_QERR_0_ALL_RESUME;
	scsi->desc.opt.d_sense = SCST_D_SENSE_0_FIXED_SENSE;

    do {
        res = ioctl(scsi->scst_usr_fd, SCST_USER_REGISTER_DEVICE, &scsi->desc);
        if(!res) 
            break;
        ++retryTime;
        sleep(5);
    } while(retryTime < 5);
    if(retryTime >= 5) 
        RAISE(SCST_USER_REGISTER_DEVICE_ERROR);

    res = pthread_mutexattr_init(&attr);
    if(res) 
        RAISE(PTHREAD_MUTEX_ATTR_INIT_ERROR);
    
#ifdef PTPD_DBG
    res =  pthread_mutexattr_settype(&attr,PTHREAD_MUTEX_ERRORCHECK );
    if(res) {
        res = errno;
        DBG("set PTHREAD_MUTEX_ERRORCHECK fail: %s", STRERROR(res));
    }
#endif
    res = pthread_rwlock_init(&scsi->fd_rwlock, NULL);
    if(res)
        RAISE(PTHREAD_RWLOCK_INIT_ERROR);
    scsi->fd_rwlock_init = TRUE;

    res = pthread_mutex_init(&scsi->recv_mutex, &attr);
    if(res) 
        RAISE(PTHREAD_MUTEX_INIT_ERROR);
    scsi->recv_mutex_init = TRUE;

    res = pthread_mutexattr_destroy(&attr);
    if(res) 
        RAISE(PTHREAD_MUTEX_ATTR_DESTROY_ERROR);

    //Create Thread
    for(i = 0, j = 0;i < SCST_THREAD; ++i) {
        res = pthread_create(&scsi->scst_thread[i], NULL, main_loop, scsi);
        if(res) {
            res = errno;
            if(res == EAGAIN)
                continue;
        }
        ++j;
    }
    if(j == 0)
        RAISE(PTHREAD_CREATE_ERROR);

    res = pthread_create(&scsi->end_refresh_thread, NULL, end_fresh_loop, scsi);
    if(res) 
        RAISE(PTHREAD_CREATE_ERROR);
    

    // res = pthread_create(&scsi->receive_scsi_back_thread, NULL, receive_scsi_back, scsi);
    // if(res)
    //     RAISE(PTHREAD_CREATE_ERROR);
    
    // system("scstadmin -config /etc/scst.conf");

    // refresh(scsi, rtOpts);
    // if(!scanSCSIEquipmemt(scsi))
        // return FALSE;

    // usleep(1000 * 100);
    // readFromTarget(scsi);

    return TRUE;   
}

ssize_t scsiRecvEvent(Octet * buf, TimeInternal * time, SCSIPath * scsi, int flags) {
    ssize_t ret = 0;
    scsi->lastDestAddr = 0;
    SCSIREC* recvptr = NULL;
    int res;
    scsi->lastDestAddr = 0;

    if(scsi->recv_event_length <= 0)
        return 0; 
    res = pthread_mutex_lock(&scsi->recv_mutex);
    if(res) 
        RAISE(PTHREAD_MUTEX_ERROR);
    recvptr = scsi->recv_event_head;
    while(recvptr != NULL && recvptr->busy != TRUE)
        recvptr = recvptr->next;
    if(!recvptr) {
        DBG("recvptr == NULL");
        pthread_mutex_unlock(&scsi->recv_mutex);
        return 0;
    }
    scsi->recv_event_length--;
    memcpy(buf, recvptr->buf, recvptr->length);
    recvptr->busy = FALSE;
    time->seconds = recvptr->ntime.tv_sec;
    time->nanoseconds = recvptr->ntime.tv_nsec;
    ret = recvptr->length;
    scsi->lastSourceAddr = recvptr->wwn;

    res = pthread_mutex_unlock(&scsi->recv_mutex);
    if(res) 
        RAISE(PTHREAD_MUTEX_ERROR);
    
    scsi->receivedPacketsTotal++;
    if(!scsi->lastSourceAddr || scsi->lastSourceAddr != scsi->info.wwn)
        scsi->receivedPackets++;

    scsi->lastDestAddr = scsi->info.wwn;

    return ret;
}

ssize_t scsiRecvGeneral(Octet * buf, SCSIPath* scsi) {
    ssize_t ret = 0;
    SCSIREC* recvptr = NULL;
    int res;
    scsi->lastSourceAddr = 0;

    if(scsi->recv_general_length <= 0)
        return 0; 

    res = pthread_mutex_lock(&scsi->recv_mutex);
    if(res) 
        RAISE(PTHREAD_MUTEX_ERROR);

    recvptr = scsi->recv_general_head;
    while(recvptr != NULL && recvptr->isEvent != FALSE)
        recvptr = recvptr->next;
    if(!recvptr) {
        DBG("recvptr == NULL");
        pthread_mutex_unlock(&scsi->recv_mutex);
        return 0;
    }
    scsi->recv_general_length--;
    memcpy(buf, recvptr->buf, recvptr->length);
    recvptr->busy = FALSE;
    ret = recvptr->length;
    scsi->lastSourceAddr = recvptr->wwn;

    res = pthread_mutex_unlock(&scsi->recv_mutex);
    if(res) 
        RAISE(PTHREAD_MUTEX_ERROR);
    scsi->receivedPacketsTotal++;

    if(!scsi->lastSourceAddr || (scsi->lastSourceAddr != scsi->info.wwn))
        scsi->receivedPackets++;
    
    return ret;
}

static 
int findValidFd(SCSIPath* scsi, uint64_t dst) {
    assert(scsi);
    int res = -1;
    if(!scsi->valid_end_array_length || !scsi->valid_end_array_capacity)
        return -1;
    int rw = pthread_rwlock_rdlock(&scsi->fd_rwlock);
    if(rw)
        RAISE(PTHREAD_RDLOCK_ERROR);
    pthread_cleanup_push(cleanUpWRLock, &scsi->fd_rwlock);
    for(int i = 0; i < scsi->valid_end_array_capacity; ++i) {
        if(scsi->valid_end_array[i] && scsi->valid_end_array[i]->wwn == dst) {
            res = scsi->valid_end_array[i]->fd;
            break;
        }
    }
    pthread_cleanup_pop(1);
    return res;
}

Boolean 
scsiSendGeneral(Octet * buf, UInteger16 length, SCSIPath * scsi, 
const RunTimeOpts *rtOpts, uint64_t destinationAddress) {
    struct timespec ntime;
    int i;
    Boolean res = TRUE, ret = TRUE;
    refreshSGIO();
    int sendn = 0;
    cmdp[2] = 0xfe;
    cmdp[9] = 0xfe;
    if(destinationAddress) {
        *(char *)(buf + 6) |= PTP_UNICAST;
        int fd = findValidFd(scsi, destinationAddress);
        if(fd != -1) {
            res = Command(scsi, fd,WRITE_16, (unsigned char*)buf, length, NULL);
            if(!res) {
                ret = FALSE;
                DBG("write to %lx fails %s", destinationAddress, STRERROR(errno));
            } 
            ++sendn;
        } else 
            ret = FALSE;
    } else {
        for(i = 0; i < scsi->valid_end_array_capacity; i++) {
            if(scsi->valid_end_array[i]) {
                res = Command(scsi, scsi->valid_end_array[i]->fd,WRITE_16, (unsigned char*)buf, length, NULL);
                if(!res) {
                    ret = FALSE;
                    DBG("write to %s fails %s", scsi->valid_end_array[i]->dev_str, STRERROR(errno));
                    continue;
                }
                ++sendn;
            }
        }
    }
    if(sendn > 0) {
        saveMessageInReceiveList(scsi,buf,length,FALSE,scsi->info.wwn, ntime);
        if(ret == TRUE) {
            scsi->sentPackets++;
            scsi->sentPacketsTotal++;
        }
    }
    return TRUE;
}

ssize_t 
scsiSendEvent(Octet * buf, UInteger16 length, SCSIPath * scsi, 
const RunTimeOpts *rtOpts, uint64_t destinationAddress, TimeInternal * tim)
{
    struct timespec ntime = {0,0};
    int i;
    Boolean ret = TRUE;
    int res = 0;
    int sendn = 0;
    refreshSGIO();
    cmdp[2] = 0xfe;
    cmdp[9] = 0xfe;
    // res = clock_gettime(CLOCK_REALTIME, &ntime);
    // if(res == -1) {
    //     res = errno;
    //     DBG("%s\n", STRERROR(res));
    //     RAISE(GENER_ERROR);
    // }
    if(destinationAddress) {
        *(char *)(buf + 6) |= PTP_UNICAST;
        int fd = findValidFd(scsi, destinationAddress);
        if(fd != -1) {
            res = Command(scsi, fd,WRITE_16, (unsigned char*)buf, length, &ntime);
            if(!res) {
                ret = FALSE;
                DBG("write to %lx fails %s", destinationAddress, STRERROR(errno));
            }
            ++sendn;
        } else 
            ret = FALSE;
    } else {
        struct timespec ntimes[scsi->valid_end_array_length];
        memset(ntimes, 0 ,sizeof(ntimes));
        int j = 0;
        for(i = 0; i < scsi->valid_end_array_capacity; i++) {
            if(scsi->valid_end_array[i]) {
                res = Command(scsi, scsi->valid_end_array[i]->fd,WRITE_16, (unsigned char*)buf, length, &ntimes[j]);
                if(!res) {
                    ret = FALSE;
                    DBG("write to %s fails %s", scsi->valid_end_array[i]->dev_str, STRERROR(errno));
                    continue;
                }
                ++sendn;
                ++j;
            }
        }
        for(i = 0; i < j; ++i) {
            ntime.tv_sec += ntimes[i].tv_sec;
            ntime.tv_nsec += ntimes[i].tv_nsec;
        }
        ntime.tv_sec /= j;
        ntime.tv_nsec /= j;
    }
    // res = clock_gettime(CLOCK_REALTIME, &ntime_);
    // if(sendn > 0) {
    //     printf("%ld,%ld\n", ntime.tv_sec, ntime.tv_nsec);
    //     printf("%ld,%ld\n", ntime_.tv_sec, ntime_.tv_nsec);
    //     abort();
    // }
    if(sendn > 0) {
        if(res == -1) {
            res = errno;
            DBG("scsiSendEvent->clock_gettime: %s", STRERROR(res));
            RAISE(GENER_ERROR);
        }
        tim->seconds = ntime.tv_sec;
        tim->nanoseconds = ntime.tv_nsec;
        saveMessageInReceiveList(scsi,buf,length,TRUE,scsi->info.wwn, ntime);
        if(ret == TRUE) {
            scsi->sentPackets++;
            scsi->sentPacketsTotal++;
        }
    }
    return TRUE;
}

ssize_t 
scsiSendPeerEvent(Octet * buf, UInteger16 length, SCSIPath * scsi, 
const RunTimeOpts *rtOpts, uint64_t destinationAddress, TimeInternal * tim)
{
    struct timespec ntime = {0, 0};
    int i;
    Boolean res = TRUE, ret = TRUE;
    refreshSGIO();
    int sendn = 0;
    cmdp[2] = 0xfe;
    cmdp[9] = 0xfe;
    // res = clock_gettime(CLOCK_REALTIME, &ntime);
    // if(res == -1) {
    //     res = errno;
    //     DBG("%s\n", STRERROR(res));
    //     RAISE(GENER_ERROR);
    // }
    if(destinationAddress) {
        *(char *)(buf + 6) |= PTP_UNICAST;
        int fd = findValidFd(scsi, destinationAddress);
        if(fd != -1) {
            res = Command(scsi, fd,WRITE_16, (unsigned char*)buf, length, &ntime);
            if(!res) {
                ret = FALSE;
                DBG("write to %lx fails %s", destinationAddress, STRERROR(errno));
            } 
            ++sendn;
        } else 
             ret = FALSE;
    } else {
        int j = 0;
        struct timespec ntimes[scsi->valid_end_array_length];
        memset(ntimes,0, sizeof(ntimes));
        for(i = 0; i < scsi->valid_end_array_capacity; i++) {
            if(scsi->valid_end_array[i]) {
                res = Command(scsi, scsi->valid_end_array[i]->fd,WRITE_16, (unsigned char*)buf, length, &ntimes[j]);
                if(!res) {
                    ret = FALSE;
                    DBG("write to %s fails %s", scsi->valid_end_array[i]->dev_str, STRERROR(errno));
                    continue;
                }
                ++j;
                ++sendn;
            }
        }
        for(i = 0; i < j; ++i) {
            ntime.tv_sec += ntimes[i].tv_sec;
            ntime.tv_nsec += ntimes[i].tv_nsec;
        }
        ntime.tv_sec /= j;
        ntime.tv_nsec /= j;
    }
    if(sendn > 0) {
        if(res == -1) {
            res = errno;
            DBG("scsiSendEvent->clock_gettime: %s", STRERROR(res));
            RAISE(GENER_ERROR);
        }
        tim->seconds = ntime.tv_sec;
        tim->nanoseconds = ntime.tv_nsec;
        saveMessageInReceiveList(scsi,buf,length,TRUE,scsi->info.wwn, ntime);
        if(ret == TRUE) {
            scsi->sentPackets++;
            scsi->sentPacketsTotal++;
        }
    }
    return TRUE;
}

ssize_t 
scsiSendPeerGeneral(Octet * buf, UInteger16 length, SCSIPath* scsi,
 const RunTimeOpts *rtOpts, uint64_t destinationAddress)
{
    struct timespec ntime;
    int i;
    Boolean res = TRUE, ret = TRUE;
    refreshSGIO();
    int sendn = 0;
    cmdp[2] = 0xfe;
    cmdp[9] = 0xfe;
    if(destinationAddress) {
        *(char *)(buf + 6) |= PTP_UNICAST;
        int fd = findValidFd(scsi, destinationAddress);
        if(fd != -1) {
            res = Command(scsi, fd,WRITE_16, (unsigned char*)buf, length, NULL);
            if(!res) {
                ret = FALSE;
                DBG("write to %lx fails %s", destinationAddress, STRERROR(errno));
            }
            ++sendn;
        } else 
            ret = FALSE;
    }
    else {
        for(i = 0; i < scsi->valid_end_array_capacity; i++) {
            if(scsi->valid_end_array[i]) {
                res = Command(scsi, scsi->valid_end_array[i]->fd,WRITE_16, (unsigned char*)buf, length, NULL);
                if(!res) {
                    ret = FALSE;
                    DBG("write to %s fails %s", scsi->valid_end_array[i]->dev_str, STRERROR(errno));
                    continue;
                }
                ++sendn;
            }
        }
    }
    if(sendn > 0) {
        saveMessageInReceiveList(scsi,buf,length,FALSE,scsi->info.wwn, ntime);
        if(ret == TRUE) {
            scsi->sentPackets++;
            scsi->sentPacketsTotal++;
        }
    }
    return TRUE;
}