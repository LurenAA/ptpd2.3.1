
#include "../ptpd.h"
#include <unistd.h>


static
Boolean isEndInSlash(const char* str) {
    int len = strlen(str);

    if(!len) return FALSE;

    return  str[len - 1] == '/'? TRUE : FALSE;
}

static 
Boolean scsiinterfaceExist(const char* ifaceName) {
    DIR* dirp;
    Boolean ret = TRUE;
    struct dirent* direntp = NULL;
    int node_name_number = 0, port_state_number = 0;

    if(!strlen(ifaceName)) {
        DBG("scsiinterfaceExists called for an empty interface!");
        return FALSE;
    }

    dirp = opendir(ifaceName);
    if(!dirp) {
        DBG("scsiinterfaceExists called for a not exit directory! %s",strerror(errno));
        return FALSE;
    }

    for(direntp = readdir(dirp); 
    direntp != NULL; 
    direntp = readdir(dirp)) {
        if(!strcmp(&direntp->d_name[0], "node_name")) {
            ++node_name_number;
        }
        else if(!strcmp(&direntp->d_name[0], "port_state")) {
            ++port_state_number;
        }
        if(node_name_number == 1 && port_state_number == 1) 
            break;
    }

    if(node_name_number != 1 || port_state_number != 1) {
        DBG("node_name_number: %d, port_state_number: %d", node_name_number, port_state_number);
        ret = FALSE;
        goto end;
    }


end:
    closedir(dirp);
    return ret;
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

    if(!len) {
        DBG("getSCSIInterfaceInfo called for an empty interface!");
        return FALSE;
    }

    memset(&fileName[0], '\0', sizeof(fileName));
    strcpy(&fileName[0], ifaceName);
    if(isEndInSlash(ifaceName) == FALSE) {
        fileName[len] = '/';
        ++len;
    }
    strcat(&fileName[0], "node_name");

    fd = open(&fileName[0], O_RDONLY);
    if(fd == -1) {
        DBG("getSCSIInterfaceInfo open node_name %s", strerror(errno));
        return FALSE;
    }

    readN = read(fd, &wwn[0], 18);
    if(readN == -1 || readN != 18) {
        DBG("getSCSIInterfaceInfo read %d", readN);
        ret = FALSE;
        goto end;
    }
    wwn[readN] = '\0';
    info->wwn = strtoul(&wwn[0], &endptr, HEX);
    if(info->wwn == ULONG_MAX || endptr == &wwn[0]) {
        DBG("getSCSIInterfaceInfo strtoul");
        ret = FALSE;
        goto end;
    }
    close(fd);

    memset(&fileName[len], '\0', sizeof(fileName) - len);
    strcat(&fileName[0], "port_state");
    fd = open(&fileName[0], O_RDONLY);
    if(fd == -1) {
        DBUGDF(errno);
        return FALSE;
    }

    memset(&wwn[0], '\0', sizeof(wwn));
    readN = read(fd, &wwn[0], sizeof(wwn));
    if(readN == -1) {
        DBUGDF(errno);
        ret = FALSE;
        goto end;
    }

    if(!strncmp(&wwn[0], "Online", 6)) 
        info->online = TRUE;
    else 
        info->online = FALSE;

end:
    close(fd);
    return ret;
}
 
Boolean testSCSIInterface(char * ifaceName, const RunTimeOpts* rtOpts) {
    if(rtOpts->transport != SCSI_FC) {
        ERROR("Unsupported transport: %d\n", rtOpts->transport);
        return FALSE;
    }
    
    SCSIInterfaceInfo info;
    
    if(getSCSIInterfaceInfo(ifaceName, &info) == FALSE) 
        return FALSE;
    
    if(info.wwn == 0 || info.online != TRUE)
        return FALSE;
    
    return TRUE;
}

Boolean scsiShutdown(SCSIPath* scsi) {
    int i;
    int res;
    if(!scsi)
        return TRUE;
    for(i = 0; i < DICTIONARY_LEN; ++i) {
        if(scsi->dictionary_values[i] != NULL) {
            free((void*)scsi->dictionary_values[i]);
            scsi->dictionary_values[i] = NULL;
        }
        if(scsi->dictionary_fd[i]) {
            close(scsi->dictionary_fd[i]); 
            scsi->dictionary_fd[i] = 0;
        }
    }
    memset(&scsi->sbp[0], 0, MX_SB_LEN * sizeof(unsigned char));
    memset(&scsi->cmdp[0], 0, INQ_CMD_LEN * sizeof(unsigned char));
    memset(&scsi->dxferp[0], 0, INQ_REPLY_LEN * sizeof(unsigned char));
    memset(&scsi->io, 0 ,sizeof(sg_io_hdr_t));
    memset(&scsi->dictionary_keys[0], 0, sizeof(scsi->dictionary_keys));
    
    if(scsi->scst_usr_fd) 
        close(scsi->scst_usr_fd);

    for(i = 0; i < SCST_THREAD; ++i) {
        if(scsi->thread[i]) {
            res = pthread_cancel(scsi->thread[i]);
            if(res) {
                if(res == ESRCH) 
                    DBG("the thread %d has dead", scsi->thread[i]);
                else 
                    DBUGDF(res);
            }
        }
    }
    usleep(10 * 1000);

    for(i = 0; i < SCST_THREAD; ++i) {
        if(scsi->thread[i]) {
            res = pthread_join(scsi->thread[i], NULL);
            if(res) {
                DBUGDF(res);
            }
        }
    }

    memset(scsi->thread, 0, sizeof(scsi->thread));
    return TRUE;
}

int findEmptyPlace(const SCSIPath* scsi) {
    int i = DICTIONARY_LEN;
    if(!scsi) {
        goto out;
    }
    for(i = 0; i < DICTIONARY_LEN; ++i) {
        if(scsi->dictionary_fd[i] == 0 && 
        scsi->dictionary_keys[i] == 0 && scsi->dictionary_values[i] == NULL) {
            goto out;
        }
    }
out:
    return i;
}

//通过wwn来查找对应的下标
int findIndexInDictionaryUsingWWN(const SCSIPath* scsi, uint64_t n) {
    int i = DICTIONARY_LEN;
    if(!scsi)
        goto out;
    for(i  = 0; i < DICTIONARY_LEN; ++i) {
        if(scsi->dictionary_keys[i] == n) {
            goto out;
        }
    }
out: 
    return i;
}

//通过设备位置的字符来找
int findIndexInDictionaryUsingValue(const SCSIPath* scsi, const char* value) {
    int i = DICTIONARY_LEN;
    if(!scsi || !value) 
        goto out;
    for(i = 0; i < DICTIONARY_LEN; ++i) {
        if(scsi->dictionary_values[i] != NULL && strcmp(scsi->dictionary_values[i], value) == 0) {
            goto out;
        }
    }
out: 
    return i;
}

//使用fd来查找
int findIndexInDictionaryUsingFd(const SCSIPath* scsi, int fd) {
    int i = DICTIONARY_LEN;
    if(!scsi) 
        goto out;
    for(i = 0; i < DICTIONARY_LEN; ++i) {
        if(scsi->dictionary_fd[i] == fd) {
            goto out;
        }
    }
out:
    return i;
}

//检查poll中一个对象的状态
static Boolean 
checkPollSingle(int fd, short flags) {
    static struct pollfd plf;
    int n = 0;

    memset(&plf, 0, sizeof(struct pollfd));
    plf.fd = fd;
    plf.events = flags;
    n = poll(&plf, 1, 0);
    if(n == 0 || n  == -1) {
        DBUGDF(errno);
        return FALSE;
    }

    if((plf.revents & flags) == 0)
        return FALSE;

    return TRUE;
}

//查找出wwns中的空位
static
int findEmptyWWNPlace(uint64_t * wwns, int size) {
    int i = 0;

    for( ; i < size; ++i) {
        if(wwns[i] == 0)
            return i;
    }
    return size;
}

//检测HBA设备是否在线 host_path = /sys/class/fc_host/host5
static Boolean
checkHBAPortState(const char* host_path, int* ifonline) {
    Boolean res = TRUE;
    char fileName[MAX_FILENAME_LENGTH];
    char readBuf[PORT_STATE_LEN];
    int fd = 0;
    ssize_t rdnum = 0;
    *ifonline = 0;

    memset(&fileName[0], '\0', MAX_FILENAME_LENGTH);
    if(strlen(host_path) >= MAX_FILENAME_LENGTH) {
        DBUGDF(EINVAL);
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
        *ifonline = 1;
    } else 
        *ifonline = 0;
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
    if(!io) {
        DBUGDF(EINVAL);
        return FALSE;
    }
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
Boolean sendSCSI(sg_io_hdr_t *io, int fd) {
    Boolean res = TRUE;
    if(!io || !io->dxfer_len || !io->dxferp || !io->sbp) {
        DBUGDF(EINVAL);
        return FALSE;
    }
    if(io->cmd_len > 16 || io->cmd_len < 6 || !io->cmdp) {
        DBUGDF(EMSGSIZE);
        return FALSE;
    }

    if(checkPollSingle(fd, POLLOUT) == FALSE) {
        DBUGDF(EAGAIN);
        return FALSE;
    }

    res = write(fd, (void*)io, sizeof(sg_io_hdr_t));
    if(res != sizeof(sg_io_hdr_t) && errno != EDOM) {
        DBUGDF(EINVAL);
        return FALSE;
    }
    if(errno == EDOM) {
        DBUGDF(EDOM);
        return FALSE;
    }

    return res;
}

//保存dictionary
static Boolean
saveDictionary(SCSIPath* scsi, uint64_t wwn, const char* value, int fd, int* indexp) {
    Boolean res = TRUE;
    int index = DICTIONARY_LEN;
    if(!scsi || (wwn == 0&& !value&& fd==0)) {
        DBUGDF(EINVAL);
        return FALSE;
    }
    
    if(value && index == DICTIONARY_LEN)
        index = findIndexInDictionaryUsingValue(scsi, value);
    if(fd && index == DICTIONARY_LEN)  
        index = findIndexInDictionaryUsingFd(scsi, fd);
    if(wwn && index == DICTIONARY_LEN)
        index = findIndexInDictionaryUsingWWN(scsi, wwn);

    if(index == DICTIONARY_LEN) {
        //find empty place
        index = findEmptyPlace(scsi);
        if(index == DICTIONARY_LEN) {
            DBUGDF(ERANGE);
            return FALSE;
        }
    }
    if(indexp)
        *indexp = index;
    scsi->dictionary_fd[index] = fd != 0 ? fd : scsi->dictionary_fd[index];
    scsi->dictionary_keys[index] = wwn != 0 ? wwn : scsi->dictionary_keys[index];
    scsi->dictionary_values[index] = value != NULL ? strdup(value) : scsi->dictionary_values[index];

    return res;
}
//get fd by dev str
static Boolean 
getFdByFileName(SCSIPath* scsi, const char* dev, int* fdp) {
    Boolean res = TRUE;
    if(!scsi || !dev || !fdp) { 
        DBUGDF(EINVAL);
        return FALSE;
    }
    int index = findIndexInDictionaryUsingValue(scsi, dev);
    if(index == DICTIONARY_LEN || scsi->dictionary_fd[index] == 0) {
        //no this fd before
        int fd = open(dev, O_RDWR | O_NONBLOCK);
        if(fd == -1) {
            DBUGDF(EINVAL);
            return FALSE;
        }
        res = saveDictionary(scsi, 0, dev, fd, &index);
        if(!res) 
            return FALSE;
        *fdp = fd;
    } 

    return res;    
}

//发送SCSI请求
static Boolean
sendSCSIByDevName(sg_io_hdr_t* io, const char* dev, SCSIPath* scsi) {
    Boolean res = TRUE;
    int index;
    if(!dev) {
        DBUGDF(EINVAL);
        return FALSE;
    }
    res = getFdByFileName(scsi, dev, &index);
    if(!res) 
        return FALSE;
    res = sendSCSI(io, scsi->dictionary_fd[index]);

    return res;
}

static Boolean 
sendSCSICommandByFd(SCSIPath* scsi,  int fd,  int dxfer_direction, unsigned char cmd_len) {
    Boolean res = TRUE;
    sg_io_hdr_t* iop = &scsi->io;
    if(!scsi) {
        DBUGDF(EINVAL);
        return FALSE;
    }
    res = initSgIoHdr(iop, dxfer_direction, cmd_len, MX_SB_LEN, INQ_REPLY_LEN,
    (void*)&scsi->dxferp[0], &scsi->cmdp[0], &scsi->sbp[0], 0);
    if(res == FALSE)
        return FALSE;
    res = sendSCSI(iop, fd);

    return res;
}

static
int sendSCSICommand(SCSIPath* scsi, const char* dev) {
    Boolean res = TRUE;
    int fd;
    sg_io_hdr_t* iop = &scsi->io;
    
    if(!scsi || !dev) {
        DBUGDF(EINVAL);
        return FALSE;
    }
    res = getFdByFileName(scsi, dev, &fd);
    if(!res) 
        return FALSE;

    res = initSgIoHdr(iop, SG_DXFER_FROM_DEV, 6, MX_SB_LEN, INQ_REPLY_LEN,
    (void*)&scsi->dxferp[0], &scsi->cmdp[0], &scsi->sbp[0], 0);
    if(!res)
        return FALSE;
    
    res = sendSCSI(iop, fd);

    return res;
}

static Boolean 
sentINQUIRY(SCSIPath* scsi, const char* dev) {
    Boolean res = TRUE;
    if(!scsi || !dev) {
        DBUGDF(EINVAL);
        return FALSE;
    }
    //cdb
    memset(scsi->cmdp, 0, INQ_CMD_LEN);
    scsi->cmdp[0] = 0x12;
    scsi->cmdp[3] = INQ_REPLY_LEN >> 8; //ALLOCATION LENGTH
    scsi->cmdp[4] = INQ_REPLY_LEN & 0xff;

    res = sendSCSICommand(scsi, dev);

    return res;
}

static Boolean
sentINQUIRYByFd(SCSIPath* scsi, int fd) {
    if(!scsi ) {
        DBUGDF(EINVAL);
        return FALSE;
    }
    //cdb
    memset(scsi->cmdp, 0, INQ_CMD_LEN);
    scsi->cmdp[0] = 0x12;
    scsi->cmdp[3] = INQ_REPLY_LEN >> 8; //ALLOCATION LENGTH
    scsi->cmdp[4] = INQ_REPLY_LEN & 0xff;

    if(!sendSCSICommandByFd(scsi, fd, SG_DXFER_FROM_DEV, 6))
        return FALSE;

    return TRUE;
}

//初始化sg_io
static Boolean initAllAboutSg(SCSIPath* scsi) {
    Boolean res = TRUE;
    if(!scsi) {
        DBUGDF(EINVAL);
        return FALSE;
    }
    memset(&scsi->cmdp[0], 0, INQ_CMD_LEN);
    memset(&scsi->sbp[0], 0, MX_SB_LEN);
    memset(&scsi->dxferp[0], 0, INQ_REPLY_LEN);
    memset(&scsi->io, 0, sizeof(sg_io_hdr_t));

    sg_io_hdr_t* io = &scsi->io;
    io->cmdp = &scsi->cmdp[0];
    io->sbp = &scsi->sbp[0];
    io->dxferp = (void*)&scsi->dxferp[0];

    return res;
}

Boolean readSCSI(SCSIPath* scsi, int fd, int * readnum) {
    Boolean res = TRUE;
    
    if(!scsi) {
        DBUGDF(EINVAL);
        return FALSE;
    }
    initAllAboutSg(scsi);
    int nread = read(fd, &scsi->io, sizeof(sg_io_hdr_t));
    if(nread == -1) {
        DBUGDF(errno);
        return FALSE;
    }
    if(readnum) 
        *readnum = nread;
    if(nread != sizeof(sg_io_hdr_t)) {
        DBUGDF(EIO);
        return FALSE;
    }
    
    return res;
}

//扫描本地scsi设备,发送请求
Boolean scanSCSIEquipmemt(SCSIPath* scsi) {
    DIR* dirp;
    struct dirent* direntp;
    int res = 0;
    char tmpName[5 * strlen(DEV_PREFIX)];
    int index = DICTIONARY_LEN;
    bool isNew = false;
    int fd = 0;

    if(!scsi) {
        
        DBUGDF(EINVAL);
        return FALSE;
    }
    dirp = opendir(DEV_PREFIX);
    if(dirp == NULL) {

        DBUGDF(errno);
        return FALSE;
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
        index = findIndexInDictionaryUsingValue(scsi, &tmpName[0]);
        if(index == DICTIONARY_LEN) {
            //no this one
            isNew = true;
            index = findEmptyPlace(scsi);
            scsi->dictionary_values[index] = strdup(&tmpName[0]);
        }
        fd = open(&tmpName[0], O_RDWR | O_NONBLOCK);
        if(fd == -1) {
            res = errno;
            DBUGDF(res);
            if(isNew) {
                free((void*)scsi->dictionary_values[index]);
                scsi->dictionary_values[index] = NULL;
            }
            continue;
        }
        scsi->dictionary_fd[index] = fd;
        res = sentINQUIRYByFd(scsi, fd);
        if(!res) {
            DBUGDF(res);
            if(isNew) {
                free((void*)scsi->dictionary_values[index]);
                scsi->dictionary_values[index] = NULL;
                scsi->dictionary_fd[index] = 0;
                close(fd);
            }
        }

        isNew = false;
    }

    return TRUE;
}

Boolean 
parseINQUIRY(SCSIPath* scsi, int fd) {
    Boolean res = TRUE;
    if(!scsi) {
        DBUGDF(EINVAL);
        return FALSE;
    }
    int alloc_len;
    unsigned char* buf = &scsi->dxferp[0];
    uint64_t wwn = 0;
    int ifidok = 0;

    alloc_len = (int)buf[4] + 4;
    if(alloc_len < 31) {
        DBUGDF(EINVAL);
        return FALSE;
    }
    //check inq id
    ifidok = memcmp(&buf[18], WWN_INQ_ID, 6);
    if(ifidok) {
        DBUGDF(EINVAL);
        return FALSE;
    }

    // wwn = strtoul((char*)&buf[WWN_BEGIN], &eptr, HEX);
    // if(wwn == ULONG_MAX || eptr == (char*)&buf[WWN_BEGIN]) {
    //     res = EINVAL;
    //     DDF(res);
    //     goto out;
    // }
    for(int n =0 ; n < 8; ++n) 
        wwn = (wwn << 8) |  buf[WWN_BEGIN + n];
   
    res = saveDictionary(scsi, wwn, NULL, fd, NULL);

    return res;
}

static
Boolean processInformation(SCSIPath* scsi, int fd) {
    Boolean res = TRUE;
    if(memcmp(&scsi->dxferp[18], WWN_INQ_ID, 6) == 0)
        parseINQUIRY(scsi, fd);

    return res;
}

Boolean readFromTarget(SCSIPath* scsi) {
    int i= 0;
    int poll = 0;
    int fd;
    for( ; i < DICTIONARY_LEN; ++i) {
        fd = scsi->dictionary_fd[i];
        if(fd == 0)
            continue;
        poll = checkPollSingle(fd, POLLIN);
        if(poll == FALSE) {
            continue;
        }
        if(readSCSI(scsi, fd, NULL) == TRUE)
            processInformation(scsi, fd);
    }

    return TRUE;
}

Boolean sentWRITE16ByFd(SCSIPath* scsi, int fd, const char* str, int len) {
    Boolean res = TRUE;
    if(!scsi || !str || len <= 0) {
        DBUGDF(EINVAL);
        return FALSE;
    }
    if(len > sizeof(scsi->dxferp)) {
        DBUGDF(E2BIG);
        return FALSE;
    }

    memset(&scsi->cmdp[0], 0, INQ_CMD_LEN);
    scsi->cmdp[0] = 0x8A;
    scsi->cmdp[13] = INQ_REPLY_LEN / 512;

    memset(&scsi->dxferp[0], 0, INQ_REPLY_LEN);
    memcpy(&scsi->dxferp[0], str, len); 

    res = sendSCSICommandByFd(scsi, fd, SG_DXFER_TO_DEV, 16);

    return res ;
}

static Boolean
process_cmd(struct vdisk_cmd *vcmd) {
    Boolean ret = TRUE;

    return ret;
}

void* main_loop(void* arg) {
    SCSIPath* scsi = (SCSIPath*)arg;
    struct pollfd pl;
    int res,i,j ;
    struct vdisk_cmd vcmd = {
        .scsi = scsi
    };
    Boolean ret = TRUE;

    memset(&pl, 0, sizeof(pl));
    pl.fd = scsi->scst_usr_fd;
    pl.events = POLLIN;
#define MULTI_CMDS_CNT 2
    struct 
    {
        struct scst_user_get_multi multi_cmd;
        struct scst_user_get_cmd cmds[MULTI_CMDS_CNT];
        struct scst_user_reply_cmd replies[MULTI_CMDS_CNT];
    } multi;
    memset(&multi, 0, sizeof(multi));
    multi.multi_cmd.preplies = (aligned_u64)&multi.replies[0];
    multi.multi_cmd.replies_cnt = 0;
    multi.multi_cmd.replies_done = 0;
    multi.multi_cmd.cmds_cnt = MULTI_CMDS_CNT;

    while(1) {
        res = ioctl(scsi->scst_usr_fd, SCST_USER_REPLY_AND_GET_MULTI, &multi.multi_cmd);
        if(res) {
            res = errno;
            switch(res) {
                case ESRCH:
			    case EBUSY: 
                    DBG("main_loop: ESRCH/EBUSY");
                    multi.multi_cmd.preplies = (uintptr_t)&multi.replies[0];
                    multi.multi_cmd.replies_cnt = 0;
                    multi.multi_cmd.cmds_cnt = MULTI_CMDS_CNT;
                case EINTR:
                    DBG("main_loop: EINTR");
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
            res = poll(&pl, 1, 0);
            if(res > 0)
                continue;
            else if(res == 0)
                goto again_poll;
            else {
                res = errno;
                DBUGDF(res);
                goto again_poll;
            }
        }
        if (multi.multi_cmd.replies_done < multi.multi_cmd.replies_cnt) {
			multi.multi_cmd.preplies = (uintptr_t)&multi.replies[multi.multi_cmd.replies_done];
			multi.multi_cmd.replies_cnt = multi.multi_cmd.replies_cnt - multi.multi_cmd.replies_done;
			multi.multi_cmd.cmds_cnt = MULTI_CMDS_CNT;
			continue;
		}        
        multi.multi_cmd.preplies = (uintptr_t)&multi.replies[0];
        for (i = 0, j = 0; i < multi.multi_cmd.cmds_cnt; i++, j++) {
            vcmd.cmd = &multi.cmds[i];
			vcmd.reply = &multi.replies[j];
            ret = process_cmd(&vcmd);
            if(ret == FALSE) {
                return (void*)ret;
            }
        }
        multi.multi_cmd.replies_cnt = j;
		multi.multi_cmd.cmds_cnt = MULTI_CMDS_CNT;
    }
}

Boolean 
SCSIInit(SCSIPath* scsi, RunTimeOpts * rtOpts, PtpClock * ptpClock) {
    int res = 0;

    if(!testSCSIInterface(rtOpts->ifaceName, rtOpts) || 
    !getSCSIInterfaceInfo(rtOpts->ifaceName, &scsi->info))
        return FALSE;
    
    if(!scanSCSIEquipmemt(scsi))
        return FALSE;
    
    usleep(1000 * 100);

    readFromTarget(scsi);

    memset(scsi->thread,0, sizeof(scsi->thread));
    scsi->scst_usr_fd = open("/dev/scst_user", O_RDWR | O_NONBLOCK);
    if(scsi->scst_usr_fd == -1) {
        DBUGDF(errno);
        return FALSE;
    }
    memset(&scsi->desc, 0, sizeof(scsi->desc));
    scsi->desc.version_str = (unsigned long)DEV_USER_VERSION;
    scsi->desc.license_str = (unsigned long)"GPL";
    strncpy(scsi->desc.name, "fc_ptp", sizeof(scsi->desc.name) - 1);
    scsi->desc.name[sizeof(scsi->desc.name) - 1] = '\0';
    scsi->desc.type = TYPE_DISK;
    scsi->desc.block_size = (1 << 9);
    scsi->desc.opt.parse_type = SCST_USER_PARSE_STANDARD;
    scsi->desc.opt.on_free_cmd_type = SCST_USER_ON_FREE_CMD_IGNORE;
    scsi->desc.opt.memory_reuse_type = SCST_USER_MEM_REUSE_ALL;
    scsi->desc.opt.tst = SCST_TST_1_SEP_TASK_SETS;
	scsi->desc.opt.tmf_only = 0;
	scsi->desc.opt.queue_alg = SCST_QUEUE_ALG_1_UNRESTRICTED_REORDER;
	scsi->desc.opt.qerr = SCST_QERR_0_ALL_RESUME;
	scsi->desc.opt.d_sense = SCST_D_SENSE_0_FIXED_SENSE;
    res = ioctl(scsi->scst_usr_fd, SCST_USER_REGISTER_DEVICE, &scsi->desc);
    if(res != 0) {
        DBUGDF(errno);
        return FALSE;
    }
    for(int i = 0;i < SCST_THREAD; ++i) {
        res = pthread_create(&scsi->thread[i], NULL, main_loop, scsi);
        if(res) {
            memset(&scsi->thread[i], 0, sizeof(pthread_t));
            DBUGDF(errno);
            return FALSE;
        }
    }

    return TRUE;   
}

Boolean
scsiRefresh(SCSIPath* scsi, const RunTimeOpts * rtOpts, PtpClock * ptpClock) {
    Boolean res = TRUE;

    return res;
}