
#include "../ptpd.h"
//find empty place in dictionary
 
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
// 0 true -1false
int checkPollSingle(int fd, short flags) {
    static struct pollfd plf;
    int n = 0;
    int res = 0;

    memset(&plf, 0, sizeof(struct pollfd));
    plf.fd = fd;
    plf.events = flags;
    n = poll(&plf, 1, 0);
    if(n == 0) {
        res = -1;
        goto out;
    }
    if(n == -1) {
        res = errno;
        PRINTLNDEBUG("poll %s", strerror(res));
        goto out;
    }

    if((plf.revents & flags) == 0)
        res = -1;
out:
    return res;
}

//设置wwns的数量
int getWWNsNumber(uint64_t * wwns, int size, int* wwns_number) {
    int res = 0, i = 0;
    *wwns_number = 0;
    if(size <= 0 || !wwns) {
        res = EINVAL;
        return res;   
    }
    for(; i < size; ++i) {
        if(wwns[i])
            ++(*wwns_number);
    }
    return res;
}

//查找是否存在该wwn
static
bool ifhaveThisWWN(uint64_t * wwns, int size, uint64_t wwn) {
    int i = 0;

    for( ; i < size; ++i) {
        if(wwns[i] == 0)
            continue;
        if(wwns[i] == wwn) 
            return true;
    }
    return false;
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
static 
int checkHBAPortState(const char* host_path, int* ifonline) {
    int res = 0;
    char fileName[MAX_FILENAME_LENGTH];
    char readBuf[PORT_STATE_LEN];
    int fd = 0;
    ssize_t rdnum = 0;
    *ifonline = 0;

    memset(&fileName[0], '\0', MAX_FILENAME_LENGTH);
    if(strlen(host_path) >= MAX_FILENAME_LENGTH) {
        res = EINVAL;
        PRINTLNDEBUG("strlen(host_path) = %ld", strlen(host_path));
        goto out1;
    }
    strcpy(&fileName[0], host_path);
    strcat(&fileName[0], FC_STATE_NAME);

    fd = open(&fileName[0], O_RDONLY);
    if(fd == -1) {
        res = errno;
        PRINTLNDEBUG("checkHBAPortState: open error: %s", strerror(res));
        goto out1;
    }

    memset(&readBuf[0], '\0', PORT_STATE_LEN);
    rdnum = read(fd, &readBuf[0], PORT_STATE_LEN);
    if(rdnum == -1) {
        res = errno;
        PRINTLNDEBUG("checkHBAPortState read error: %s", strerror(res));
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
out1:
    return res;
}

// 获取本机中的HBA的wwn
int getWWN(SCSIPath* scsi) {
    uint64_t* wwns = &scsi->wwns[0];
    int res = 0;
    struct dirent* direntp;
    DIR* dirp = opendir(FC_HOST_LOCATION);
    int host_num[HOST_MAX_NUM];
    int host_num_index = 0, i = 0;
    char file_name_buffer[MAX_FILENAME_LENGTH];
    int index = 0, fd;
    ssize_t rdnum = 0;
    char wwn_buffer[WWNS_LEN * 2 + 3]; // '\0' +1 '0x' +2 
    char* endptr;
    int ifonline = 0;
    int wwns_index = 0;
    uint64_t tmp_wwn = 0;
    
    if(!dirp) {
        res = errno;
        PRINTLNDEBUG("dir open error: %s", strerror(res));
        goto out1;
    }

    for(direntp = readdir(dirp) ; 
    direntp != NULL; 
    direntp = readdir(dirp)) {
        if(errno) {
            res = errno;
            PRINTLNDEBUG("readdir error: %s", strerror(res));
            goto out;
        }
        if(!strlen(direntp->d_name) || strcmp(direntp->d_name, ".") == 0 ||
        strcmp(direntp->d_name, "..") == 0 || strncmp(direntp->d_name, "host", 4) != 0) {
            continue;
        }
        host_num[host_num_index] = atoi(direntp->d_name + 4);
        ++host_num_index; 
        errno = 0;
    }

    if(!host_num_index) {
        res = ENOENT;
        PRINTLNDEBUG("no device in " FC_HOST_LOCATION);
        goto out;
    }

    memset(file_name_buffer, '\0', sizeof(file_name_buffer));
    memcpy(&file_name_buffer[0], FC_HOST_LOCATION, sizeof(FC_HOST_LOCATION));
    index = strlen(FC_HOST_LOCATION);
    for(i = 0; i < host_num_index; ++i) {
        memset(&file_name_buffer[0] + index, '\0', MAX_FILENAME_LENGTH - index);
        sprintf(&file_name_buffer[0] + index, "/host%d", host_num[i]);
        res = checkHBAPortState(&file_name_buffer[0], &ifonline);
        if((!res) && (!ifonline)) 
            continue;
        strcat(file_name_buffer, FC_NODE_NAME);

        fd = open(&file_name_buffer[0], O_RDONLY);
        if(fd == -1) {
            res = errno;
            PRINTLNDEBUG("open %s error: %s", &file_name_buffer[0], strerror(res));
            goto out;
        }
        // if(lseek(fd, 2, SEEK_SET) != 2) {
        //     res = errno;
        //     close(fd);
        //     PRINTLNDEBUG("lseek file : %s error : %s", &file_name_buffer[0], strerror(res));
        //     goto out;
        // }
        memset(wwn_buffer, '\0', WWNS_LEN * 2 + 3);
        rdnum = read(fd, &wwn_buffer[0], WWNS_LEN * 2 + 2);
        if(rdnum != WWNS_LEN * 2 + 2) {
            res = ERANGE;      
            PRINTLNDEBUG("read number error: %ld , %s", rdnum , strerror(res));
            goto out;
        }
        tmp_wwn = strtoul(&wwn_buffer[0], &endptr, 16);
        if(endptr == &wwn_buffer[0]) {
            res = -1;
            PRINTLNDEBUG("endptr == &wwn_buffer[0]");
            close(fd);
            goto out;
        }
        if(tmp_wwn == ULONG_MAX  && errno == ERANGE) {
            res = errno;
            PRINTLNDEBUG("strtoul : %s", strerror(res));
            close(fd);
            goto out;
        }
        if(ifhaveThisWWN(wwns, WWN_MAX_NUM, tmp_wwn) == true) {
            close(fd);
            continue;
        }
        wwns_index = findEmptyWWNPlace(wwns, WWN_MAX_NUM);
        if(wwns_index == WWN_MAX_NUM) {
            res = ERANGE;
            close(fd);
            PRINTLNDEBUG("full of wwns");
            goto out;
        }
        wwns[wwns_index] = tmp_wwn;

        if(close(fd) == -1) {
            res = errno;
            PRINTLNDEBUG("close %s error: %s", &file_name_buffer[0], strerror(res));
            goto out;
        }
        
    }
    
out:
    closedir(dirp);
out1:
    return res;
}

//释放字典所有资源
int freeAllDictionaryValues(char** dictionary_values, int size) {
    if(!dictionary_values || size <= 0) {
        return EINVAL;
    }
    for(int i = 0; i < size; ++i) {
        if(dictionary_values[i]) 
            free((void*)dictionary_values[i]);
    }
    return 0;
}

//初始化sg_io_hdr_t
static 
int initSgIoHdr(sg_io_hdr_t *io, int dxfer_direction, unsigned char cmd_len, unsigned char mx_sb_len, 
unsigned int dxfer_len, void * dxferp, unsigned char * cmdp, unsigned char * sbp,
unsigned int flags) {
    int res = 0;
    if(!io) {
        res = EINVAL;
        goto out;
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
out:
    return res;
}

//发送SCSI请求
static
int sendSCSI(sg_io_hdr_t *io, int fd) {
    int res = 0;
    if(!io || !io->dxfer_len || !io->dxferp || !io->sbp) {
        res = EINVAL;
        PRINTLNDEBUG("dxfer_len: dxfer_len == 0 or dxferp == NULL or sbp == NULL%s", strerror(res));
        goto out;
    }
    if(io->cmd_len > 16 || io->cmd_len < 6 || !io->cmdp) {
        res = EMSGSIZE;
        PRINTLN("cmd_len outofrang or cmdp == NULL : %s", strerror(res));
        goto out;
    }

    if(checkPollSingle(fd, POLLOUT) != 0) {
        //try again
        res = EAGAIN;
        goto out;
    }

    res = write(fd, (void*)io, sizeof(sg_io_hdr_t));
    if(res != sizeof(sg_io_hdr_t) && errno != EDOM) {
        res = EINVAL;
        PRINTLNDEBUG("write scsi not enough");
        goto out;
    }
    if(errno == EDOM) {
        res = errno;
        PRINTLNDEBUG("attemp reach SG_MAX_QUEUE");
        goto out;
    }
    res = 0;

out:
    return res;
}

//保存dictionary
static
int saveDictionary(SCSIPath* scsi, uint64_t wwn, const char* value, int fd, int* indexp) {
    int res = 0;
    int index = DICTIONARY_LEN;
    if(!scsi || (wwn == 0&& !value&& fd==0)) {
        res = EINVAL;
        PRINTLNDEBUG("value invalid");
        goto out;
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
            res = ERANGE;
            PRINTLNDEBUG("full of dictionary");
            goto out;
        }
    }
    if(indexp)
        *indexp = index;
    scsi->dictionary_fd[index] = fd != 0 ? fd : scsi->dictionary_fd[index];
    scsi->dictionary_keys[index] = wwn != 0 ? wwn : scsi->dictionary_keys[index];
    scsi->dictionary_values[index] = value != NULL ? strdup(value) : scsi->dictionary_values[index];


out :
    return res;
}
//get fd buy dev str
static 
int getFdByFileName(SCSIPath* scsi, const char* dev, int* fdp) {
    int res = 0;
    if(!scsi || !dev || !fdp) { 
        res = EINVAL;
        PRINTLNDEBUG("%s", strerror(res));
        goto out;
    }
    int index = findIndexInDictionaryUsingValue(scsi, dev);
    if(index == DICTIONARY_LEN || scsi->dictionary_fd[index] == 0) {
        //no this fd before
        int fd = open(dev, O_RDWR | O_NONBLOCK);
        if(fd == -1) {
            res = errno;
            PRINTLNDEBUG("open fd error %s", strerror(res));
            goto out;
        }
        res = saveDictionary(scsi, 0, dev, fd, &index);
        if(res) 
            goto out;
        *fdp = fd;
    } 
out:    
    return res;    
}

//发送SCSI请求
static
int sendSCSIByDevName(sg_io_hdr_t* io, const char* dev, SCSIPath* scsi) {
    int res = 0, index;
    if(!dev) {
        res = EINVAL;
        PRINTLNDEBUG("dev = null");
        goto out;
    }
    res = getFdByFileName(scsi, dev, &index);
    if(res) 
        goto out;
    res = sendSCSI(io, scsi->dictionary_fd[index]);
out:
    return res;
}

static 
int sendSCSICommandByFd(SCSIPath* scsi,  int fd,  int dxfer_direction, unsigned char cmd_len) {
    int res = 0;
    sg_io_hdr_t* iop = &scsi->io;
    if(!scsi) {
        res = EINVAL;
        PRINTLN("%s", strerror(res));
        goto out;
    }
    res = initSgIoHdr(iop, dxfer_direction, cmd_len, MX_SB_LEN, INQ_REPLY_LEN,
    (void*)&scsi->dxferp[0], &scsi->cmdp[0], &scsi->sbp[0], 0);
    if(res)
        goto out;
    res = sendSCSI(iop, fd);
out:
    return res;
}

static
int sendSCSICommand(SCSIPath* scsi, const char* dev) {
    int res = 0;
    int fd;
    sg_io_hdr_t* iop = &scsi->io;
    
    if(!scsi || !dev) {
        res = EINVAL;
        PRINTLN("%s", strerror(res));
        goto out;
    }
    res = getFdByFileName(scsi, dev, &fd);
    if(res) {
        goto out;
    }

    res = initSgIoHdr(iop, SG_DXFER_FROM_DEV, 6, MX_SB_LEN, INQ_REPLY_LEN,
    (void*)&scsi->dxferp[0], &scsi->cmdp[0], &scsi->sbp[0], 0);
    if(res)
        goto out;
    
    res = sendSCSI(iop, fd);
out:
    return res;
}

int sentINQUIRY(SCSIPath* scsi, const char* dev) {
    int res = 0;
    if(!scsi || !dev) {
        res = EINVAL;
        PRINTLN("%s", strerror(res));
        goto out;
    }
    //cdb
    memset(scsi->cmdp, 0, INQ_CMD_LEN);
    scsi->cmdp[0] = 0x12;
    scsi->cmdp[3] = INQ_REPLY_LEN >> 8; //ALLOCATION LENGTH
    scsi->cmdp[4] = INQ_REPLY_LEN & 0xff;

    res = sendSCSICommand(scsi, dev);
out:
    return res;
}

int sentINQUIRYByFd(SCSIPath* scsi, int fd) {
    int res = 0;
    if(!scsi ) {
        res = EINVAL;
        DDF(res);
        goto out;
    }
    //cdb
    memset(scsi->cmdp, 0, INQ_CMD_LEN);
    scsi->cmdp[0] = 0x12;
    scsi->cmdp[3] = INQ_REPLY_LEN >> 8; //ALLOCATION LENGTH
    scsi->cmdp[4] = INQ_REPLY_LEN & 0xff;

    res = sendSCSICommandByFd(scsi, fd, SG_DXFER_FROM_DEV, 6);
out:
    return res;
}

//初始化sg_io
int initAllAboutSg(SCSIPath* scsi) {
    int res = 0;
    if(!scsi) {
        res = EINVAL;
        DDF(res);
        goto out;
    }
    memset(&scsi->cmdp[0], 0, INQ_CMD_LEN);
    memset(&scsi->sbp[0], 0, MX_SB_LEN);
    memset(&scsi->dxferp[0], 0, INQ_REPLY_LEN);
    memset(&scsi->io, 0, sizeof(sg_io_hdr_t));

    sg_io_hdr_t* io = &scsi->io;
    io->cmdp = &scsi->cmdp[0];
    io->sbp = &scsi->sbp[0];
    io->dxferp = (void*)&scsi->dxferp[0];
out:
    return res;
}

int readSCSI(SCSIPath* scsi, int fd, int * readnum) {
    int res = 0;
    
    if(!scsi) {
        res = EINVAL;
        DDF(res);
        goto out;
    }
    initAllAboutSg(scsi);
    int nread = read(fd, &scsi->io, sizeof(sg_io_hdr_t));
    if(nread == -1) {
        res = errno;
        DDF(res);
        goto out;
    }
    if(readnum) 
        *readnum = nread;
    if(nread != sizeof(sg_io_hdr_t)) {
        res = EIO;
        PRINTLNDEBUG("nread != sizeof(sg_io_hdr_t)");
        goto out;
    }
    
out:
    return res;
}

//扫描本地scsi设备,发送请求
int scanSCSIEquipmemt(SCSIPath* scsi) {
    DIR* dirp;
    struct dirent* direntp;
    int res = 0;
    char tmpName[5 * strlen(DEV_PREFIX)];
    int index = DICTIONARY_LEN;
    bool isNew = false;
    int fd = 0;

    if(!scsi) {
        res = EINVAL;
        DDF(res);
        goto out;
    }
    dirp = opendir(DEV_PREFIX);
    if(dirp == NULL) {
        res = errno;
        DDF(res);
        goto out;
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
            DDF(res);
            if(isNew) {
                free((void*)scsi->dictionary_values[index]);
                scsi->dictionary_values[index] = NULL;
            }
            continue;
        }
        scsi->dictionary_fd[index] = fd;
        res = sentINQUIRYByFd(scsi, fd);
        if(res) {
            DDF(res);
            if(isNew) {
                free((void*)scsi->dictionary_values[index]);
                scsi->dictionary_values[index] = NULL;
                scsi->dictionary_fd[index] = 0;
                close(fd);
            }
        }

        isNew = false;
    }

out:
    return res;
}

int parseINQUIRY(SCSIPath* scsi, int fd) {
    int res = 0;
    if(!scsi) {
        res = EINVAL;
        DDF(res);
        goto out;
    }
    int alloc_len;
    unsigned char* buf = &scsi->dxferp[0];
    uint64_t wwn = 0;
    int ifidok = 0;

    alloc_len = (int)buf[4] + 4;
    if(alloc_len < 31) {
        res = EINVAL;
        DDF(res);
        goto out;
    }
    //check inq id
    ifidok = memcmp(&buf[18], WWN_INQ_ID, 6);
    if(ifidok) {
        res = EINVAL;
        DDF(res);
        goto out;
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

out:
    return res;
}

static
int processInformation(SCSIPath* scsi, int fd) {
    int res = 0;
    if(memcmp(&scsi->dxferp[18], WWN_INQ_ID, 6) == 0)
        parseINQUIRY(scsi, fd);

    return res;
}

int readFromTarget(SCSIPath* scsi) {
    int res = 0;
    int i= 0;
    int poll = 0;
    int fd;
    for( ; i < DICTIONARY_LEN; ++i) {
        fd = scsi->dictionary_fd[i];
        if(fd == 0)
            continue;
        poll = checkPollSingle(fd, POLLIN);
        if(poll == -1) {
            continue;
        }
        if(readSCSI(scsi, fd, NULL) == 0)
            processInformation(scsi, fd);
    }

    return res;
}

int sentWRITE16ByFd(SCSIPath* scsi, int fd, const char* str, int len) {
    int res = 0;
    if(!scsi || !str || len <= 0) {
        res = EINVAL;
        DDF(res);
        goto out;
    }
    if(len > sizeof(scsi->dxferp)) {
        res = E2BIG;
        DDF(res);
        goto out;
    }

    memset(&scsi->cmdp[0], 0, INQ_CMD_LEN);
    scsi->cmdp[0] = 0x8A;
    scsi->cmdp[13] = INQ_REPLY_LEN / 512;

    memset(&scsi->dxferp[0], 0, INQ_REPLY_LEN);
    memcpy(&scsi->dxferp[0], str, len); 

    res = sendSCSICommandByFd(scsi, fd, SG_DXFER_TO_DEV, 16);
out :
    return res ;
}