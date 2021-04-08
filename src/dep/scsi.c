
#include "../ptpd.h"
#include <unistd.h>

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
    SCSIREC* recv = NULL, *recv1 = NULL;
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
    res = pthread_mutex_destroy(&scsi->mutex);
    if(res) {
        DBUGDF(errno);
        return FALSE;
    }
    recv = scsi->recv;
    while(recv != NULL) {
        recv1 = recv->next;
        free((void*)recv);
        recv = recv1;
    }

    memset(scsi->thread, 0, sizeof(scsi->thread));
    memset(scsi->tgt_devs, 0 , sizeof(scsi->tgt_devs));
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
again:
    n = poll(&plf, 1, 0);
    if(n == 0)
        return FALSE;
    if(n  == -1) {
        if(errno == EINTR)
            goto again;
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


//user initialize cmdp before call this function
static Boolean
sentWRITE16ByFd(SCSIPath* scsi, int fd, UInteger16 len) {
    int i = 0;
    // memset(scsi->cmdp, 0, INQ_CMD_LEN);
    scsi->cmdp[0] = 0x8A;
    // scsi->cmdp[13] = 1;
    for(; i < 2; ++i) {
        scsi->cmdp[13 - i] = (0xff & (len >> (i * 8)));
    }
    
    if(!sendSCSICommandByFd(scsi, fd, SG_DXFER_TO_DEV, 16))
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
Boolean sendWWNtoDev(SCSIPath* scsi, int fd) {
    Boolean res = TRUE;
    int len = 0;
    memset(&scsi->cmdp[0], 0, INQ_CMD_LEN);
    memset(&scsi->dxferp[0], 0, INQ_REPLY_LEN);
    scsi->cmdp[2] = 0xff;
    scsi->cmdp[9] = 0xff;
    len = snprintf(NULL,0,"%lu",scsi->info.wwn);
    if(len <= 0) {
        DBUGDF(errno);
        return FALSE;
    }
    len = snprintf((char*)&scsi->dxferp[0], len, "%lu",scsi->info.wwn);
    res = sentWRITE16ByFd(scsi, fd, len);
    return res;
}

static
Boolean processInformation(SCSIPath* scsi, int fd) {
    Boolean res = TRUE;
    if(memcmp(&scsi->dxferp[18], WWN_INQ_ID, 6) == 0) {
        parseINQUIRY(scsi, fd);
        // return sendWWNtoDev(scsi, fd);
    }

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
again:
        poll = checkPollSingle(fd, POLLIN);
        if(poll == FALSE) {
            continue;
        }
        if(readSCSI(scsi, fd, NULL) == TRUE)
            processInformation(scsi, fd);
        goto again;
    }

    return TRUE;
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

static 
struct vdisk_tgt_dev *find_tgt_dev(SCSIPath* scsi, uint64_t sess_h) {
    unsigned int i;
    struct vdisk_tgt_dev* res = NULL;
    for(i = 0; i < ARRAY_SIZE(scsi->tgt_devs); ++i) {
        if(scsi->tgt_devs[i].sess_h == sess_h) {
            res = &scsi->tgt_devs[i];
            break;
        }
    }
    return res;
}

static struct vdisk_tgt_dev *
find_empty_tgt_dev(SCSIPath* scsi)  {
    return find_tgt_dev(scsi, 0);
}

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

static 
Boolean do_sess(struct vdisk_cmd* vcmd) {
    Boolean res =  TRUE;
    struct scst_user_get_cmd *cmd = vcmd->cmd;
    struct scst_user_reply_cmd *reply = vcmd->reply;
    struct vdisk_tgt_dev *tgt_dev;
    
    tgt_dev = find_tgt_dev(vcmd->scsi, cmd->sess.sess_h);
    if (cmd->subcode == SCST_USER_ATTACH_SESS) {
        DBG("sess initiator: %s \n", cmd->sess.initiator_name);
        if (tgt_dev != NULL) {
            DBUGDF(EEXIST);
            res = FALSE;
            goto reply;
        }
        tgt_dev = find_empty_tgt_dev(vcmd->scsi);
        if(tgt_dev == NULL) {
            DBUGDF(ENOMEM);
            res = FALSE;
            goto reply;
        }
        tgt_dev->sess_h = cmd->sess.sess_h;
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
            tgt_dev->wwn = wwn;
        }
    } else {
        if(tgt_dev == NULL) {
            DBUGDF(ESRCH);
            res = FALSE;
            goto reply;
        }
        tgt_dev->sess_h = 0;
    }
reply:
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
        DBUGDF(res);
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
    }
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
/**
 *  obselete this : cdb[9] == 0xff && cdb[2] == 0xff  master -> slave wwn 
 *  cdb[9] == 0xfe && dfb[2] == 0xfe  ptpd   
 **/ 
static void exec_write(struct vdisk_cmd *vcmd) {
    struct scst_user_scsi_cmd_exec *cmd = &vcmd->cmd->exec_cmd;
    uint8_t *cdb = cmd->cdb;
    char* pbuf = (char*)cmd->pbuf;
    int res;
    SCSIPath* scsi = vcmd->scsi;

    if(cdb[2] == 0xfe && cdb[9] == 0xfe) {  //ptp
        SCSIREC* recv;
        struct timeval time;
        Boolean isEvent = (((pbuf[0] & 0x0f) < 4) && ((pbuf[0] & 0x0f) >= 0));
        uint16_t length = pbuf[13] + (pbuf[12] << 8); 

        if(isEvent) {
            res = gettimeofday(&time, NULL);
            if(res)  {
                res = errno;
                DBUGDF(res);
                return ;
            }
        }

        res = pthread_mutex_lock(&scsi->mutex);
        if(res) {
            res = errno;
            DBUGDF(res);
            return ;
        }
        recv = scsi->recv;
        while(recv != NULL) {
            if(recv->busy == FALSE || recv->next == NULL) {
                break;
            }
            recv = recv->next;
        }
        if(recv == NULL || (recv->next == NULL && recv->busy == TRUE)) {
            if(recv == NULL) {
                scsi->recv = (SCSIREC*)malloc(sizeof(SCSIREC));
                recv = scsi->recv;
            } else {
                recv->next = (SCSIREC*)malloc(sizeof(SCSIREC));
                recv = recv->next;
            }
        }
        memset(recv, 0, sizeof(SCSIREC) - sizeof(struct a *));
        recv->busy = TRUE;
        if(isEvent) {
            recv->time.tv_sec = time.tv_sec;
            recv->time.tv_usec = time.tv_usec;
            recv->isEvent = TRUE;
            scsi->recv_event++;
        } else {
            recv->isEvent = FALSE;
            scsi->recv_general++;
        }
        struct vdisk_tgt_dev* dev = find_tgt_dev(scsi, vcmd->cmd->exec_cmd.sess_h);
        recv->wwn = dev->wwn;
        recv->length = length;
        recv->next = NULL;
        memcpy(recv->buf, pbuf, length);

        
        res = pthread_mutex_unlock(&scsi->mutex);
        if(res) {
            res = errno;
            DBUGDF(res);
            return ;
        }
    } 
    // else if(cdb[2] == 0xff && cdb[9] == 0xff) { //ptpd
    //     uint64_t wwn;
    //     char* endptr;
    //     wwn = strtoul(&pbuf[0], &endptr, 16);
    //     if(endptr == &pbuf[0] || wwn == ULONG_MAX) {
    //         DBUGDF(errno);
    //         return ;
    //     }   
    //     struct vdisk_tgt_dev * tgt_dev = find_tgt_dev(vcmd->scsi, cmd->sess_h);
    //     if(!tgt_dev) {
    //         DBG("no tgt_dev");
    //         return ;
    //     }
    //     tgt_dev->wwn = wwn;
    // }
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
            buf[31 - i] = (wwn & (0xFF << (i * 8)));
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
    struct vdisk_tgt_dev *tgt_dev = NULL;

    memset(vcmd->reply,0 , sizeof(*vcmd->reply));
    vcmd->reply->cmd_h = vcmd->cmd->cmd_h;
    vcmd->reply->subcode = vcmd->cmd->subcode;
    reply_exec->reply_type = SCST_EXEC_REPLY_COMPLETED;

    vcmd->may_need_to_free_pbuf = 0;

    if((cmd->pbuf == 0) && (cmd->alloc_len != 0)) {
        cmd->pbuf =(unsigned long)align_alloc(cmd->alloc_len);
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
#ifdef SDEBUG
    //show opcode 
    unsigned int j = 0;
    
    flockfile(stdout);
    for(; j < ARRAY_SIZE(scsi_opcode);++j) {
        if(opcode == scsi_opcode[j])
            break;
    }
    if(j >= ARRAY_SIZE(scsi_opcode)) {
        printf("log: opcode out of range \n");
    } else 
        printf("log: opcode = %s\n", scsi_opcode_string[j]);
    funlockfile(stdout);
#endif    
    switch (opcode) {
        case INQUIRY:
            DBG("####################\n");
            DBG("        QUIRY       \n");
            DBG("####################\n");
            exec_inquiry(vcmd);
            break;
        case WRITE_6:
        case WRITE_10:
        case WRITE_12:
        case WRITE_16:
            tgt_dev = find_tgt_dev(vcmd->scsi, cmd->sess_h);
            if(tgt_dev == NULL) {
                set_cmd_error(vcmd,
				    SCST_LOAD_SENSE(scst_sense_hardw_error));
				return res;
            }
            exec_write(vcmd);
            break;
    }
    return res;
}

static Boolean
process_cmd(struct vdisk_cmd *vcmd) {
    Boolean ret = TRUE;
    struct scst_user_get_cmd *cmd = vcmd->cmd;
	struct scst_user_reply_cmd *reply = vcmd->reply;
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
    int res,i,j ;
    struct vdisk_cmd vcmd = {
        .scsi = scsi
    }; 
    Boolean ret = TRUE;
    
    res = sigemptyset(&sigset);
    if(res == -1) {
        res = errno;
        DBUGDF(res);
        return FALSE;
    }
    res = sigaddset(&sigset, SIGALRM);
    if(res == -1) {
        res = errno;
        DBUGDF(res);
        return FALSE;
    }
    res = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
    if(res == -1) {
        res = errno;
        DBUGDF(res);
        return FALSE;
    }

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
            res = poll(&pl, 1, -1);
            if(res > 0)
                continue;
            else if(res == 0)
                goto again_poll;
            else {
                res = errno;
                if(res != EINTR)
                    DBUGDF(res);
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
    DBG("####################\n");
    DBG("go out of main loop\n");
    DBG("####################\n");
    return (void*)(long)ret;
}

#define LOAD_ "- - -"
#define INDEXN (sizeof("/sys/class/scsi_host/hostn") - 2)
static 
void refresh(SCSIPath* scsi,const  RunTimeOpts * rtOpts) {
    static char fileName[64] = {};
    static Boolean Ini = TRUE;
    if(Ini == TRUE) {
        Ini = FALSE;
        memset(&fileName[0], '\0', sizeof(fileName));
        strcpy(&fileName[0], "/sys/class/scsi_host/hostn");
        strcat(&fileName[0],"/scan");
    }
    int fd, n;
    for(int i = 0; i < 6; ++i) {
        fileName[INDEXN] = 48 + i;
        fd = open(fileName, O_WRONLY);
        if(fd == -1) {
            DBUGDF(errno);
            goto out;
        }
        n = write(fd, LOAD_, sizeof(LOAD_));
        if(n == -1) {
            DBUGDF(errno);
            goto out;
        }
        fsync(fd);
    out:
        close(fd);
    }
    
    return ;
}

Boolean 
SCSIInit(SCSIPath* scsi, RunTimeOpts * rtOpts, PtpClock * ptpClock) {
    int res = 0;
    scsi->recv = NULL;
    if(!testSCSIInterface(rtOpts->ifaceName, rtOpts) || 
    !getSCSIInterfaceInfo(rtOpts->ifaceName, &scsi->info))
        return FALSE;

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
    res = ioctl(scsi->scst_usr_fd, SCST_USER_REGISTER_DEVICE, &scsi->desc);
    if(res != 0) {
        DBUGDF(errno);
        return FALSE;
    }
    res = pthread_mutex_init(&scsi->mutex, NULL);
    if(res) {
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
    system("scstadmin -config /etc/scst.conf");
    // system("/home/xgb/refresh.sh");
    refresh(scsi, rtOpts);
    if(!scanSCSIEquipmemt(scsi))
        return FALSE;
    
    usleep(1000 * 100);

    readFromTarget(scsi);

    return TRUE;   
}

Boolean
scsiRefresh(SCSIPath* scsi, const RunTimeOpts * rtOpts, PtpClock * ptpClock) {
     Boolean res = TRUE;
    // system("/home/xgb/refresh.sh");
    refresh(scsi, rtOpts);
    int i;
    for(i = 0; i < DICTIONARY_LEN; ++i) {
        if(scsi->dictionary_fd[i])
            sentINQUIRYByFd(scsi, scsi->dictionary_fd[i]);
    }
    
    usleep(1000 * 100);
    
    readFromTarget(scsi);
    return res;
}

ssize_t scsiRecvEvent(Octet * buf, TimeInternal * time, SCSIPath * scsi, int flags) {
    ssize_t ret = 0;
    scsi->lastDestAddr = 0;
    SCSIREC* recvptr = NULL;
    int res;

    if(scsi->recv_event <= 0)
        return 0; 
    res = pthread_mutex_lock(&scsi->mutex);
    if(res) {
        DBUGDF(errno);
        return -1;
    }
    recvptr = scsi->recv;
    while(recvptr != NULL && recvptr->isEvent != TRUE)
        recvptr = recvptr->next;
    if(!recvptr) {
        DBG("recvptr == NULL");
        pthread_mutex_unlock(&scsi->mutex);
        return 0;
    }
    scsi->recv_event--;
    memcpy(buf, recvptr->buf, recvptr->length);
    recvptr->busy = FALSE;
    time->seconds = recvptr->time.tv_sec;
    time->nanoseconds = recvptr->time.tv_usec * 1000;
    ret = recvptr->length;
    scsi->lastSourceAddr = recvptr->wwn;

    res = pthread_mutex_unlock(&scsi->mutex);
    if(res) {
        DBUGDF(errno);
        return -1;
    }
    scsi->receivedPacketsTotal++;
    scsi->receivedPackets++;
    
    return ret;
}

ssize_t scsiRecvGeneral(Octet * buf, SCSIPath* scsi) {
    ssize_t ret = 0;
    SCSIREC* recvptr = NULL;
    int res;
    scsi->lastSourceAddr = 0;

    if(scsi->recv_general <= 0)
        return 0; 
    res = pthread_mutex_lock(&scsi->mutex);
    if(res) {
        DBUGDF(errno);
        return -1;
    }
    recvptr = scsi->recv;
    while(recvptr != NULL && recvptr->isEvent != FALSE)
        recvptr = recvptr->next;
    if(!recvptr) {
        DBG("recvptr == NULL");
        pthread_mutex_unlock(&scsi->mutex);
        return 0;
    }
    scsi->recv_general--;
    memcpy(buf, recvptr->buf, recvptr->length);
    recvptr->busy = FALSE;
    ret = recvptr->length;
    scsi->lastSourceAddr = recvptr->wwn;

    res = pthread_mutex_unlock(&scsi->mutex);
    if(res) {
        DBUGDF(errno);
        return -1;
    }
    scsi->receivedPacketsTotal++;
    scsi->receivedPackets++;
    
    return ret;
}

Boolean 
scsiSendGeneral(Octet * buf, UInteger16 length, SCSIPath * scsi, 
const RunTimeOpts *rtOpts, uint64_t destinationAddress) {
    int i;
    Boolean res = TRUE, ret = TRUE;
    memset(&scsi->dxferp[0], 0, INQ_REPLY_LEN);
    memset(&scsi->cmdp[0], 0, INQ_CMD_LEN);
    scsi->cmdp[2] = 0xfe;
    scsi->cmdp[9] = 0xfe;
    if(destinationAddress) { //unicast to dst
        i = findIndexInDictionaryUsingWWN(scsi, destinationAddress);
        if(i == DICTIONARY_LEN) 
            return FALSE;
        *(char *)(buf + 6) |= PTP_UNICAST;
        memcpy(&scsi->dxferp[0], buf, (size_t)length);
        res = sentWRITE16ByFd(scsi, scsi->dictionary_fd[i],length);
        if(!res) 
            ret = FALSE;
    } else { //multicast
        memcpy(&scsi->dxferp[0], buf, (size_t)length);
        for(i = 0; i < DICTIONARY_LEN; ++i) {
            if(scsi->dictionary_keys[i] && scsi->dictionary_values[i]) {
                res = sentWRITE16ByFd(scsi, scsi->dictionary_fd[i], length) ;
                if(!res) 
                    ret = FALSE;
            }
        }
    }
    if(ret == TRUE) {
        scsi->sentPackets++;
	    scsi->sentPacketsTotal++;
    }
    return ret;
}

ssize_t 
scsiSendEvent(Octet * buf, UInteger16 length, SCSIPath * scsi, 
const RunTimeOpts *rtOpts, uint64_t destinationAddress, TimeInternal * tim)
{
    int i;
    Boolean res = TRUE, ret = TRUE;
    memset(&scsi->dxferp[0], 0, INQ_REPLY_LEN);
    memset(&scsi->cmdp[0], 0, INQ_CMD_LEN);
    scsi->cmdp[2] = 0xfe;
    scsi->cmdp[9] = 0xfe;
    struct timeval tv;
    if(destinationAddress) { //unicast to dst
        i = findIndexInDictionaryUsingWWN(scsi, destinationAddress);
        if(i == DICTIONARY_LEN) 
            return FALSE;
        *(char *)(buf + 6) |= PTP_UNICAST;
        memcpy(&scsi->dxferp[0], buf, (size_t)length);
        res = sentWRITE16ByFd(scsi, scsi->dictionary_fd[i],length);
        if(!res) 
            ret = FALSE;
    } else { //multicast
        memcpy(&scsi->dxferp[0], buf, (size_t)length);
        for(i = 0; i < DICTIONARY_LEN; ++i) {
            if(scsi->dictionary_keys[i] && scsi->dictionary_values[i]) {
                res = sentWRITE16ByFd(scsi, scsi->dictionary_fd[i], length) ;
                if(!res) 
                    ret = FALSE;
            }
        }
    }
    res = gettimeofday(&tv, NULL);
    if(res == -1) {
        DBUGDF(errno);
        return FALSE;
    }
    tim->seconds = tv.tv_sec;
    tim->nanoseconds = tv.tv_usec;
    if(ret == TRUE) {
        scsi->sentPackets++;
	    scsi->sentPacketsTotal++;
    }
    return ret;
}

ssize_t 
scsiSendPeerEvent(Octet * buf, UInteger16 length, SCSIPath * scsi, 
const RunTimeOpts *rtOpts, uint64_t destinationAddress, TimeInternal * tim)
{
    int i;
    Boolean res = TRUE, ret = TRUE;
    memset(&scsi->dxferp[0], 0, INQ_REPLY_LEN);
    memset(&scsi->cmdp[0], 0, INQ_CMD_LEN);
    scsi->cmdp[2] = 0xfe;
    scsi->cmdp[9] = 0xfe;
    struct timeval tv;
    if(destinationAddress) { //unicast to dst
        i = findIndexInDictionaryUsingWWN(scsi, destinationAddress);
        if(i == DICTIONARY_LEN) 
            return FALSE;
        *(char *)(buf + 6) |= PTP_UNICAST;
        memcpy(&scsi->dxferp[0], buf, (size_t)length);
        res = sentWRITE16ByFd(scsi, scsi->dictionary_fd[i],length);
        if(!res) 
            ret = FALSE;
    } else { //multicast
        memcpy(&scsi->dxferp[0], buf, (size_t)length);
        for(i = 0; i < DICTIONARY_LEN; ++i) {
            if(scsi->dictionary_keys[i] && scsi->dictionary_values[i]) {
                res = sentWRITE16ByFd(scsi, scsi->dictionary_fd[i], length) ;
                if(!res) 
                    ret = FALSE;
            }
        }
    }
    res = gettimeofday(&tv, NULL);
    if(res == -1) {
        DBUGDF(errno);
        return FALSE;
    }
    tim->seconds = tv.tv_sec;
    tim->nanoseconds = tv.tv_usec;
    if(ret == TRUE) {
        scsi->sentPackets++;
	    scsi->sentPacketsTotal++;
    }
    return ret;
}

ssize_t 
scsiSendPeerGeneral(Octet * buf, UInteger16 length, SCSIPath* scsi,
 const RunTimeOpts *rtOpts, uint64_t destinationAddress)
{
    int i;
    Boolean res = TRUE, ret = TRUE;
    memset(&scsi->dxferp[0], 0, INQ_REPLY_LEN);
    memset(&scsi->cmdp[0], 0, INQ_CMD_LEN);
    scsi->cmdp[2] = 0xfe;
    scsi->cmdp[9] = 0xfe;
    if(destinationAddress) { //unicast to dst
        i = findIndexInDictionaryUsingWWN(scsi, destinationAddress);
        if(i == DICTIONARY_LEN) 
            return FALSE;
        *(char *)(buf + 6) |= PTP_UNICAST;
        memcpy(&scsi->dxferp[0], buf, (size_t)length);
        res = sentWRITE16ByFd(scsi, scsi->dictionary_fd[i],length);
        if(!res) 
            ret = FALSE;
    } else { //multicast
        memcpy(&scsi->dxferp[0], buf, (size_t)length);
        for(i = 0; i < DICTIONARY_LEN; ++i) {
            if(scsi->dictionary_keys[i] && scsi->dictionary_values[i]) {
                res = sentWRITE16ByFd(scsi, scsi->dictionary_fd[i], length) ;
                if(!res) 
                    ret = FALSE;
            }
        }
    }
    if(ret == TRUE) {
        scsi->sentPackets++;
	    scsi->sentPacketsTotal++;
    }
    return ret;
}