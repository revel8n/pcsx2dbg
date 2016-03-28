// Copyright (C) 2014 oct0xor
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 2.0.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License 2.0 for more details.
// 
// A copy of the GPL 2.0 should have been included with the program.
// If not, see http ://www.gnu.org/licenses/

#define _WINSOCKAPI_

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include <algorithm>
#include <vector>
#include <string>
#include <unordered_map>
#include <set>

#include <ida.hpp>
#include <area.hpp>
#include <ua.hpp>
#include <nalt.hpp>
#include <idd.hpp>
#include <segment.hpp>
#include <dbg.hpp>
#include <allins.hpp>

#include "debmod.h"

#include "gdb.h"

#ifdef _DEBUG
#define debug_printf ::msg
#else
#define debug_printf(...)
#endif

#define DEBUGGER_NAME "pcsx2"
#define DEBUGGER_ID (0x8001)
#define PROCESSOR_NAME "r5900l"

static error_t idaapi idc_threadlst(idc_value_t *argv, idc_value_t *res);
void get_threads_info(void);
void clear_all_bp(uint32 tid);
uint32 read_pc_register(uint32 tid);
uint32 read_lr_register(uint32 tid);
uint32 read_ctr_register(uint32 tid);
int do_step(uint32 tid, uint32 dbg_notification);
bool addr_has_bp(uint32 ea);

static const char idc_threadlst_args[] = {0};

uint32 ProcessID;
uint32 ThreadID;

bool LaunchTargetPicker = true;
bool AlwaysDC = false;
bool ForceDC = true;
bool WasOriginallyConnected = false;

static bool attaching = false; 
static bool singlestep = false;
static bool continue_from_bp = false;
static bool dabr_is_set = false;
uint32 dabr_addr;
uint8 dabr_type;

eventlist_t events;

std::unordered_map<int, std::string> process_names;
std::unordered_map<int, std::string> modules;
std::unordered_map<int, int> main_bpts_map;

std::set<uint32> step_bpts;
std::set<uint32> main_bpts;

static const unsigned char bpt_code[] = {0x7f, 0xe0, 0x00, 0x08};

#define STEP_INTO 15
#define STEP_OVER 16

#define RC_GPR 1
#define RC_GPR_EXTENDED 2
#define RC_CP0 4
#define RC_FPR 8
#define RC_FCR 16
#define RC_VU0F 32
#define RC_VU0I 64

struct regval
{
    uint64 lval;
    uint64 rval;
};
typedef struct regval regval;

//--------------------------------------------------------------------------
const char* register_classes[] =
{
    "GPR",
    "GPR (128-bit)",
    "CP0",
    "FPR",
    "FCR",
    "VU0F",
    "VU0I",
    NULL
};

//--------------------------------------------------------------------------
const char* register_formats[] =
{
    "ps2_4_words",
    NULL
};

const char * const GPR_REG[35] =
{
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
    "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
    "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",
    "pc", "hi", "lo"
};

const char * const COP0_REG[32] =
{
    "Index", "Random", "EntryLo0", "EntryLo1", "Context", "PageMask",
    "Wired", "C0r7", "BadVaddr", "Count", "EntryHi", "Compare", "Status",
    "Cause", "EPC", "PRId", "Config", "C0r17", "C0r18", "C0r19", "C0r20",
    "C0r21", "C0r22", "C0r23", "Debug", "Perf", "C0r26", "C0r27", "TagLo",
    "TagHi", "ErrorPC", "C0r31"
};

//floating point cop1 Floating point reg
const char * const COP1_REG_FP[32] = 
{
    "f00", "f01", "f02", "f03", "f04", "f05", "f06", "f07",
    "f08", "f09", "f10", "f11", "f12", "f13", "f14", "f15",
    "f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23",
    "f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31"
};

//floating point cop1 control registers
const char * const COP1_REG_FCR[32] =
{
    "fcr00", "fcr01", "fcr02", "fcr03", "fcr04", "fcr05", "fcr06", "fcr07",
    "fcr08", "fcr09", "fcr10", "fcr11", "fcr12", "fcr13", "fcr14", "fcr15",
    "fcr16", "fcr17", "fcr18", "fcr19", "fcr20", "fcr21", "fcr22", "fcr23",
    "fcr24", "fcr25", "fcr26", "fcr27", "fcr28", "fcr29", "fcr30", "fcr31"
};

//floating point cop2 reg
const char * const COP2_REG_FP[32] =
{
    "vf00", "vf01", "vf02", "vf03", "vf04", "vf05", "vf06", "vf07",
    "vf08", "vf09", "vf10", "vf11", "vf12", "vf13", "vf14", "vf15",
    "vf16", "vf17", "vf18", "vf19", "vf20", "vf21", "vf22", "vf23",
    "vf24", "vf25", "vf26", "vf27", "vf28", "vf29", "vf30", "vf31"
};

//cop2 control registers
const char * const COP2_REG_CTL[32] =
{
    "vi00", "vi01", "vi02", "vi03", "vi04", "vi05", "vi06", "vi07",
    "vi08", "vi09", "vi10", "vi11", "vi12", "vi13", "vi14", "vi15",
    "Status", "MACflag", "ClipFlag", "c2c19", "R", "I", "Q", "c2c23",
    "c2c24", "c2c25", "TPC", "CMSAR0", "FBRST", "VPU-STAT", "c2c30", "CMSAR1"
};

const char * const COP2_VFnames[4] = { "x", "y", "z", "w" };

enum RegisterIndexType
{
    REF_INDEX_ZERO = 0,

    REF_INDEX_SP = 29,
    REF_INDEX_FP = 30,

    REF_INDEX_PC = 32,
    REF_INDEX_HI = 33,
    REF_INDEX_LO = 34,
};

const char * const * register_names[EECAT_COUNT] =
{
    GPR_REG,
    COP0_REG,
    COP1_REG_FP,
    COP1_REG_FCR,
    COP2_REG_FP,
    COP2_REG_CTL,
};

// NOTE: REGISTER_CUSTFMT flagged registers do not appear to be able to support REGISTER_ADDRESS,
//    so EECAT_GPR registers are duplicated as both 32-bit (RC_GPR) and 128-bit (RC_GPR_EXTENDED) registers
struct register_group 
{
    int register_category;
    int register_count;
    register_class_t register_class;
    int register_type;
    int register_flags;
    const char *const *register_format;
} register_groups[] =
{
    { EECAT_GPR, GPR_COUNT, RC_GPR, dt_dword, REGISTER_ADDRESS, nullptr },
    { EECAT_GPR, 32, RC_GPR_EXTENDED, dt_byte16, REGISTER_CUSTFMT | REGISTER_ADDRESS, register_formats },
    { EECAT_CP0, 32, RC_CP0, dt_dword, 0, nullptr },
    { EECAT_FPR, 32, RC_FPR, dt_float, 0, nullptr },
    { EECAT_FCR, 32, RC_FCR, dt_dword, 0, nullptr },
    { EECAT_VU0F, 32, RC_VU0F, dt_byte16, REGISTER_CUSTFMT, register_formats },
    { EECAT_VU0I, 32, RC_VU0I, dt_dword, 0, nullptr },
};

//--------------------------------------------------------------------------
register_info_t registers[REGISTER_EXTENDED_COUNT] =
{
    { 0 },
};

int register_ids[REGISTER_EXTENDED_COUNT] =
{
    { 0 },
};

void setup_registers()
{
    for (int i = 0, reg = 0; i < qnumber(register_groups); ++i)
    {
        for (int j = 0; j < register_groups[i].register_count; ++j, ++reg)
        {
            // setup register id
            register_ids[reg] = REGISTER_ID(register_groups[i].register_category, j);

            // setup register info
            registers[reg].name = register_names[register_groups[i].register_category][j];
            registers[reg].flags = register_groups[i].register_flags;
            registers[reg].register_class = register_groups[i].register_class;
            registers[reg].dtyp = register_groups[i].register_type;
            registers[reg].bit_strings = register_groups[i].register_format;
            registers[reg].bit_strings_default = 0;
        }
    }

    registers[REF_INDEX_ZERO].flags = REGISTER_READONLY;
    registers[REF_INDEX_SP].flags |= REGISTER_SP;
    registers[REF_INDEX_FP].flags |= REGISTER_FP;
    registers[REF_INDEX_PC].flags |= REGISTER_IP;
}

//-------------------------------------------------------------------------
static inline uint32 bswap32(uint32 x)
{
    return ( (x << 24) & 0xff000000 ) |
           ( (x <<  8) & 0x00ff0000 ) |
           ( (x >>  8) & 0x0000ff00 ) |
           ( (x >> 24) & 0x000000ff );
}

static inline uint64 bswap64(uint64 x)
{
    return ( (x << 56) & 0xff00000000000000ULL ) |
           ( (x << 40) & 0x00ff000000000000ULL ) |
           ( (x << 24) & 0x0000ff0000000000ULL ) |
           ( (x <<  8) & 0x000000ff00000000ULL ) |
           ( (x >>  8) & 0x00000000ff000000ULL ) |
           ( (x >> 24) & 0x0000000000ff0000ULL ) |
           ( (x >> 40) & 0x000000000000ff00ULL ) |
           ( (x >> 56) & 0x00000000000000ffULL );
}

bool GetHostnames(const char* input, std::string& ipOut, std::string& dnsNameOut)
{
    WSADATA wsaData;
    int iResult;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        return false;
    }

    sockaddr_in remotemachine;
    char hostname[NI_MAXHOST];

    remotemachine.sin_family = AF_INET;
    remotemachine.sin_addr.s_addr = inet_addr(input);

    // IP->Hostname
    DWORD dwRetVal = getnameinfo((SOCKADDR *)&remotemachine, 
        sizeof(sockaddr), 
        hostname, 
        NI_MAXHOST, 
        NULL, 
        0, 
        NI_NAMEREQD);

    if (dwRetVal == 0)
    {
        dnsNameOut = hostname;
        return true;
    }

    // Hostname -> IP
    struct hostent *remoteHost;
    remoteHost = gethostbyname(input);

    int i = 0;
    struct in_addr addr = { 0 };
    if (remoteHost && remoteHost->h_addrtype == AF_INET)
    {
        if (remoteHost->h_addr_list[0] != 0)
        {
            addr.s_addr = *(u_long *) remoteHost->h_addr_list[0];
            ipOut = inet_ntoa(addr);
            return true;
        }
    }

    WSACleanup();
    return false;
}

static void handle_events(u32 signal, u32 pc, u32 address)
{
    debug_printf("handle_events\n");

    debug_event_t ev;

    switch (signal)
    {
    case SIGABRT:
        {
            if (attaching)
            {
                debug_printf("PCSX2_DBG_EVENT_PROCESS_START\n");

                attaching = false;

                ev.eid     = PROCESS_START;
                ev.pid     = ProcessID;
                ev.tid     = NO_THREAD;
                ev.ea      = BADADDR;
                ev.handled = true;

                qstrncpy(ev.modinfo.name, "pcsx2", sizeof(ev.modinfo.name));
                ev.modinfo.base = 0x100000;
                ev.modinfo.size = 0;
                ev.modinfo.rebase_to = BADADDR;

                events.enqueue(ev, IN_BACK);

                ev.eid     = PROCESS_SUSPEND;
                ev.pid     = ProcessID;

                events.enqueue(ev, IN_BACK);

                break;
            }
        }
        break;
    case SIGSEGV:
    case SIGTERM:
        {
            debug_printf("PCSX2_DBG_EVENT_PROCESS_EXIT\n");

            ev.eid     = PROCESS_EXIT;
            ev.pid     = ProcessID;
            ev.tid     = NO_THREAD;
            ev.ea      = BADADDR;
            ev.handled = true;
            ev.exit_code = 0;

            events.enqueue(ev, IN_BACK);
        }
        break;
    case SIGSTOP:
        {
            debug_printf("PCSX2_DBG_EVENT_PROCESS_SUSPEND\n");

            ev.eid = PROCESS_SUSPEND;
            ev.pid = ProcessID;
            ev.tid = ThreadID;
            ev.ea = pc;
            ev.handled = true;
            ev.exit_code = 0;

            events.enqueue(ev, IN_BACK);
        }
        break;
    case SIGCONT:
        {
            debug_printf("PCSX2_DBG_EVENT_PROCESS_CONTINUE\n");

            ev.eid = NO_EVENT;
            ev.pid = ProcessID;
            ev.tid = ThreadID;
            ev.ea = pc;
            ev.handled = true;
            ev.exit_code = 0;

            events.enqueue(ev, IN_BACK);
        }
        break;
    case SIGTRAP:
        {
            debug_printf("PCSX2_DBG_EVENT_TRAP\n");

            if (continue_from_bp == true)
            {
                debug_printf("\tContinuing from breakpoint...\n");
                continue_from_bp = false;
            }
            else if (BADADDR != address)
            {
                debug_printf("\tData breakpoint...\n");

                ev.eid = BREAKPOINT;
                ev.pid = ProcessID;
                ev.tid = ThreadID;
                ev.ea = pc;
                ev.handled = true;
                ev.bpt.hea = address;
                ev.bpt.kea = BADADDR;
                ev.exc.ea = BADADDR;

                events.enqueue(ev, IN_BACK);
            }
            else if (singlestep == true)
            {
                debug_printf("\tSingle step...\n");

                ev.eid     = STEP;
                ev.pid     = ProcessID;
                ev.tid     = ThreadID;
                ev.ea      = pc;
                ev.handled = true;
                ev.exc.code = 0;
                ev.exc.can_cont = true;
                ev.exc.ea = BADADDR;

                events.enqueue(ev, IN_BACK);

                continue_from_bp = false;
                singlestep = false;
            }
            else if (!addr_has_bp(pc))
            {
                ev.eid     = PROCESS_SUSPEND;
                ev.pid     = ProcessID;
                ev.tid     = ThreadID;
                ev.ea      = pc;
                ev.handled = true;

                events.enqueue(ev, IN_BACK);
            }
            else
            {
                debug_printf("\tBreakpoint...\n");

                ev.eid     = BREAKPOINT;
                ev.pid     = ProcessID;
                ev.tid     = ThreadID;
                ev.ea      = pc;
                ev.handled = true;
                ev.bpt.hea = BADADDR;
                ev.bpt.kea = BADADDR;
                ev.exc.ea  = BADADDR;

                events.enqueue(ev, IN_BACK);
            }

            for (std::set<uint32>::const_iterator step_it = step_bpts.begin(); step_it != step_bpts.end(); ++step_it)
            {
                uint32 addr = *step_it;

                if (!addr_has_bp(addr))
                {
                    main_bpts_map.erase(addr);

                    gdb_remove_bp(addr, GDB_BP_TYPE_X, 4);
                    debug_printf("step bpt cleared: 0x%08X\n", (uint32)addr);
                }
            }
            step_bpts.clear();
        }
        break;
    default:
        debug_printf("Unknown event signal: 0x%08X\n");
        break;
    }
}

//--------------------------------------------------------------------------
// Initialize debugger
static bool idaapi init_debugger(const char *hostname, int port_num, const char *password)
{
    debug_printf("init_debugger\n");

    if (!gdb_init(port_num))
        return false;

    set_idc_func_ex("threadlst", idc_threadlst, idc_threadlst_args, 0);

    return true;
}

//--------------------------------------------------------------------------
// Terminate debugger
static bool idaapi term_debugger(void)
{
    debug_printf("term_debugger\n");

    gdb_deinit();

    set_idc_func_ex("threadlst", NULL, idc_threadlst_args, 0);

    return true;
}

//--------------------------------------------------------------------------
int idaapi process_get_info(int n, process_info_t *info)
{
    if (n > 0)
        return 0;

    info->pid = 0;
    qstrncpy(info->name, "pcsx2", sizeof(info->name));

    return 1;
}

static error_t idaapi idc_threadlst(idc_value_t *argv, idc_value_t *res)
{
    get_threads_info();
    return eOk;
}

void get_threads_info(void)
{
    debug_printf("get_threads_info\n");

    if (attaching == true) 
    {
        debug_event_t ev;

        attaching = false;

        ThreadID = 1;

        ev.eid     = THREAD_START;
        ev.pid     = ProcessID;
        ev.tid     = ThreadID;
        ev.ea      = read_pc_register(ThreadID);
        ev.handled = true;

        events.enqueue(ev, IN_BACK);

        clear_all_bp(0);

        // set break point on current instruction
        gdb_add_bp(ev.ea, GDB_BP_TYPE_X, 4);
        step_bpts.insert(ev.ea);
    }
}

void get_modules_info(void)
{
}

void clear_all_bp(uint32 tid)
{
}

void bp_list(void)
{
}

bool addr_has_bp(uint32 ea)
{
    return (main_bpts.end() != main_bpts.find(ea));
}

//--------------------------------------------------------------------------
// Start an executable to debug
static int idaapi deci3_start_process(const char *path,
                              const char *args,
                              const char *startdir,
                              int dbg_proc_flags,
                              const char *input_path,
                              uint32 input_file_crc32)
{
    //uint64 tid;

    debug_printf("start_process\n");
    debug_printf("path: %s\n", path);

    ProcessID = 0;

    attaching = true;

    debug_event_t ev;

    ev.eid     = PROCESS_START;
    ev.pid     = ProcessID;
    ev.tid     = NO_THREAD;
    ev.ea      = BADADDR;
    ev.handled = true;

    qstrncpy(ev.modinfo.name, "pcsx2", sizeof(ev.modinfo.name));
    ev.modinfo.base = 0x100000;
    ev.modinfo.size = 0;
    ev.modinfo.rebase_to = BADADDR;

    events.enqueue(ev, IN_BACK);

    get_threads_info();
    get_modules_info();
    clear_all_bp(-1);

    gdb_continue();

/*
    ev.eid     = PROCESS_SUSPEND;
    ev.pid     = ProcessID;

    events.enqueue(ev, IN_BACK);

    gdb_handle_events(handle_events);
*/

    debug_printf("ProcessID: 0x%X\n", ProcessID);

    /*debug_event_t ev;
    ev.eid     = PROCESS_START;
    ev.pid     = ProcessID;
    ev.tid     = NO_THREAD;
    ev.ea      = BADADDR;
    ev.handled = true;

    qstrncpy(ev.modinfo.name, path, sizeof(ev.modinfo.name));
    ev.modinfo.base = 0x10200;
    ev.modinfo.size = 0;
    ev.modinfo.rebase_to = BADADDR;

    events.enqueue(ev, IN_BACK);*/

    return 1;
}

//--------------------------------------------------------------------------
// Attach to an existing running process
int idaapi deci3_attach_process(pid_t pid, int event_id)
{
    debug_printf("deci3_attach_process\n");

    // block the process until all generated events are processed
    attaching = true;

    ProcessID = pid;

    process_names[ProcessID] = "pcsx2";

    debug_event_t ev;
    ev.eid     = PROCESS_START;
    ev.pid     = ProcessID;
    ev.tid     = NO_THREAD;
    ev.ea      = BADADDR;
    ev.handled = true;

    qstrncpy(ev.modinfo.name, process_names[ProcessID].c_str(), sizeof(ev.modinfo.name));
    ev.modinfo.base = 0x100000;
    ev.modinfo.size = 0;
    ev.modinfo.rebase_to = BADADDR;

    events.enqueue(ev, IN_BACK);

    get_threads_info();
    get_modules_info();
    clear_all_bp(-1);

    ev.eid     = PROCESS_ATTACH;
    ev.pid     = ProcessID;
    ev.tid     = NO_THREAD;
    ev.ea      = BADADDR;
    ev.handled = true;

    qstrncpy(ev.modinfo.name, process_names[ProcessID].c_str(), sizeof(ev.modinfo.name));
    ev.modinfo.base = 0x100000;
    ev.modinfo.size = 0;
    ev.modinfo.rebase_to = BADADDR;

    events.enqueue(ev, IN_BACK);

    process_names.clear();

    return 1;
}

//--------------------------------------------------------------------------
int idaapi deci3_detach_process(void)
{
    debug_printf("deci3_detach_process\n");

    gdb_continue();

    gdb_deinit();

    debug_event_t ev;
    ev.eid     = PROCESS_DETACH;
    ev.pid     = ProcessID;

    events.enqueue(ev, IN_BACK);

    return 1;
}

//-------------------------------------------------------------------------
void idaapi rebase_if_required_to(ea_t new_base)
{
    debug_printf("rebase_if_required_to: 0x%llX\n", (uint64)new_base);
}

//--------------------------------------------------------------------------
int idaapi prepare_to_pause_process(void)
{
    debug_printf("prepare_to_pause_process\n");

    //gdb_pause();

    debug_event_t ev;
    ev.eid     = PROCESS_SUSPEND;
    ev.pid     = ProcessID;

    events.enqueue(ev, IN_BACK);

    return 1;
}

//--------------------------------------------------------------------------
int idaapi deci3_exit_process(void)
{
    debug_printf("deci3_exit_process\n");

    gdb_kill();

    debug_event_t ev;
    ev.eid     = PROCESS_EXIT;
    ev.pid     = ProcessID;
    ev.tid     = NO_THREAD;
    ev.ea      = BADADDR;
    ev.exit_code = 0;
    ev.handled = true;

    events.enqueue(ev, IN_BACK);

    return 1;
}

#ifdef _DEBUG

static const char *get_event_name(event_id_t id)
{
    switch ( id )
    {
        case NO_EVENT:        return "NO_EVENT";
        case THREAD_START:    return "THREAD_START";
        case THREAD_EXIT:     return "THREAD_EXIT";
        case PROCESS_ATTACH:  return "PROCESS_ATTACH";
        case PROCESS_DETACH:  return "PROCESS_DETACH";
        case PROCESS_START:   return "PROCESS_START";
        case PROCESS_SUSPEND: return "PROCESS_SUSPEND";
        case PROCESS_EXIT:    return "PROCESS_EXIT";
        case LIBRARY_LOAD:    return "LIBRARY_LOAD";
        case LIBRARY_UNLOAD:  return "LIBRARY_UNLOAD";
        case BREAKPOINT:      return "BREAKPOINT";
        case STEP:            return "STEP";
        case EXCEPTION:       return "EXCEPTION";
        case INFORMATION:     return "INFORMATION";
        case SYSCALL:         return "SYSCALL";
        case WINMESSAGE:      return "WINMESSAGE";
        default:              return "???";
    }
}

#endif

//--------------------------------------------------------------------------
// Get a pending debug event and suspend the process
gdecode_t idaapi get_debug_event(debug_event_t *event, int ida_is_idle)
{
    if ( event == NULL )
        return GDE_NO_EVENT;

    while ( true )
    {
        gdb_handle_events(handle_events);

        if ( events.retrieve(event) )
        {
#ifdef _DEBUG

            if (event->eid == BREAKPOINT && event->bpt.hea != BADADDR)
            {
                debug_printf("get_debug_event: BREAKPOINT (HW)\n");
            }
            else
            {
                debug_printf("get_debug_event: %s\n", get_event_name(event->eid));
            }

#endif

            if (event->eid == PROCESS_ATTACH)
            {
                attaching = false;
            }

            if (attaching == false) 
            {
            }

            return (events.empty()) ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
        }

        if (events.empty())
            break;
    }

    if (attaching == false)
    {
    }

    return GDE_NO_EVENT;
}

//--------------------------------------------------------------------------
// Continue after handling the event
int idaapi continue_after_event(const debug_event_t *event)
{
    if ( event == NULL )
        return false;

    if (!events.empty())
        return true;

#ifdef _DEBUG

    if (event->eid == BREAKPOINT && event->bpt.hea != BADADDR)
    {
        debug_printf("continue_after_event: BREAKPOINT (HW)\n");
    }
    else
    {
        debug_printf("continue_after_event: %s\n", get_event_name(event->eid));
    }

#endif

    switch (event->eid)
    {
    case PROCESS_ATTACH:
    case PROCESS_SUSPEND:
    case STEP:
    case BREAKPOINT:
    case NO_EVENT:
        gdb_continue();
        break;
    default:
        break;
    } 

    return true;
}

//--------------------------------------------------------------------------
void idaapi stopped_at_debug_event(bool dlls_added)
{
}

//--------------------------------------------------------------------------
int idaapi thread_suspend(thid_t tid)
{
    debug_printf("thread_suspend: tid = 0x%llX\n", (uint64)tid);

    gdb_pause();

    return 1;
}

//--------------------------------------------------------------------------
int idaapi thread_continue(thid_t tid)
{
    debug_printf("thread_continue: tid = 0x%llX\n", (uint64)tid);

    gdb_continue();

    return 1;
}

#define G_STR_SIZE 256

enum spu_instructions
{
    SPU_a  =   58,
    SPU_absdb  =   150,
    SPU_addx  =   108,
    SPU_ah  =   76,
    SPU_ahi  =   9,
    SPU_ai  =   8,
    SPU_and  =   70,
    SPU_andbi  =   7,
    SPU_andc  =   59,
    SPU_andhi  =   6,
    SPU_andi  =   5,
    SPU_avgb  =   84,
    SPU_bg  =   41,
    SPU_bgx  =   97,
    SPU_bi  =   109,
    SPU_bihnz  =   93,
    SPU_bihz  =   92,
    SPU_binz  =   91,
    SPU_bisl  =   110,
    SPU_bisled  =   112,
    SPU_biz  =   90,
    SPU_br  =   171,
    SPU_bra  =   166,
    SPU_brasl  =   169,
    SPU_brhnz  =   163,
    SPU_brhz  =   161,
    SPU_brnz  =   159,
    SPU_brsl  =   172,
    SPU_brz  =   157,
    SPU_cbd  =   180,
    SPU_cbx  =   139,
    SPU_cdd  =   183,
    SPU_cdx  =   142,
    SPU_ceq  =   124,
    SPU_ceqb  =   138,
    SPU_ceqbi  =   27,
    SPU_ceqh  =   131,
    SPU_ceqhi  =   26,
    SPU_ceqi  =   25,
    SPU_cflts  =   195,
    SPU_cfltu  =   196,
    SPU_cg  =   60,
    SPU_cgt  =   39,
    SPU_cgtb  =   44,
    SPU_cgtbi  =   17,
    SPU_cgth  =   42,
    SPU_cgthi  =   16,
    SPU_cgti  =   15,
    SPU_cgx  =   96,
    SPU_chd  =   181,
    SPU_chx  =   140,
    SPU_clgt  =   69,
    SPU_clgtb  =   83,
    SPU_clgtbi  =   21,
    SPU_clgth  =   65,
    SPU_clgthi  =   20,
    SPU_clgti  =   19,
    SPU_clz  =   62,
    SPU_cntb  =   66,
    SPU_csflt  =   197,
    SPU_cuflt  =   198,
    SPU_cwd  =   182,
    SPU_cwx  =   141,
    SPU_dfa  =   80,
    SPU_dfceq  =   126,
    SPU_dfcgt  =   72,
    SPU_dfcmeq  =   133,
    SPU_dfcmgt  =   79,
    SPU_dfm  =   82,
    SPU_dfma  =   101,
    SPU_dfms  =   102,
    SPU_dfnma  =   104,
    SPU_dfnms  =   103,
    SPU_dfs  =   81,
    SPU_dftsv  =   178,
    SPU_dsync  =   32,
    SPU_eqv  =   43,
    SPU_fa  =   73,
    SPU_fceq  =   125,
    SPU_fcgt  =   71,
    SPU_fcmeq  =   132,
    SPU_fcmgt  =   78,
    SPU_fesd  =   45,
    SPU_fi  =   86,
    SPU_fm  =   75,
    SPU_fma  =   155,
    SPU_fms  =   156,
    SPU_fnms  =   154,
    SPU_frds  =   47,
    SPU_frest  =   121,
    SPU_frsqest  =   122,
    SPU_fs  =   74,
    SPU_fscrrd  =   107,
    SPU_fscrwr  =   123,
    SPU_fsm  =   117,
    SPU_fsmb  =   119,
    SPU_fsmbi  =   162,
    SPU_fsmh  =   118,
    SPU_gb  =   114,
    SPU_gbb  =   116,
    SPU_gbh  =   115,
    SPU_hbr  =   113,
    SPU_hbra  =   192,
    SPU_hbrr  =   194,
    SPU_heq  =   89,
    SPU_heqi  =   28,
    SPU_hgt  =   37,
    SPU_hgti  =   18,
    SPU_hlgt  =   85,
    SPU_hlgti  =   22,
    SPU_il  =   165,
    SPU_ila  =   193,
    SPU_ilh  =   160,
    SPU_ilhu  =   173,
    SPU_iohl  =   167,
    SPU_iret  =   111,
    SPU_lnop  =   30,
    SPU_lqa  =   170,
    SPU_lqd  =   11,
    SPU_lqr  =   168,
    SPU_lqx  =   127,
    SPU_lr  =   199,
    SPU_mfspr  =   34,
    SPU_mpy  =   61,
    SPU_mpya  =   153,
    SPU_mpyh  =   128,
    SPU_mpyhh  =   129,
    SPU_mpyhha  =   99,
    SPU_mpyhhau  =   100,
    SPU_mpyhhu  =   136,
    SPU_mpyi  =   23,
    SPU_mpys  =   130,
    SPU_mpyu  =   38,
    SPU_mpyui  =   24,
    SPU_mtspr  =   87,
    SPU_nand  =   68,
    SPU_nop  =   33,
    SPU_nor  =   120,
    SPU_or  =   40,
    SPU_orbi  =   2,
    SPU_orc  =   77,
    SPU_orhi  =   1,
    SPU_ori  =   0,
    SPU_orx  =   149,
    SPU_rchcnt  =   36,
    SPU_rdch  =   35,
    SPU_rot  =   48,
    SPU_roth  =   52,
    SPU_rothi  =   188,
    SPU_rothm  =   53,
    SPU_rothmi  =   189,
    SPU_roti  =   184,
    SPU_rotm  =   49,
    SPU_rotma  =   50,
    SPU_rotmah  =   54,
    SPU_rotmahi  =   190,
    SPU_rotmai  =   186,
    SPU_rotmi  =   185,
    SPU_rotqbi  =   143,
    SPU_rotqbii  =   179,
    SPU_rotqby  =   146,
    SPU_rotqbybi  =   134,
    SPU_rotqbyi  =   176,
    SPU_rotqmbi  =   144,
    SPU_rotqmbii  =   174,
    SPU_rotqmby  =   147,
    SPU_rotqmbybi  =   135,
    SPU_rotqmbyi  =   177,
    SPU_selb  =   151,
    SPU_sf  =   105,
    SPU_sfh  =   56,
    SPU_sfhi  =   4,
    SPU_sfi  =   3,
    SPU_sfx  =   95,
    SPU_shl  =   51,
    SPU_shlh  =   55,
    SPU_shlhi  =   57,
    SPU_shli  =   187,
    SPU_shlqbi  =   145,
    SPU_shlqbii  =   191,
    SPU_shlqby  =   148,
    SPU_shlqbybi  =   137,
    SPU_shlqbyi  =   175,
    SPU_shufb  =   152,
    SPU_stop  =   29,
    SPU_stopd  =   94,
    SPU_stqa  =   158,
    SPU_stqd  =   10,
    SPU_stqr  =   164,
    SPU_stqx  =   98,
    SPU_sumb  =   46,
    SPU_sync  =   31,
    SPU_wrch  =   88,
    SPU_xor  =   106,
    SPU_xorbi  =   14,
    SPU_xorhi  =   13,
    SPU_xori  =   12,
    SPU_xsbh  =   67,
    SPU_xshw  =   64,
    itype_xswd  =   63,
};

//-------------------------------------------------------------------------
int do_step(uint32 tid, uint32 dbg_notification)
{
    debug_printf("do_step\n");

    char mnem[G_STR_SIZE] = {0};

    ea_t ea = read_pc_register(tid);

    mnem[0] = 0;

    bool unconditional_noret = false;

    ea_t next_addr = ea + 4;
    ea_t resolved_addr = BADADDR;
    if (decode_insn(ea))
    {
        u32 reg[4] = { 0 };

        insn_t l_cmd = cmd;
        switch (l_cmd.itype)
        {
        case MIPS_bc0f:        // Branch on Coprocessor 0 False
        case MIPS_bc1f:        // Branch on FPU False
        case MIPS_bc2f:        // Branch on Coprocessor 2 False
        case MIPS_bc3f:        // Branch on Coprocessor 3 False
        case MIPS_bc0fl:       // Branch on Coprocessor 0 False Likely
        case MIPS_bc1fl:       // Branch on FPU False Likely
        case MIPS_bc2fl:       // Branch on Coprocessor 2 False Likely
        case MIPS_bc3fl:       // Branch on Coprocessor 3 False Likely
        case MIPS_bc0t:        // Branch on Coprocessor 0 True
        case MIPS_bc1t:        // Branch on FPU True
        case MIPS_bc2t:        // Branch on Coprocessor 2 True
        case MIPS_bc3t:        // Branch on Coprocessor 3 True
        case MIPS_bc0tl:       // Branch on Coprocessor 0 True Likely
        case MIPS_bc1tl:       // Branch on FPU True Likely
        case MIPS_bc2tl:       // Branch on Coprocessor 2 True Likely
        case MIPS_bc3tl:       // Branch on Coprocessor 3 True Likely
            {
                resolved_addr = l_cmd.Op1.addr & ~3;
                next_addr = ea + 8;
            }
            break;
        case MIPS_beq:         // Branch on Equal
        case MIPS_beql:        // Branch on Equal Likely
        case MIPS_bne:         // Branch on Not Equal
        case MIPS_bnel:        // Branch on Not Equal Likely
            {
                resolved_addr = l_cmd.Op3.addr & ~3;
                next_addr = ea + 8;
            }
            break;
        case MIPS_bgez:        // Branch on Greater Than or Equal to Zero
        case MIPS_bgezal:      // Branch on Greater Than or Equal to Zero And Link
        case MIPS_bgezall:     // Branch on Greater Than or Equal to Zero And Link Likely
        case MIPS_bgezl:       // Branch on Greater Than or Equal to Zero Likely
        case MIPS_bgtz:        // Branch on Greater Than Zero
        case MIPS_bgtzl:       // Branch on Greater Than Zero Likely
        case MIPS_blez:        // Branch on Less Than or Equal to Zero
        case MIPS_blezl:       // Branch on Less Than or Equal to Zero Likely
        case MIPS_bltz:        // Branch on Less Than Zero
        case MIPS_bltzal:      // Branch on Less Than Zero And Link
        case MIPS_bltzall:     // Branch on Less Than Zero And Link Likely
        case MIPS_bltzl:       // Branch on Less Than Zero Likely
        case MIPS_bnez:        // Branch on Not Zero
        case MIPS_bnezl:       // Branch on Not Zero Likely
        case MIPS_beqz:        // Branch on Zero
        case MIPS_beqzl:       // Branch on Zero Likely
            {
                resolved_addr = l_cmd.Op2.addr & ~3;
                next_addr = ea + 8;
            }
            break;
        case MIPS_j:           // Jump
        case MIPS_jal:         // Jump And Link
        case MIPS_jalx:        // Jump And Link And Exchange
        case MIPS_b:           // Branch Always
        case MIPS_bal:         // Branch Always and Link
            {
                resolved_addr = l_cmd.Op1.addr & ~3;
                next_addr = ea + 8;
            }
            break;
        case MIPS_jr:          // Jump Register
            {
                unconditional_noret = true;
            }
        case MIPS_jalr:        // Jump And Link Register
            {
                gdb_read_register(register_ids[l_cmd.Op1.reg], reg);
                resolved_addr = reg[0] & ~3;
                next_addr = ea + 8;
            }
            break;
        default:
            {
            }
            break;
        }

        // get mnemonic
        ua_mnem(ea, mnem, sizeof(mnem));

        //debug_printf("do_step:\n");
        debug_printf("\tnext address: %08llX - resolved address: %08llX - decoded mnemonic: %s\n", (uint64)next_addr, (uint64)resolved_addr, mnem);
    }

    uint32 instruction;
    if (BADADDR != next_addr && (BADADDR == resolved_addr || !unconditional_noret))
    {
        gdb_add_bp(next_addr, GDB_BP_TYPE_X, 4);
        step_bpts.insert(next_addr);
    }

    if (BADADDR != resolved_addr && (unconditional_noret || STEP_OVER != dbg_notification))
    {
        gdb_add_bp(resolved_addr, GDB_BP_TYPE_X, 4);
        step_bpts.insert(resolved_addr);
    }

    return 1;
}

//--------------------------------------------------------------------------
// Run one instruction in the thread
int idaapi thread_set_step(thid_t tid)
{
    debug_printf("thread_set_step\n");

    int dbg_notification;
    int result = 0;

    dbg_notification = get_running_notification();

    if (dbg_notification == STEP_INTO || dbg_notification == STEP_OVER)
    {
        result = do_step(tid, dbg_notification);
        singlestep = true;
    }

    return result;
}

//-------------------------------------------------------------------------
uint32 read_pc_register(uint32 tid) 
{
    u32 reg[4];
    gdb_read_register(register_ids[REF_INDEX_PC], reg);

    return reg[0];
}

//--------------------------------------------------------------------------
// Read thread registers
int idaapi read_registers(thid_t tid, int clsmask, regval_t *values)
{
    if ( values == NULL ) 
    {
        debug_printf("NULL ptr detected !\n");
        return 0;
    }

    debug_printf("read_registers\n");

    u32 reg[REGISTER_COUNT][4] = { 0 };
    gdb_read_registers(reg);

    if (0 != (clsmask & registers[0].register_class) ||
        0 != (clsmask & registers[GPR_COUNT].register_class))
    {
        for (u32 i = 0; i < 32; ++i)
        {
            values[i].ival = reg[i][0];
            values[i + GPR_COUNT].set_bytes((u8*)reg[i], 16);
        }

        // PC
        values[REF_INDEX_PC].ival = reg[REF_INDEX_PC][0];
        // HI
        values[REF_INDEX_HI].ival = reg[REF_INDEX_HI][0];
        // LO
        values[REF_INDEX_LO].ival = reg[REF_INDEX_LO][0];
    }

    for (u32 i = GPR_COUNT; i < REGISTER_COUNT; ++i)
    {
        if (0 == (clsmask & registers[i + 32].register_class))
            continue;

        switch (registers[i + 32].dtyp)
        {
        case dt_dword:
        {
            values[i + 32].ival = reg[i][0];
        }
        break;

        case dt_byte16:
        {
            values[i + 32].set_bytes((u8*)reg[i], 16);
        }
        break;

        default:
            break;
        }
    }

    return 1;
}

//--------------------------------------------------------------------------
// Write one thread register
int idaapi write_register(thid_t tid, int reg_idx, const regval_t *value)
{
    debug_printf("write_register\n");

    // zero register should be read only
    if (0 == reg_idx || GPR_COUNT == reg_idx)
        return 0;

    u32 reg[4] = {0};
    const int reg_id = register_ids[reg_idx];
    const int reg_type = registers[reg_idx].dtyp;

    if (reg_idx < 32)
    {
        gdb_read_register(reg_id, reg);
    }

    switch (reg_type)
    {
    case dt_dword:
    {
        reg[0] = value->ival & 0xFFFFFFFF;
    }
    break;

    case dt_byte16:
    {
        u32* in_reg = (u32*)value->get_data();
        reg[0] = in_reg[0];
        reg[1] = in_reg[1];
        reg[2] = in_reg[2];
        reg[3] = in_reg[3];
    }
    break;

    default:
    {
        return 0;
    }
    break;
    }

    gdb_write_register(reg_id, reg);

    return 1;
}

//--------------------------------------------------------------------------
// Get information on the memory areas
// The debugger module fills 'areas'. The returned vector MUST be sorted.
// Returns:
//   -3: use idb segmentation
//   -2: no changes
//   -1: the process does not exist anymore
//    0: failed
//    1: new memory layout is returned
int idaapi get_memory_info(meminfo_vec_t &areas)
{
    debug_printf("get_memory_info\n");

    memory_info_t info;

    info.startEA = 0;
    info.endEA = LS_SIZE; // 0xFFFF0000;
    info.name = NULL;
    info.sclass = NULL;
    info.sbase = 0;
    info.bitness = 1;
    info.perm = 0; // SEGPERM_EXEC / SEGPERM_WRITE / SEGPERM_READ
    
    areas.push_back(info);

    return 1;
}

//--------------------------------------------------------------------------
// Read process memory
ssize_t idaapi read_memory(ea_t ea, void *buffer, size_t size)
{
    debug_printf("read_memory\n");

    return gdb_read_mem(ea, (u8*)buffer, size);
}

//--------------------------------------------------------------------------
// Write process memory
ssize_t idaapi write_memory(ea_t ea, const void *buffer, size_t size)
{
    debug_printf("write_memory\n");

    return gdb_write_mem(ea, (u8*)buffer, size);
}

//--------------------------------------------------------------------------
int idaapi is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
    debug_printf("is_ok_bpt\n");

    switch(type)
    {
        case BPT_SOFT:
            {
                debug_printf("Software breakpoint\n");

                return BPT_OK;
            }
            break;

        case BPT_EXEC:
            {
                debug_printf("Execute instruction\n");

                return BPT_BAD_TYPE;
            }
            break;

        case BPT_WRITE:
            {
                debug_printf("Write access\n");

                return BPT_OK;

                /*if (len != 8)
                {
                    msg("Hardware breakpoints must be 8 bytes long\n");
                    return BPT_BAD_LEN;
                }*/
                
/*
                if (ea % 8 != 0)
                {
                    msg("Hardware breakpoints must be 8 byte aligned\n");
                    return BPT_BAD_ALIGN;
                }
                
                if (dabr_is_set == false)
                {
                    //dabr_is_set is not set yet bug
                    return BPT_OK;
                }
                else
                {
                    msg("It's possible to set a single hardware breakpoint\n");
                    return BPT_TOO_MANY;
                }
*/
            }
            break;

            // No read access?

        case BPT_RDWR:
            {
                debug_printf("Read/write access\n");

                return BPT_OK;

                /*if (len != 8)
                {
                    msg("Hardware breakpoints must be 8 bytes long\n");
                    return BPT_BAD_LEN;
                }*/

/*
                if (ea % 8 != 0)
                {
                    msg("Hardware breakpoints must be 8 byte aligned\n");
                    return BPT_BAD_ALIGN;
                }

                if (dabr_is_set == false)
                {
                    //dabr_is_set is not set yet bug
                    return BPT_OK;
                }
                else
                {
                    msg("It's possible to set a single hardware breakpoint\n");
                    return BPT_TOO_MANY;
                }
*/
            }
            break;

        default:
            debug_printf("Unsupported BP type !\n");
            return BPT_BAD_TYPE;
    }

}

//--------------------------------------------------------------------------
int idaapi update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
    debug_printf("update_bpts - add: %d - del: %d\n", (uint32)nadd, (uint32)ndel);

    int i;
    //std::vector<uint32>::iterator it;
    uint32 orig_inst = -1;
    uint32 BPCount;
    int cnt = 0;

    //debug_printf("BreakPoints sum: %d\n", BPCount);

    //bp_list();

    for (i = 0; i < ndel; i++)
    {
        debug_printf("del_bpt: type: %d, ea: 0x%llX, code: %d\n", (uint32)bpts[nadd + i].type, (uint64)bpts[nadd + i].ea, (uint32)bpts[nadd + i].code);

        bpts[nadd + i].code = BPT_OK;
        cnt++;

        switch(bpts[nadd + i].type)
        {
        case BPT_SOFT:
            {
                debug_printf("Software breakpoint\n");

                gdb_remove_bp(bpts[nadd + i].ea, GDB_BP_TYPE_X, bpts[nadd + i].size);

                main_bpts.erase(bpts[nadd + i].ea);

                main_bpts_map.erase(bpts[nadd + i].ea);
            }
            break;

        case BPT_EXEC:
            {
                debug_printf("Execute breakpoint\n");

                gdb_remove_bp(bpts[nadd + i].ea, GDB_BP_TYPE_X, bpts[nadd + i].size);

                main_bpts.erase(bpts[nadd + i].ea);

                main_bpts_map.erase(bpts[nadd + i].ea);
            }
            break;

        case BPT_WRITE:
            {
                debug_printf("Write access\n");

                gdb_remove_bp(bpts[nadd + i].ea, GDB_BP_TYPE_W, bpts[nadd + i].size);

                main_bpts.erase(bpts[nadd + i].ea);

                main_bpts_map.erase(bpts[nadd + i].ea);
            }
            break;

        case BPT_RDWR:
            {
                debug_printf("Read/write access\n");

                gdb_remove_bp(bpts[nadd + i].ea, GDB_BP_TYPE_A, bpts[nadd + i].size);

                main_bpts.erase(bpts[nadd + i].ea);

                main_bpts_map.erase(bpts[nadd + i].ea);
            }
            break;
        }
    }

    for (i = 0; i < nadd; i++)
    {
        if (bpts[i].code != BPT_OK)
            continue;

        debug_printf("add_bpt: type: %d, ea: 0x%llX, code: %d, size: %d\n", (uint32)bpts[i].type, (uint64)bpts[i].ea, (uint32)bpts[i].code, (uint32)bpts[i].size);

        //BPT_SKIP

        switch(bpts[i].type)
        {
        case BPT_SOFT:
            {
                debug_printf("Software breakpoint\n");

                gdb_add_bp(bpts[i].ea, GDB_BP_TYPE_X, bpts[i].size);

                bpts[i].code = BPT_OK;

                main_bpts.insert(bpts[i].ea);

                // NOTE: Software breakpoints require "original bytes" data
                gdb_read_mem(bpts[i].ea, (u8*)&orig_inst, sizeof(orig_inst));

                bpts[i].orgbytes.qclear();
                bpts[i].orgbytes.append(&orig_inst,  sizeof(orig_inst));

                cnt++;
            }
            break;

        case BPT_EXEC:
            {
                debug_printf("Execute instruction\n");

                gdb_add_bp(bpts[i].ea, GDB_BP_TYPE_X, bpts[i].size);

                bpts[i].code = BPT_OK;

                main_bpts.insert(bpts[i].ea);

                cnt++;
            }
            break;

        case BPT_WRITE:
            {
                debug_printf("Write access\n");

                gdb_add_bp(bpts[i].ea, GDB_BP_TYPE_W, bpts[i].size);

                bpts[i].code = BPT_OK;

                main_bpts.insert(bpts[i].ea);

                cnt++;
            }
            break;

            // No read access?

        case BPT_RDWR:
            {
                debug_printf("Read/write access\n");

                gdb_add_bp(bpts[i].ea, GDB_BP_TYPE_A, bpts[i].size);

                bpts[i].code = BPT_OK;

                main_bpts.insert(bpts[i].ea);

                cnt++;
            }
            break;

        default:
            debug_printf("Unsupported BP type !\n");
            break;
        }
    }

    //debug_printf("BreakPoints sum: %d\n", BPCount);

    //bp_list();

    return cnt;
}

//--------------------------------------------------------------------------
// Map process address
ea_t idaapi map_address(ea_t off, const regval_t *regs, int regnum)
{
    //debug_printf("map_address\n");

    if (regs == NULL)
    {
        return off;
    }

    if (regnum >= 0)
    {
        if (regnum < GPR_COUNT)
        {
            return regs[regnum].ival & 0xFFFFFFFF;
        }
    }

    return BADADDR;
}

//-------------------------------------------------------------------------
int idaapi send_ioctl(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize)
{
    return 0;
}

//--------------------------------------------------------------------------
//
//      DEBUGGER DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
debugger_t debugger =
{
    IDD_INTERFACE_VERSION,
    DEBUGGER_NAME,				// Short debugger name
    DEBUGGER_ID,	// Debugger API module id
    PROCESSOR_NAME,				// Required processor name
    DBG_FLAG_REMOTE | DBG_FLAG_NOHOST | DBG_FLAG_NEEDPORT | DBG_FLAG_CAN_CONT_BPT | DBG_FLAG_NOSTARTDIR | DBG_FLAG_NOPARAMETERS | DBG_FLAG_NOPASSWORD | DBG_FLAG_DEBTHREAD,

    register_classes,			// Array of register class names
    RC_GPR,					// Mask of default printed register classes
    registers,					// Array of registers
    qnumber(registers),			// Number of registers

    0x1000,						// Size of a memory page

    bpt_code,				    // Array of bytes for a breakpoint instruction
    qnumber(bpt_code),			// Size of this array
    0,							// for miniidbs: use this value for the file type after attaching
    0,							// reserved

    init_debugger,
    term_debugger,

    process_get_info,
    deci3_start_process,
    deci3_attach_process,
    deci3_detach_process,
    rebase_if_required_to,
    prepare_to_pause_process,
    deci3_exit_process,

    get_debug_event,
    continue_after_event,
    NULL, //set_exception_info,
    stopped_at_debug_event,

    thread_suspend,
    thread_continue,
    thread_set_step,
    read_registers,
    write_register,
    NULL, //thread_get_sreg_base

    get_memory_info,
    read_memory,
    write_memory,

    is_ok_bpt,
    update_bpts,
    NULL, //update_lowcnds
    NULL, //open_file
    NULL, //close_file
    NULL, //read_file
    map_address,
    NULL, //set_dbg_options
    NULL, //get_debmod_extensions
    NULL, //update_call_stack
    NULL, //appcall
    NULL, //cleanup_appcall
    NULL, //eval_lowcnd
    NULL, //write_file
    send_ioctl,
};
