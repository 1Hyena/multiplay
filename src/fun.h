#include <string>

// Role bits:
#define ROLE_NONE 0 // 00000
#define ROLE_AUTH 1 // 00001
#define ROLE_SU   2 // 00010
//#define ROLE_   4 // 00100
//                8 // 01000
//               16 // 10000

struct fun_type {
    const char* name;                             // function name
    const char* desc;                             // function description
    void (*function)(class USER *, const char *); // function pointer 
    size_t access;                                // function access bits
    bool logging;                                 // function is logged
};

extern const struct fun_type fun_table[];
extern class SOCKETS sockets;

bool is_logged(const char * command);

