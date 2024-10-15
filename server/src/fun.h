#ifndef FUN_H_15_10_2024
#define FUN_H_15_10_2024

#include "program.h"

void do_exit  (PROGRAM &program, size_t sid, const char *argument);
void do_create(PROGRAM &program, size_t sid, const char *argument);
void do_join  (PROGRAM &program, size_t sid, const char *argument);
void do_leave (PROGRAM &program, size_t sid, const char *argument);
void do_list  (PROGRAM &program, size_t sid, const char *argument);
void do_help  (PROGRAM &program, size_t sid, const char *argument);
void do_allow (PROGRAM &program, size_t sid, const char *argument);

#endif
