// SPDX-License-Identifier: MIT
#ifndef PROGRAM_H_14_10_2024
#define PROGRAM_H_14_10_2024

#include <string>
#include <sys/time.h>
#include <cstdint>

class PROGRAM {
    public:
    static constexpr const char *const VERSION = "2.0";

    PROGRAM()
    : status(EXIT_FAILURE)
    , options(nullptr)
    , signals(nullptr)
    , sockets(nullptr) {}

    ~PROGRAM() {}

    static size_t get_log_size();

    static void print_log(
        const char *, const char *, ...
    ) __attribute__((format(printf, 2, 3)));

    void log(const char *, ...) __attribute__((format(printf, 2, 3)));

    void bug(const char * =__builtin_FILE(), int =__builtin_LINE());
    bool init(int argc, char **argv);
    void run();
    int deinit();
    int get_status() const;

    const char *get_version() const;
    uint16_t get_port() const;
    bool is_verbose() const;

    long long get_timestamp() const;
    void set_timer(size_t usec);

    private:
    static bool print_text(FILE *fp, const char *text, size_t length);
    static void write_time(char *buffer, size_t length);

    int            status;
    class OPTIONS *options;
    class SIGNALS *signals;
    class SOCKETS *sockets;

    static size_t log_size;
    static bool   log_time;
    struct itimerval timer;
};

#endif
