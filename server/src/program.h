// SPDX-License-Identifier: MIT
#ifndef PROGRAM_H_14_10_2024
#define PROGRAM_H_14_10_2024

#include <string>
#include <sys/time.h>
#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <map>

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

    void log(const char *, ...) const __attribute__((format(printf, 2, 3)));

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

    class SOCKETS *get_sockets() const;

    bool has_channel(size_t session_id) const;
    bool has_guest(size_t host_id, size_t guest_id) const;
    size_t find_channel(const char *name) const;
    void set_channel(size_t session_id, const char *name);
    void rem_channel(size_t session_id);
    void set_guest(size_t host_id, size_t guest_id);
    void rem_guest(size_t host_id, size_t guest_id);
    void rem_guest(size_t guest_id);
    std::map<std::string, size_t> get_channels() const;

    private:
    void interpret(size_t session_id, std::string &input);

    static bool print_text(FILE *fp, const char *text, size_t length);
    static void write_time(char *buffer, size_t length);
    static const char *first_arg(const char *argument, std::string *output);
    static bool is_prefix(
        const char *prefix, const char *whole, bool check_case =false
    );

    int            status;
    class OPTIONS *options;
    class SIGNALS *signals;
    class SOCKETS *sockets;

    std::unordered_map<size_t, std::string> channels;
    std::unordered_map<size_t, std::unordered_set<size_t>> guests;

    static size_t log_size;
    static bool   log_time;
    struct itimerval timer;
};

inline const char *PROGRAM::first_arg(
    const char *argument, std::string *output
) {
    ////////////////////////////////////////////////////////////////////////////
    // Name:    first_arg
    // Purpose: Pick off one argument from a string and return the rest.
    //          Understands quates, parenthesis (barring ) ('s) and percentages.
    ////////////////////////////////////////////////////////////////////////////
    char cEnd = ' ';

    while (*argument == ' ') argument++;

    if ( *argument == '\'' || *argument == '"'
      || *argument == '%'  || *argument == '('
      || *argument == '{' )
    {
        if ( *argument == '(' ) {
            cEnd = ')';
            argument++;
        }
        else if ( *argument == '{' ) {
            cEnd = '}';
            argument++;
        }
        else cEnd = *argument++;
    }

    while ( *argument != '\0' ) {
        if ( *argument == cEnd ) {
            argument++;
            break;
        }

        if (output) output->append(1, *argument);
        argument++;
    }

    while ( *argument == ' ' ) argument++;
    return argument;
}

inline bool PROGRAM::is_prefix(
    const char *astr, const char *bstr, bool check_case
) {
    // Return false if astr not a prefix of bstr.

    if (astr == nullptr || bstr == nullptr) return false;
    if (check_case) {
        for (; *astr; astr++, bstr++) {
            if ((*astr) != (*bstr)) return false;
        }
    }
    else {
        for (; *astr; astr++, bstr++) {
            if (tolower(*astr) != tolower(*bstr)) return false;
        }
    }
    return true;
}

#endif
