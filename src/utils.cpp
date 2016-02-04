#include "utils.h"

/*****************************************************************************
 Name:		first_arg
 Purpose:	Pick off one argument from a string and return the rest.
            Understands quates, parenthesis (barring ) ('s) and percentages.
 ****************************************************************************/
const char *first_arg(const char *argument, char *output, size_t len) {
    char *arg_first = output;
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

    while ( *argument != '\0' && argument != output) {
        if ( *argument == cEnd ) {
            argument++;
            break;
        }
        
        *arg_first = *argument;
        if (len > 0 && --len > 0) arg_first++;
        argument++;
    }
    *arg_first = '\0';
    
    while ( *argument == ' ' ) argument++;
    return argument;
}

/*
 * Compare strings, case insensitive, for prefix matching.
 * Return false if astr not a prefix of bstr.
 */
bool str_prefix(const char *astr, const char *bstr) {
    if (astr == nullptr || bstr == nullptr) return false;

    for (; *astr; astr++, bstr++) {
        if (tolower(*astr) != tolower(*bstr)) return false;
    }
    return true;
}

double vector_length(double x, double y) {
    return point_distance(0.0, 0.0, x, y);
}

double point_distance(double x1, double y1, double x2, double y2) {
    double dx = x2 - x1;
    double dy = y2 - y1;
    return sqrt(dx*dx + dy*dy);
}

void normalize(double* x, double* y) {
    double d = vector_length(*x, *y);
    if (d == 0.0) return;
   *x = *x / d;
   *y = *y / d;
}

void generate_salt(char *s, const size_t len) {
    if (len == 0) return;
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    for (size_t i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    s[len-1] = 0;
}

void sha256(const char *text, char *to) {
    size_t i;
    std::string command;
    FILE *fp;

    command.append("printf \"");
    char buf[32];
    for (i=0;;++i) {
        if (!text[i]) break;
        sprintf(buf, "%02x", text[i]);
        command.append(buf);
    }
    command.append("\" | xxd -p -r | sha256sum");

    /* Open the command for reading. */
    fp = popen(command.c_str(), "r");
    if (fp == nullptr) {
        *to = '\0';
        return;
    }

    char c;
    for (i=0; i<64; ++i) {
        c = fgetc(fp);
        if (c == EOF) break;
        to[i] = c;
    }
    to[i] = '\0';

    pclose(fp);
}

bool is_set(size_t flags, size_t flag) {
    return ((flags & flag) == flag);
}

bool is_safe(const char *text) {
    while (1) {
        if (*text == '\0') break;
        if (!isalnum(*text) && *text != '_') return false;
        text++;
    }
    return true;
}

int get_line(std::vector<unsigned char> *bytes, std::string *to) {
    size_t i, sz = bytes->size();
    bool newline = false;
    std::string line;
    for (i=0; i<sz; ++i) {
        unsigned char c = bytes->at(i);
        if (c == '\r') continue;
        if (c == '\n') {
            newline = true;
            break;
        }
        line.append(1, c);
    }
    if (!newline) return 0;
    to->swap(line);
    return i+1; // +1 for the newline
}

void write_to_buffer(std::vector<unsigned char> *to, const char *text) {
    for (;*text;++text) to->push_back(*text);
}

inline double deg2rad (const double degree) { return (degree * M_PIl / 180.0); };
inline double rad2deg (const double radian) { return (radian * 180.0 / M_PIl); };

void shift_coordinates(double *lat, double *lon, double angle, double meters) {
    const double earth_diameter = 6371.0 * 2 * 1000;
    double latitude  = *lat;
    double longitude = *lon;

    latitude = deg2rad(latitude);
    longitude = deg2rad(longitude);
    angle = deg2rad(angle);
    meters *= 2 / earth_diameter;

    *lat = asin((sin(latitude) * cos(meters)) + (cos(latitude) * sin(meters) * cos(angle)));
    *lon = longitude + atan2((sin(angle) * sin(meters) * cos(latitude)), cos(meters) - (sin(latitude) * sin(*lat)));
    *lat = rad2deg(*lat);
    *lon = rad2deg(*lon);

    return;
}

bool str2int(int *i, char const *s, int base = 0) {
    char *end;
    long  l;
    errno = 0;
    l = strtol(s, &end, base);
    if ((errno == ERANGE && l == std::numeric_limits<long int>::max()) || l > std::numeric_limits<int>::max()) {
        return false;
    }
    if ((errno == ERANGE && l == std::numeric_limits<long int>::min()) || l < std::numeric_limits<int>::min()) {
        return false;
    }
    if (*s == '\0' || *end != '\0') {
        return false;
    }
    *i = l;
    return true;
}

