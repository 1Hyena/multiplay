#include <stdio.h>
#include <cstdlib>
#include <cctype>
#include <string.h>
#include <math.h>
#include <string>
#include <vector>
#include <limits>

const char *first_arg(const char *argument, char *arg_first, size_t len);
bool str_prefix(const char *astr, const char *bstr);

double vector_length(double x, double y);
double point_distance(double x1, double y1, double x2, double y2);
void normalize(double* x, double* y);
void sha256(const char *text, char * to);
void generate_salt(char *s, const size_t len);
bool is_set(size_t flags, size_t flag);
bool is_safe(const char *text);
int get_line(std::vector<unsigned char> *bytes, std::string *to);
void write_to_buffer(std::vector<unsigned char> *to, const char *text);
void shift_coordinates(double *lat, double *lon, double angle, double meters);
double coordinate_distance(double lat1, double lng1, double lat2, double lng2);
inline double deg2rad (const double degree);
inline double rad2deg (const double radian);
bool str2int(char const *s, int *i, int base);
void str2hex(const char *str, std::string *hex);
void bin2hex(const unsigned char *bytes, size_t len, std::string *hex);
void hex2bin(const char *hex, std::vector<unsigned char> *bin);
bool word_exists(const char *word, const char *list);
std::string capitalize(const std::string &str);
