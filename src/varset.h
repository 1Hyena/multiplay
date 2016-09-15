#ifndef VARSET_H_15_09_2016
#define VARSET_H_15_09_2016

#include <limits>
#include <string>
#include <map>
#include <string.h>

class VARSET {
    public:
    VARSET() {};
   ~VARSET() {};

    inline void set(const char *var, int val        ) {if (isset(var) && !hasi(var)) assim(var, std::to_string(val).c_str()); else integers[var] = val;}
    inline void set(const char *var, const char *val) {if (isset(var) && !hass(var)) assim(var, val);                         else strings [var] = val;}
    inline void set(const char *var, double val     ) {if (isset(var) && !hasd(var)) assim(var, std::to_string(val).c_str()); else doubles [var] = val;}

    inline int         geti(const char *var) const {return (integers.count(var) > 0 ? integers.at(var)         : 0    );}
    inline const char *gets(const char *var) const {return (strings. count(var) > 0 ? strings .at(var).c_str() : ""   );}
    inline double      getd(const char *var) const {return (doubles. count(var) > 0 ? doubles .at(var)         : 0.0  );}
    inline bool        getb(const char *var) const {return (integers.count(var) > 0 ? integers.at(var)         : false);}

    inline void get(const char *var, int         **to) {if (integers.count(var) > 0) *to = &(integers[var]); else *to = nullptr;}
    inline void get(const char *var, std::string **to) {if (strings .count(var) > 0) *to = &(strings [var]); else *to = nullptr;}
    inline void get(const char *var, double      **to) {if (doubles .count(var) > 0) *to = &(doubles [var]); else *to = nullptr;}

    inline bool hasi(const char *var) const {return (integers.count(var) > 0);}
    inline bool hass(const char *var) const {return (strings. count(var) > 0);}
    inline bool hasd(const char *var) const {return (doubles. count(var) > 0);}
    inline bool hasb(const char *var) const {return (integers.count(var) > 0);}

    inline bool isset(const char *var) const {return (hasi(var) || hass(var) || hasd(var) || hasb(var) ? true : false);}

    inline void clone_from(const VARSET *vs) {
        if (!vs) return;
        integers = (*vs).integers;
        strings  = (*vs).strings;
        doubles  = (*vs).doubles;
    }

    inline void merge_from(const VARSET *vs) {
        if (!vs) return;

        for (const auto &a : vs->integers) {
            const char *var = a.first.c_str();
            integers[var] = vs->geti(var);
        }
        for (const auto & a : vs->strings) {
            const char *var = a.first.c_str();
            strings[var] = vs->gets(var);
        }
        for (const auto & a : vs->doubles) {
            const char *var = a.first.c_str();
            doubles[var] = vs->getd(var);
        }
    }

    bool contains(const VARSET *vs) const {
        for (const auto & a : vs->integers) {
            const char *var = a.first.c_str();
            if (!hasi(var) || geti(var) != vs->geti(var)) return false;
        }
        for (const auto & a : vs->strings) {
            const char *var = a.first.c_str();
            if (!hass(var) || strcmp(gets(var), vs->gets(var))) return false;
        }
        for (const auto & a : vs->doubles) {
            const char *var = a.first.c_str();
            if (!hasd(var) || getd(var) != vs->getd(var)) return false;
        }
        return true;
    }

    void get_variables(std::set<std::string> *to) {
        for (const auto & a : integers) to->insert(a.first.c_str());
        for (const auto & a : strings ) to->insert(a.first.c_str());
        for (const auto & a : doubles ) to->insert(a.first.c_str());
    }

    inline void to_string(std::map<std::string, std::string> *to) {
        for (const auto & a : integers) (*to)[a.first.c_str()] = std::to_string(a.second);
        for (const auto & a : strings ) (*to)[a.first.c_str()] = a.second;
        for (const auto & a : doubles ) (*to)[a.first.c_str()] = std::to_string(a.second);
    }

    inline const char *to_string(const char *var) const {
        if (strings .count(var) > 0) return strings.at(var).c_str();
        if (integers.count(var) > 0) return std::to_string(integers.at(var)).c_str();
        if (doubles .count(var) > 0) return std::to_string(doubles.at(var)).c_str();
        return "";
    }

    void clear() {
        integers.clear();
        strings.clear();
        doubles.clear();
    }

    private:
    std::map<std::string, int        > integers;
    std::map<std::string, std::string> strings;
    std::map<std::string, double     > doubles;

    inline void assim(const char *var, const char *val) {
             if (!isset(var)) strings[var] = val;
        else if (hasi(var)) {
            int ival;
            if (str2int(val, &ival, 10)) integers[var] = ival;
        }
        else if (hasd(var)) {
            double dval;
            if (str2double(val, &dval)) doubles[var] = dval;
        }
    }

    static bool str2int(char const *s, int *i, int base = 0) {
        char *end;
        long  l;
        errno = 0;
        l = strtol(s, &end, base);
        if ((errno == ERANGE && l == std::numeric_limits<long int>::max()) || l > std::numeric_limits<int>::max()) return false;
        if ((errno == ERANGE && l == std::numeric_limits<long int>::min()) || l < std::numeric_limits<int>::min()) return false;
        if (*s == '\0' || *end != '\0') return false;
        *i = l;
        return true;
    }

    static bool str2double(const char *s, double *d) {
        try {
            *d = std::stod(s);
        }
        catch (...) {
            return false;
        }
        return true;
    }
};

#endif

