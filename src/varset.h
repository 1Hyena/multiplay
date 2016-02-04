#ifndef _VARSET_H_
#define _VARSET_H_

#include <string>
#include <map>
#include <string.h>

class VARSET {
    public:
    VARSET() {};
   ~VARSET() {};

    inline void set(const char *var, int val        ) {integers[var] = val; doubles [var] = val;}
    inline void set(const char *var, const char *val) {strings [var] = val;                     }
    inline void set(const char *var, double val     ) {doubles [var] = val; integers[var] = val;}
    inline void set(const char *var, bool val       ) {booleans[var] = val; booleans[var] = val;}

    inline int         geti(const char *var) const {return (integers.count(var) > 0 ? integers.at(var)         : 0    );}
    inline const char *gets(const char *var) const {return (strings. count(var) > 0 ? strings .at(var).c_str() : ""   );}
    inline double      getd(const char *var) const {return (doubles. count(var) > 0 ? doubles .at(var)         : 0.0  );}
    inline bool        getb(const char *var) const {return (booleans.count(var) > 0 ? booleans.at(var)         : false);}    
    
    inline void get(const char *var, int         **to) {if (integers.count(var) > 0) *to = &(integers[var]); else *to = nullptr;}
    inline void get(const char *var, std::string **to) {if (strings .count(var) > 0) *to = &(strings [var]); else *to = nullptr;}
    inline void get(const char *var, double      **to) {if (doubles .count(var) > 0) *to = &(doubles [var]); else *to = nullptr;}
    inline void get(const char *var, bool        **to) {if (booleans.count(var) > 0) *to = &(booleans[var]); else *to = nullptr;}
    
    inline bool hasi(const char *var) const {return (integers.count(var) > 0);}
    inline bool hass(const char *var) const {return (strings. count(var) > 0);}
    inline bool hasd(const char *var) const {return (doubles. count(var) > 0);}
    inline bool hasb(const char *var) const {return (booleans.count(var) > 0);}

    inline void clone_from(const VARSET *vs) {
        if (!vs) return;
        integers = (*vs).integers;
        strings  = (*vs).strings;
        doubles  = (*vs).doubles;
        booleans = (*vs).booleans;
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
        for (const auto & a : vs->booleans) {
            const char *var = a.first.c_str();
            booleans[var] = vs->getb(var);
        }
    }

    bool contains(const VARSET *vs) const {
        for (const auto &a : vs->integers) {
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
        for (const auto & a : vs->booleans) {
            const char *var = a.first.c_str();
            if (!hasb(var) || getb(var) != vs->getb(var)) return false;
        }        
        return true;
    }
    
    void clear() {
        integers.clear();
        strings.clear();
        doubles.clear();
        booleans.clear();
    }

    private:
    std::map<std::string, int        > integers;
    std::map<std::string, std::string> strings;
    std::map<std::string, double     > doubles;
    std::map<std::string, bool       > booleans;
};

#endif

