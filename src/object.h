#include <string>
#include <set>

#include "varset.h"

class OBJECT {
    friend class MANAGER;

    private:
     OBJECT() {}
    ~OBJECT() {}
    
    inline void add_event(const char *var, void (*function)(class MANAGER *, int, VARSET*)) {
        events[var].push_back(function);
    }

    inline void set_parent(const char *object_name) {
        parent = object_name;
    }

    std::string name;
    std::string parent;
    std::map<std::string, std::vector<void (*)(class MANAGER *, int, VARSET*)>> events;
    std::set<int> instances;
    VARSET vs;
};

