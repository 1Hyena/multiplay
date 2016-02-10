#include <set>
#include <map>
#include <vector>
#include <stdarg.h>

#include "object.h"
#include "instance.h"
#include "utils.h"

class MANAGER {
    public:
     MANAGER() {clear(); }
    ~MANAGER() {if (initiated) bug("deinit not called (memory leak)");}
    
    bool init(void (*log_function)(const char *p_fmt, ...)) {
        if (log_function) log = log_function; 
        if (initiated) {
            bug("Unable to init (already initialized).");
            return false;
        }

        initiated = true;
        next_id   = 1;
        last_inactive_count = 0;
        bug_count = 0;
        return init_ext();
    }

    bool deinit() {
        if (!initiated) {
            bug("Unable to deinit (already deinitialized).");
            return false;
        }

        clear();
        initiated = false;
        return true;
    }

    void clear() {
        for (auto a : inactive_instances) {
            if (a.second == nullptr) continue;
            delete a.second;
        }
        inactive_instances.clear();

        std::vector<int> del_instances;
        del_instances.reserve(instances.size());
        for (auto a : instances) {
            if (a.second == nullptr) continue;
            del_instances.push_back(a.first);
        }
        while (!del_instances.empty()) {
            int id = del_instances.back();
            if (instance_exists(id)
            && !instance_destroy(id)) {
                bug("Failed to destroy instance: %d", id);
            }
            del_instances.pop_back();
        }
        instances.clear();

        std::vector<std::string> del_objects;
        del_objects.reserve(objects.size());
        for (auto a : objects) {
            if (a.second == nullptr) continue;
            del_objects.push_back(a.first);
        }
        while (!del_objects.empty()) {
            const char *name = del_objects.back().c_str();
            if (object_exists(name)
            && !object_delete(name)) {
                bug("Failed to delete object: %s", name);
            }
            del_objects.pop_back();
        }
        objects.clear();
    }

    OBJECT *object_add(const char *name) {
        if (object_exists(name)) {
            bug("Unable to add object '%s' - it already exists.", name);
            return nullptr;
        }
        OBJECT *obj = new (std::nothrow) OBJECT();

        if (obj) {
            obj->name = name;
            obj->vs.set("object_name", name);
            objects[name] = obj;
        }
        else bug("Not enough memory to add a new object '%s'.", name);

        return obj;
    }

    bool object_delete(const char* name) {
        if (!object_exists(name)) {
            bug("Attempt to delete a non-existent object '%s'.", name);
            return false;
        }
        OBJECT *obj = objects[name];
        delete obj;
        objects.erase(name);
        return true;
    }

    inline bool object_exists(const char* name) {
        return (objects.count(name) != 0);
    }
    
    inline OBJECT *object_find(const char* name) {
        return (object_exists(name) ? objects[name] : nullptr);
    }
    
    const char* object_get_parent(const char* object_name) {
        OBJECT *obj = object_find(object_name);
        if (!obj) return nullptr;
        return obj->parent.c_str();
    }

    int instance_create(const char* object_name) {
        OBJECT *obj = object_find(object_name);
        if (!obj) {
            bug("Attempt to create an instance of a non-existent object '%s'.", object_name);
            return 0;
        }

        INSTANCE *ins = new (std::nothrow) INSTANCE();
        if (!ins) {
            bug("Not enough memory to allocate an instance of object '%s'.", object_name);
            return 0;
        }
        
        ins->id          = next_id++;
        ins->object_name = object_name;
        ins->destroyed   = false;
        
        OBJECT *parent = object_find(obj->parent.c_str());
        if (parent) ins->vs.clone_from(&objects[parent->name]->vs);

        ins->vs.merge_from(&objects[object_name]->vs);
        inactive_instances[ins->id] = ins;
        return ins->id;
    }

    bool instance_activate(int id) {
        if (inactive_instances.count(id) == 0) {
            bug("Attempt to activate a non-existent instance %d.", id);
            return false;
        }
        instances[id] = inactive_instances[id];
        inactive_instances.erase(id);

        const char *obj_name = instances[id]->object_name.c_str();
        OBJECT *obj = object_find(obj_name);
        if (obj) {
            obj->instances.insert(id);
            
            OBJECT *parent = object_find(obj->parent.c_str());
            if (parent) parent->instances.insert(id);
        }
        else bug("Object '%s' not found when activating instance %d.", obj_name, id);

        event_perform("create", id);
        return true;
    }

    bool instance_destroy(int id) {
        if (!instance_exists(id)) {
            bug("Attempt to destroy a non-existent instance %d.", id);
            return false;
        }
        INSTANCE *ins = instances[id];
        if (ins->destroyed) {
            bug("Attempt to destroy instance %d twice.", id);
            return false;
        }
        ins->destroyed = true;

        event_perform("destroy", id);

        OBJECT *obj = object_find(ins->object_name.c_str());
        if (obj) {
            obj->instances.erase(id);

            OBJECT *parent = object_find(obj->parent.c_str());
            if (parent) parent->instances.erase(id);
        }
        else bug("Object '%s' not found when destroying instance %d.", ins->object_name.c_str(), id);

        delete ins;
        instances.erase(id);
        return true;
    }

    inline bool instance_exists(int id) {
        return (instances.count(id) > 0);
    }

    inline INSTANCE *instance_find(int id) {
        return (instance_exists(id) ? instances[id] :
                inactive_instances.count(id) > 0 ? 
                inactive_instances[id] : nullptr);
    }

    inline void step() {
        size_t iisz = inactive_instances.size();
        if (iisz != last_inactive_count) {
            log("%lu inactive instance%s.", iisz, iisz == 1 ? "" : "s");
            last_inactive_count = iisz;
        }
        
        step_ext();
        return;
    }

    inline void set(int id, const char *variable, const char *value) {
        INSTANCE *ins = instance_find(id);
        if (ins) ins->vs.set(variable, value);
    }

    inline void set(int id, const char *variable, int value) {
        INSTANCE *ins = instance_find(id);
        if (ins) ins->vs.set(variable, value);
    }

    inline void set(int id, const char *variable, double value) {
        INSTANCE *ins = instance_find(id);
        if (ins) ins->vs.set(variable, value);
    }

    inline void get_vs(int id, VARSET *to) {
        INSTANCE *ins = instance_find(id);
        if (ins) to->clone_from(&ins->vs);
    }

    void event_perform(const char *event, int id) {
        INSTANCE *ins = instance_find(id);
        if (!ins) return;
        OBJECT *obj = object_find(ins->object_name.c_str());
        if (!obj) {
            bug("Object '%s' not found when performing the '%s' event on instance %d.", ins->object_name.c_str(), event, id);
            return;
        }
        
        OBJECT *parent = object_find(obj->parent.c_str());
        if (parent) {
            if (parent->events.count(event) > 0) {
                auto funs = &parent->events[event];
                size_t sz = funs->size();

                for (size_t i=0; i<sz; ++i) {
                    funs->at(i)(this, id, nullptr);
                }
            }
        }

        if (obj->events.count(event) > 0) {
            auto funs = &obj->events[event];
            size_t sz = funs->size();

            for (size_t i=0; i<sz; ++i) {
                funs->at(i)(this, id, nullptr);
            }
        }
    }
    
    void event_perform(const char *event) {
        std::vector<std::string> update_objects;
        update_objects.reserve(objects.size());
        for (auto a : objects) {
            if (a.second == nullptr) continue;
            update_objects.push_back(a.first);
        }
        while (!update_objects.empty()) {
            OBJECT *obj = object_find(update_objects.back().c_str());
            if (obj && obj->events.count(event) > 0) {
                std::vector<int> obj_instances;
                obj_instances.reserve(obj->instances.size());
                for (auto id : obj->instances) obj_instances.push_back(id);
                
                size_t isz = obj_instances.size();
                for (size_t k=0; k<isz; ++k) {
                    int id = obj_instances[k];
                    if (!instance_exists(id)) continue;
                    auto funs = &obj->events[event];
                    size_t sz = funs->size();
                    for (size_t i=0; i<sz; ++i) funs->at(i)(this, id, nullptr);
                }
            }
            update_objects.pop_back();
        }    
    }

    int instance_find(const VARSET* vs) {
        for (auto a : instances) {
            if (a.second->vs.contains(vs)) return a.first;
        }
        return 0;
    }

    void instance_find(const VARSET* vs, std::set<int> *to) {
        for (auto a : instances) {
            if (a.second->vs.contains(vs)) to->insert(a.first);
        }
    }

    int instance_find(const char *object_name, const VARSET* vs) {
        OBJECT *obj = object_find(object_name);
        if (!obj) return 0;

        for (auto a : obj->instances) {
            INSTANCE *ins = instance_find(a);
            if (!ins) continue;
            if (ins->vs.contains(vs)) return a;
        }
        return 0;
    }
    
    void instance_find(const char *object_name, std::set<int> *to) {
        OBJECT *obj = object_find(object_name);
        if (!obj) return;

        for (auto a : obj->instances) {
            INSTANCE *ins = instance_find(a);
            if (!ins) continue;
            to->insert(a);
        }
    }

    void instance_find(const char *object_name, const VARSET *vs, std::set<int> *to) {
        OBJECT *obj = object_find(object_name);
        if (!obj) return;

        for (auto a : obj->instances) {
            INSTANCE *ins = instance_find(a);
            if (!ins) continue;
            if (ins->vs.contains(vs)) to->insert(a);
        }
    }

    void (*log)(const char *p_fmt, ...) = drop_log;
    void bug(const char *format, ...) {
        char buffer[1024];
        ++bug_count;

        va_list args;
        va_start(args, format);
        vsnprintf(buffer, sizeof(buffer), format, args);
        if (strlen(buffer) < 40) log("\x1B[1;31m%s\x1B[0m", buffer);
        else                     log("BUG %lu:\n\x1B[1;31m%s\x1B[0m", bug_count, buffer);
        va_end(args);
    }

    inline void broadcast (const char *text) {
        // Send to client users and ignore server users.
        std::set<int> users;
        instance_find("user", &users);
        for (int user_id : users) {
            INSTANCE *ins_user = instance_find(user_id);
            if (!ins_user) continue;
            int shell_id = ins_user->vs.geti("shell_id");
            INSTANCE *ins_shell = instance_find(shell_id);
            if (ins_shell && ins_shell->vs.geti("user_id") == user_id) continue;
            if (ins_user->user == nullptr) continue;

            int descriptor = ins_user->vs.geti("descriptor");
            if (obuf.count(descriptor) > 0) {
                write_to_buffer(&(obuf[descriptor]), text);
            }
        }
    }

    std::map<int, std::set<int>> descriptors; // Descriptors and their resperctive user sets.
    std::map<int, std::vector<unsigned char>> obuf; // Descriptor outputs.
    std::map<int, std::vector<unsigned char>> ibuf; // Descriptor inputs.    
    std::set<int> paralyzed; // Descriptors to be closed.
    std::set<int> ignored; // Descriptors to be ignored when reading.
    // The input ignoring mechanism is needed to prevent excess memory allocation
    // from happening in situations where a tiny amount of user input generates
    // a large amount of output for that user. Since the output is held in RAM
    // it is theoretically possible to make the process consume a lot of memory.
    // However, if we ignore the user input until its output has been flushed we
    // we are somewhat more protected against such Denial of Service attacks.

    private:
    bool init_ext();
    void step_ext();

    inline static void drop_log(const char *p_fmt, ...) {}

    bool initiated;

    std::map<std::string, OBJECT *> objects;
    std::map<int, INSTANCE *> instances;
    std::map<int, INSTANCE *> inactive_instances;
    int next_id;
    size_t last_inactive_count;
    size_t bug_count;
};

