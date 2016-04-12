#include "manager.h"
#include "user.h"
#include "shell.h"
#include "log.h"

// init extension for application specific initializations.
bool MANAGER::init_ext() {
    OBJECT *obj;
    if ( (obj = object_add("user")) ) {
        obj->add_event("create",  USER::create );
        obj->add_event("destroy", USER::destroy);
        obj->add_event("step",    USER::step   );
        obj->vs.set("shell_id",    0);
        obj->vs.set("alarm_pulse", 0);
        obj->vs.set("alarm_shift", 0);
    } else return false;
    
    if ( (obj = object_add("shell")) ) {
        obj->add_event("create",  SHELL::create );
        obj->add_event("destroy", SHELL::destroy);
        obj->add_event("step",    SHELL::step   );
        obj->vs.set("host",          "");
        obj->vs.set("port",          "");
        obj->vs.set("comment",       "");
        obj->vs.set("persistent", false);
    } else return false;

    return true;
}

// step extension for application specific updates.
void MANAGER::step_ext() {
    std::set<int> old_ignored = ignored;

    paralyzed.clear();
    event_perform("step");

    // Make sure only these descriptors remain to be ignored that are actually
    // used by an existing instance. If the instance does not exist then the
    // descriptor should not be in the ignored list.
    VARSET vs;
    std::set<int> new_ignored;
    for (auto a : ignored) {
        vs.clear();
        vs.set("descriptor", a);
        if (!instance_find("user", &vs)) continue;

        new_ignored.insert(a);
        if (old_ignored.count(a) > 0) continue;
        ::log("Input from descriptor %d is now ignored.", a);
    }

    for (auto a : old_ignored) {
        if (new_ignored.count(a) > 0) continue;
        ::log("Input from descriptor %d is no longer ignored.", a);
    }
    ignored.swap(new_ignored);
}

