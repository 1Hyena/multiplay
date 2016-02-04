#include "main.h"
#include "log.h"
#include "manager.h"
#include "shell.h"
#include "user.h"

void SHELL::create(class MANAGER *manager, int id, VARSET *vs) {
    INSTANCE *ins = manager->instance_find(id);
    if (!ins || ins->shell) return;

    SHELL *sh = new (std::nothrow) SHELL();
    ins->shell = sh;
    if (!sh) {
        manager->instance_destroy(id);
        return;
    }
    sh->manager = manager;
}

void SHELL::destroy(class MANAGER *manager, int id, VARSET *vs) {
    INSTANCE *ins = manager->instance_find(id);
    if (!ins || !ins->shell) return;

    VARSET user_vs;
    user_vs.set("shell_id", id);
    int user_id;
    while ( (user_id = manager->instance_find("user", &user_vs)) ) {
        manager->set(user_id, "shell_id", 0);
        INSTANCE *user_ins = manager->instance_find(user_id);
        if (user_ins && user_ins->user) {
            user_ins->user->paralyze();
        }
    }

    delete ins->shell;
    ins->shell = nullptr;
}

void SHELL::step(MANAGER *manager, int id, VARSET *vs) {}

