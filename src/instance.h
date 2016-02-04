#include "varset.h"

class INSTANCE {
    friend class MANAGER;

    public:
    VARSET vs;
    class USER  *user;
    class SHELL *shell;

    private:
     INSTANCE() {
         user  = nullptr;
         shell = nullptr;
     }
    ~INSTANCE() {}

    int id;
    std::string object_name;
    bool destroyed;
};

