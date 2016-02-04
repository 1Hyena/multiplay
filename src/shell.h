
class SHELL {
    friend class MANAGER;

    public:
    
    class MANAGER *manager;
    
    private:
    SHELL() {}
   ~SHELL() {}
   
    static void create (class MANAGER *manager, int id, VARSET *vs);
    static void destroy(class MANAGER *manager, int id, VARSET *vs);
    static void step   (class MANAGER *manager, int id, VARSET *vs);
};

