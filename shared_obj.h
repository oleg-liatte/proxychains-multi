#ifndef _SHARED_OBJ_H
#define _SHARED_OBJ_H


template<class T>
class shared_obj
{
public:
    struct private_t
    {
        private_t():
            refs(1)
        {
        }

        void add_ref()
        {
            refs += 1;
        }

        void deref()
        {
            if(refs > 0)
            {
                refs -= 1;
            }

            if(refs == 0)
            {
                delete this;
            }
        }

        unsigned long refs;
        T obj;
    };

public:
    shared_obj(private_t* data = 0):
        data(data)
    {
        if(data != 0)
        {
            data->add_ref();
        }
    }

    shared_obj(const shared_obj& v):
        data(v.data)
    {
        if(data != 0)
        {
            data->add_ref();
        }
    }

    ~shared_obj()
    {
        if(data != 0)
        {
            data->deref();
        }
    }

    static private_t* create()
    {
        return new private_t;
    }

    void init()
    {
        if(data != 0)
        {
            data->deref();
        }

        data = create();
    }

    shared_obj& operator=(const shared_obj& v)
    {
        if(data != 0)
        {
            data->deref();
        }

        data = v.data();

        if(data != 0)
        {
            data->add_ref();
        }
    }

    shared_obj& operator=(private_t* v)
    {
        if(data != 0)
        {
            data->deref();
        }

        data = v;

        if(data != 0)
        {
            data->add_ref();
        }
    }

    T* get()
    {
        if(data != 0)
        {
            return &data->obj;
        }
        else
        {
            return 0;
        }
    }

    const T* get() const
    {
        if(data != 0)
        {
            return &data->obj;
        }
        else
        {
            return 0;
        }
    }

    T* operator->()
    {
        return get();
    }

    const T* operator->() const
    {
        return get();
    }

    T& operator*()
    {
        return *get();
    }

    const T& operator*() const
    {
        return *get();
    }

private:
    private_t* data;

};


#endif
