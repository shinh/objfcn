#pragma once

class Base {
public:
    virtual ~Base() {}
    virtual int vf() = 0;
};

Base* MakeBase();
