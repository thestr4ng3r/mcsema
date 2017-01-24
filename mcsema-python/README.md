McSema Python Bindings
============

This directory contains Python bindings for McSema. They can be installed like this when building the whole McSema project (do not simply run this in this directory):
```
cmake -DPYTHON_INSTALL_DIR=/usr/lib/python2.7/site-packages ..
make
make install
```
If `PYTHON_INSTALL_DIR` is not directly specified, the default directory for the current Python installation is being used under `CMAKE_INSTALL_PREFIX`.

The mcsema package is structured like this:
```
mcsema
|-- cfg_ida
|-- mcsema
```
While mcsema.mcsema contains everything exposed from C++, mcsema.cfg_ida provides a wrapper to conveniently run IDA Pro with the get_cfg.py script.

## Documentation

Bare documentation using Sphinx is available in [docs](./docs) with pre-build [html](./docs/build/html).   

## Demos

A variety of demos is available in [test](./test), each in its own folder:

 * [Demo 1](./demo1): Very simple assembly function from the original demo1 for McSema.
 * [Demo 2](./demo2): Simple C Function.
 * [Demo 3](./demo3): Recompiling an executable with multiple internal functions and external calls.
 * [Demo 4](./demo4): Lifting a function with a jump table. Currently produces a Segmentation Fault.
 * [Demo 5](./demo5): Solving a CrackMe by lifting a given ELF64 executable, replacing a function and using KLEE to perform symbolic execution. Requires an installation of KLEE for LLVM 3.5. 
