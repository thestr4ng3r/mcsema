
import mcsema
import llvmlite.binding as llvm
from subprocess import call
from ctypes import CFUNCTYPE, c_int, c_long, c_double

call("clang -O0 -m32 -c -o demo_test.o demo_test.c", shell=True)

mcsema.initialize()

lifter = mcsema.LLVMLifter()

lifter.arch = "x86"
lifter.func_maps = ["../../../mc-sema/std_defs/linux.txt"]
lifter.entry_symbols = ["switch_func"]

print("-------")
print("bin_descend")
print("-------")
lifter.bin_descend("demo_test.o")

print("")
print("")
print("-------")
print("cfg_to_bc")
print("-------")

driver = mcsema.DriverEntry()
driver.is_raw = False
driver.argc = 1
driver.returns = True
driver.name = "demo_entry"
driver.sym = "switch_func"
driver.ep = 0
driver.cconv = mcsema.calling_convention.caller_cleanup

lifter.drivers = [driver]
lifter.cfg_to_bc()

bitcode = lifter.bitcode


f = open("demo_test.bc", "wb")
f.write(bitcode)
f.close()

call("opt -mtriple=i686-pc-linux-gnu -O3 demo_test.bc -o demo_test_opt.bc", shell=True)
call("llvm-link ../../../cmake-build-debug/mc-sema/runtime/linux_i386_callback.bc demo_test_opt.bc -o demo_test_linked.bc", shell=True)
call("llvm-dis demo_test_opt.bc", shell=True)
call("llvm-dis demo_test.bc", shell=True)
llvm_code = open("demo_test_opt.ll").read()
print("\n---------------------------------------")
print("Optimized LLVM Code")
print("---------------------------------------")
print(llvm_code)
print("---------------------------------------\n")





call("llc -mtriple=i686-pc-linux-gnu -filetype=obj -o demo_test_opt_llvm.o demo_test_linked.bc", shell=True)
call("clang -m32 demo_driver.c demo_test_opt_llvm.o -o demo_driver", shell=True)
call("./demo_driver", shell=True)