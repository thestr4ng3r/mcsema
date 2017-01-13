
import mcsema
import cfg_ida
import llvmlite.binding as llvm
from subprocess import call
from ctypes import CFUNCTYPE, c_int, c_long, c_double

call("clang -O0 -m32 -c -o demo_test.o demo_test.c", shell=True)

mcsema.initialize()


print("-------")
print("bin_descend")
print("-------")

#bin_descend = mcsema.BinDescend()
#bin_descend.arch = "x86"
#bin_descend.func_maps = ["../../../mc-sema/std_defs/linux.txt"]
#bin_descend.entry_symbols = ["switch_func"]
#bin_descend.execute("demo_test.o")

ida_exec = ""

cfg_gen = cfg_ida.IDACFGGenerator(ida_exec, "../../../mc-sema/bin_descend/get_cfg.py", "demo_test.o")
cfg_gen.debug_mode = True
cfg_gen.batch_mode = True
cfg_gen.func_maps = ["../../../mc-sema/std_defs/linux.txt"]
cfg_gen.entry_symbols = ["switch_func"]

cfg_gen.execute("demo_test.cfg")



print("")
print("")
print("-------")
print("cfg_to_bc")
print("-------")

cfg_to_llvm = mcsema.CFGToLLVM("i686-pc-linux-gnu", "demo_test.cfg")

driver = mcsema.DriverEntry()
driver.is_raw = True
driver.argc = 0
driver.returns = True
driver.name = "demo_entry"
driver.sym = "switch_func"
driver.ep = 0
driver.cconv = mcsema.calling_convention.caller_cleanup

cfg_to_llvm.drivers = [driver]
cfg_to_llvm.execute()
bitcode = cfg_to_llvm.bitcode


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