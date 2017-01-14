
import sys
import os.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
import demo_common as common

common.begin()

import mcsema
from subprocess import call

call("clang -m32 -c -o demo_test.o demo_test.c", shell=True)

mcsema.initialize()

print("---------------------------------------")
print("Generate CFG")
print("---------------------------------------")

cfg_gen = common.cfg_generator("demo_test.o")
cfg_gen.arch = "x86"
cfg_gen.debug_mode = False
cfg_gen.func_maps = ["../../../mc-sema/std_defs/linux.txt"]
cfg_gen.entry_symbols = ["fancy_calculation"]

cfg_gen.execute("demo_test.cfg")


print("\n\n---------------------------------------")
print("Translate to LLVM")
print("---------------------------------------")

cfg_to_llvm = mcsema.CFGToLLVM("i686-pc-linux-gnu", "demo_test.cfg")

"""driver = mcsema.DriverEntry()
driver.is_raw = False
driver.argc = 1
driver.returns = True
driver.name = "demo_entry"
driver.sym = "fancy_calculation"
driver.ep = 0
driver.cconv = mcsema.calling_convention.caller_cleanup

cfg_to_llvm.drivers = [driver]"""

cfg_to_llvm.entry_points = ["fancy_calculation"]
cfg_to_llvm.execute("demo_test.bc")



call("opt -O3 demo_test.bc -o demo_test_opt.bc", shell=True)
call("llvm-dis demo_test_opt.bc", shell=True)
call("llvm-dis demo_test.bc", shell=True)
llvm_code = open("demo_test_opt.ll").read()
print("\n---------------------------------------")
print("Optimized LLVM Code")
print("---------------------------------------")
print(llvm_code)
print("---------------------------------------\n")





#call("llc -filetype=obj -o demo_test_opt_llvm.o demo_test_opt.bc", shell=True)
#call("clang -m32 demo_driver.c demo_test_opt_llvm.o -o demo_driver", shell=True)


call("clang -m32 ../../../drivers/ELF_32_linux.S demo_test_opt.bc demo_driver.c -o demo_driver", shell=True)

call("./demo_driver", shell=True)