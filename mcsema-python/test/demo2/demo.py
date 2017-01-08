
import mcsema
from subprocess import call

call("clang -m32 -c -o demo_test.o demo_test.c", shell=True)

mcsema.initialize()

bin_descend = mcsema.BinDescend()

bin_descend.arch = "x86"
bin_descend.func_maps = ["../../../mc-sema/std_defs/linux.txt"]
bin_descend.entry_symbols = ["fancy_calculation"]

print("-------")
print("bin_descend")
print("-------")
bin_descend.execute("demo_test.o")

print("")
print("")
print("-------")
print("Convert CFG To LLVM")
print("-------")


driver = mcsema.DriverEntry()
driver.is_raw = False
driver.argc = 1
driver.returns = True
driver.name = "demo_entry"
driver.sym = "fancy_calculation"
driver.ep = 0
driver.cconv = mcsema.calling_convention.caller_cleanup

cfg_to_llvm = mcsema.CFGToLLVM()
cfg_to_llvm.drivers = [driver]
cfg_to_llvm.target_triple = bin_descend.target_triple
cfg_to_llvm.native_module = bin_descend.native_module
cfg_to_llvm.execute()

bitcode = cfg_to_llvm.bitcode


f = open("demo_test.bc", "wb")
f.write(bitcode)
f.close()

call("opt -O3 demo_test.bc -o demo_test_opt.bc", shell=True)
call("llvm-dis demo_test_opt.bc", shell=True)
call("llvm-dis demo_test.bc", shell=True)
llvm_code = open("demo_test_opt.ll").read()
print("\n---------------------------------------")
print("Optimized LLVM Code")
print("---------------------------------------")
print(llvm_code)
print("---------------------------------------\n")





call("llc -filetype=obj -o demo_test_opt_llvm.o demo_test_opt.bc", shell=True)
call("clang -m32 demo_driver.c demo_test_opt_llvm.o -o demo_driver", shell=True)
call("./demo_driver", shell=True)