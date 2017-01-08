
import mcsema
from subprocess import call

call("clang -O0 -m32 -c -o demo_test.o demo_test.c", shell=True)

mcsema.initialize()

lifter = mcsema.LLVMLifter()

lifter.arch = "x86"
lifter.func_maps = ["../../../mc-sema/std_defs/linux.txt"]
lifter.entry_symbols = ["start"]

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
driver.argc = 0
driver.returns = False
driver.name = "demo_entry"
driver.sym = "start"
driver.ep = 0
driver.cconv = mcsema.calling_convention.caller_cleanup

lifter.drivers = [driver]
lifter.cfg_to_bc()

bitcode = lifter.bitcode


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
