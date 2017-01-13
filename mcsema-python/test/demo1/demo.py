
import mcsema
import cfg_ida
from subprocess import call

call("nasm -f elf32 -o demo_test1.o demo_test1.asm", shell=True)

mcsema.initialize()

# bin_descend = mcsema.BinDescend()
#
# bin_descend.arch = "x86"
# bin_descend.func_maps = [] #["../../mc-sema/std_defs/linux.txt"]
# bin_descend.entry_symbols = ["start"]
#
# print("-------")
# print("bin_descend")
# print("-------")
# bin_descend.execute("demo_test1.o")

ida_exec = ""

cfg_gen = cfg_ida.IDACFGGenerator(ida_exec, "../../../mc-sema/bin_descend/get_cfg.py", "demo_test1.o")
cfg_gen.debug_mode = True
cfg_gen.func_maps = []
cfg_gen.entry_symbols = ["start"]

cfg_gen.execute("demo_test1.cfg")




print("")
print("")
print("-------")
print("cfg_to_bc")
print("-------")

cfg_to_llvm = mcsema.CFGToLLVM("i686-pc-linux-gnu", "demo_test1.cfg")

driver = mcsema.DriverEntry()
driver.is_raw = True
driver.argc = 0
driver.returns = True
driver.name = "demo_entry"
driver.sym = "start"
driver.ep = 0
driver.cconv = mcsema.calling_convention.caller_cleanup

cfg_to_llvm.drivers = [driver]
cfg_to_llvm.execute()

bitcode = cfg_to_llvm.bitcode


f = open("test1.bc", "wb")
f.write(bitcode)
f.close()

call("opt -O3 test1.bc -o test1_opt.bc", shell=True)
call("llvm-dis test1_opt.bc", shell=True)
llvm_code = open("test1_opt.ll").read()
print("\n---------------------------------------")
print("Optimized LLVM Code")
print("---------------------------------------")
print(llvm_code)
print("---------------------------------------\n")





call("llc -filetype=obj -o test1_llvm.o test1_opt.bc", shell=True)
call("clang -m32 demo_driver1.c test1_llvm.o -o demo_driver1", shell=True)
call("./demo_driver1", shell=True)