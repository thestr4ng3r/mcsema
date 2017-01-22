

import sys
import os.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
import demo_common as common

common.begin(noclean=True)




import mcsema
from subprocess import call

#call("clang -O0 -o qual qual.c", shell=True)

mcsema.initialize()

print("---------------------------------------")
print("Generate CFG")
print("---------------------------------------")

cfg_gen = common.cfg_generator("qual")

cfg_gen.debug_mode = True
cfg_gen.batch_mode = True
cfg_gen.arch = "x86-64"
cfg_gen.func_maps = ["../../../mc-sema/std_defs/linux.txt"]
cfg_gen.entry_symbols = ["main"]
cfg_gen.ignore_native_entry_points = True

cfg_gen.execute("qual.cfg")


print("\n\n---------------------------------------")
print("Translate to LLVM")
print("---------------------------------------")

cfg_to_llvm = mcsema.CFGToLLVM("x86_64-pc-linux-gnu", "qual.cfg")

cfg_to_llvm.entry_points = ["main"]
cfg_to_llvm.execute("qual.bc")


call("opt -O3 qual.bc -o qual_opt.bc", shell=True)
call("llvm-dis qual_opt.bc", shell=True)
#llvm_code = open("qual_opt.ll").read()

call("llvm-as qual_opt_mod.ll -o qual_opt.bc", shell=True)

#call("llc -filetype=obj -o qual_opt.o qual_opt.bc", shell=True)
#call("clang driver.c qual_opt.o -o driver", shell=True)

print("\n\n---------------------------------------")
print("Test Driver")
print("---------------------------------------")

call("clang -O0 -g -I ../../../mc-sema/common ../../../drivers/ELF_64_linux.S qual_opt.bc driver.c -o driver", shell=True)
call("./driver", shell=True)



print("\n\n---------------------------------------")
print("KLEE Driver")
print("---------------------------------------")

call("clang -DDEMO_KLEE -I /home/florian/dev/klee/include -I ../../../mc-sema/common -emit-llvm -c driver.c -o driver_klee.bc", shell=True)
call("llvm-link driver_klee.bc qual_opt.bc -o driver_klee_linked.bc", shell=True)

