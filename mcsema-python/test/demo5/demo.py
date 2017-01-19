

import sys
import os.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
import demo_common as common

common.begin(noclean=True)




import mcsema
from subprocess import call

call("clang -O0 -o password password.c", shell=True)

mcsema.initialize()

print("---------------------------------------")
print("Generate CFG")
print("---------------------------------------")

cfg_gen = common.cfg_generator("password")

cfg_gen.debug_mode = True
cfg_gen.batch_mode = True
cfg_gen.arch = "x86-64"
cfg_gen.func_maps = ["../../../mc-sema/std_defs/linux.txt"]
cfg_gen.entry_symbols = ["password"]
cfg_gen.ignore_native_entry_points = True

cfg_gen.execute("password.cfg")


print("\n\n---------------------------------------")
print("Translate to LLVM")
print("---------------------------------------")

cfg_to_llvm = mcsema.CFGToLLVM("x86_64-pc-linux-gnu", "password.cfg")

cfg_to_llvm.entry_points = ["password"]
cfg_to_llvm.execute("password.bc")


call("opt -O3 password.bc -o password_opt.bc", shell=True)
call("llvm-dis password_opt.bc", shell=True)
#llvm_code = open("password_opt.ll").read()


#call("llvm-as password_opt_mod.ll -o password_opt.bc", shell=True)


#call("llc -filetype=obj -o password_opt.o password_opt.bc", shell=True)
#call("clang driver.c password_opt.o -o driver", shell=True)

print("\n\n---------------------------------------")
print("Test Driver")
print("---------------------------------------")

call("clang  -I ../../../mc-sema/common ../../../drivers/ELF_64_linux.S password_opt.bc driver.c -o driver", shell=True)
call("./driver 0", shell=True)
call("./driver 42", shell=True)


print("\n\n---------------------------------------")
print("KLEE Driver")
print("---------------------------------------")

#call("clang -g ../../../drivers/ELF_64_linux.S password_opt.bc driver_klee.c -o driver_klee", shell=True)
#call("./driver_klee", shell=True)

call("clang -DDEMO_KLEE -I /home/florian/dev/klee/include -I ../../../mc-sema/common -emit-llvm -c driver.c -o driver_klee.bc", shell=True)
call("llvm-link driver_klee.bc password_opt.bc -o driver_klee_linked.bc", shell=True)



