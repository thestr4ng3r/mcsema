
import sys
from subprocess import call

if len(sys.argv) == 2:
	if sys.argv[1] == "clean":
		call("rm -fv *.o *.ll *.bc", shell=True)
		quit()

call("rm -f *.o *.ll *.bc", shell=True)



call("clang -O0 -o password password.c", shell=True)

import mcsema

mcsema.initialize()

bin_descend = mcsema.BinDescend()

bin_descend.debug_mode = True
bin_descend.arch = "x86-64"
bin_descend.func_maps = ["../../../mc-sema/std_defs/linux.txt"]
bin_descend.entry_symbols = ["main2"]
bin_descend.ignore_native_entry_points = True

print("-------")
print("bin_descend")
print("-------")
bin_descend.execute("password")



cfg_to_llvm = mcsema.CFGToLLVM()
cfg_to_llvm.target_triple = bin_descend.target_triple
cfg_to_llvm.native_module = bin_descend.native_module
print("")
print("")
print("-------")
print("cfg_to_bc")
print("-------")

driver = mcsema.DriverEntry()
driver.is_raw = True
driver.argc = 0
driver.returns = True
driver.name = "password_main"
driver.sym = "main2"
driver.ep = 0
driver.cconv = mcsema.calling_convention.caller_cleanup

cfg_to_llvm.drivers = [driver]
cfg_to_llvm.execute()

bitcode = cfg_to_llvm.bitcode


f = open("password_raw.bc", "wb")
f.write(bitcode)
f.close()

call("opt -O3 password_raw.bc -o password_opt.bc", shell=True)
call("llvm-dis password_opt.bc", shell=True)
llvm_code = open("password_opt.ll").read()


call("llc -filetype=obj -o password_opt.o password_opt.bc", shell=True)
call("clang driver.c password_opt.o -o driver", shell=True)
#call("./driver", shell=True)


call("clang -I /home/florian/dev/klee/include -emit-llvm -c driver_klee.c -o driver_klee.bc", shell=True)
call("llvm-link driver_klee.bc password_opt.bc -o driver_klee_linked.bc", shell=True)



