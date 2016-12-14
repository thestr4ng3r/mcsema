
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

call("opt -O3 demo_test.bc -o demo_test_opt.bc", shell=True)
call("llvm-link ../../../cmake-build-debug/mc-sema/runtime/linux_i386_callback.bc demo_test_opt.bc > demo_test_linked.bc", shell=True)
call("llvm-dis demo_test_opt.bc", shell=True)
llvm_code = open("demo_test_opt.ll").read()
print("\n---------------------------------------")
print("Optimized LLVM Code")
print("---------------------------------------")
print(llvm_code)
print("---------------------------------------\n")





call("llc -filetype=obj -o demo_test_opt_llvm.o demo_test_opt.bc", shell=True)
call("clang -m32 demo_driver.c demo_test_opt_llvm.o -o demo_driver", shell=True)
call("./demo_driver", shell=True)




quit()


llvm.initialize()
llvm.initialize_native_target()
llvm.initialize_native_asmprinter()

llvm.load_library_permanently("/lib/x86_64-linux-gnu/libc.so.6")
llvm.load_library_permanently("/lib64/ld-linux-x86-64.so.2")



target = llvm.Target.from_default_triple()
target_machine = target.create_target_machine()

backing_mod = llvm.parse_assembly("")
engine = llvm.create_mcjit_compiler(backing_mod, target_machine)




#mod = llvm.parse_bitcode(bitcode)
mod = llvm.parse_bitcode(open("demo_test_opt.bc").read())
mod.verify()

engine.add_module(mod)
engine.finalize_object()


func = mod.get_function("demo_entry")
func_ptr = engine.get_pointer_to_global(func)

#print func


cfunc = CFUNCTYPE(c_int)(func_ptr)
print cfunc(c_int(1))
