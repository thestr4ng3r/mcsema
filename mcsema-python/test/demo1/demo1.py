
import mcsema
import llvmlite.binding as llvm
from subprocess import call
from ctypes import CFUNCTYPE, c_int, c_long, c_double

call("nasm -f elf32 -o demo_test1.o demo_test1.asm", shell=True)

mcsema.initialize()

lifter = mcsema.LLVMLifter()

lifter.arch = "x86"
lifter.func_maps = [] #["../../mc-sema/std_defs/linux.txt"]
lifter.entry_symbols = ["start"]

print("-------")
print("bin_descend")
print("-------")
lifter.bin_descend("demo_test1.o")

print("")
print("")
print("-------")
print("cfg_to_bc")
print("-------")

# driver = mcsema.DriverEntry()
# driver.is_raw = False
# driver.argc = 1
# driver.returns = True
# driver.name = "demo_entry"
# driver.sym = "start"
# driver.ep = 0
# driver.cconv = mcsema.calling_convention.caller_cleanup

driver = mcsema.DriverEntry()
driver.is_raw = True
driver.argc = 0
driver.returns = True
driver.name = "demo_entry"
driver.sym = "start"
driver.ep = 0
driver.cconv = mcsema.calling_convention.caller_cleanup

lifter.drivers = [driver]
lifter.cfg_to_bc()

bitcode = lifter.bitcode


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
mod = llvm.parse_bitcode(open("test1_opt.bc").read())
mod.verify()

engine.add_module(mod)
engine.finalize_object()


func = mod.get_function("demo_entry")
func_ptr = engine.get_pointer_to_global(func)

print func


cfunc = CFUNCTYPE(c_int)(func_ptr)
print cfunc(c_int(1))
