
import mcsema
import llvmlite.binding as llvm
from ctypes import CFUNCTYPE, c_int, c_long

mcsema.initialize()

lifter = mcsema.LLVMLifter()

lifter.arch = "x86"
lifter.func_maps = ["../../mc-sema/std_defs/linux.txt"]
lifter.entry_symbols = ["start"]

print("-------")
print("bin_descend")
print("-------")
lifter.bin_descend("input/demo_test1.o")

print("")
print("")
print("-------")
print("cfg_to_bc")
print("-------")

driver = mcsema.DriverEntry()
driver.is_raw = True
driver.argc = 0
driver.returns = True
driver.name = "demo_entry"
driver.sym = "start"
driver.ep = 0
driver.cconv = mcsema.calling_convention.caller_cleanup

#lifter.drivers = ["demo_entry,test_entry,raw,return,C"]
lifter.drivers = [driver]
lifter.cfg_to_bc()

bitcode = lifter.bitcode


f = open("test1.bc", "wb")
f.write(bitcode)
f.close()



quit()


llvm.initialize()
llvm.initialize_native_target()
llvm.initialize_native_asmprinter()



target = llvm.Target.from_default_triple()
target_machine = target.create_target_machine()

backing_mod = llvm.parse_assembly("")
engine = llvm.create_mcjit_compiler(backing_mod, target_machine)




mod = llvm.parse_bitcode(bitcode)
mod.verify()

engine.add_module(mod)
engine.finalize_object()



func_ptr = engine.get_pointer_to_global(mod.get_function("demo_entry"))

#cfunc = CFUNCTYPE(c_int, c_long)(func_ptr)
#cfunc(1, 0)