
import mcsema

mcsema.initialize()

lifter = mcsema.LLVMLifter()

lifter.arch = "x86"
lifter.func_maps = ["../../mc-sema/std_defs/linux.txt"]
lifter.entry_symbols = ["start"]

print("-------")
print("bin_descend")
print("-------")
lifter.bin_descend("input/demo_test1.o", "test2")

print("")
print("")
print("-------")
print("cfg_to_bc")
print("-------")
lifter.drivers = ["demo1_entry,start,raw,return,C"]
lifter.cfg_to_bc("test1.bc")
