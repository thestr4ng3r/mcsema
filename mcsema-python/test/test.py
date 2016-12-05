
import mcsema

mcsema.initialize()

lifter = mcsema.LLVMLifter()

lifter.arch = "x86"
lifter.func_maps = ["../../mc-sema/std_defs/linux.txt"]
lifter.entry_symbols = ["start"]

lifter.bin_descend("input/demo_test1.o", "test2")
