
import sys
import os.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
import demo_common as common
from demo_common import call

common.begin(noclean=True)


from mcsema import mcsema

mcsema.initialize()

print("---------------------------------------")
print("Generate CFG")
print("---------------------------------------")

cfg_gen = common.cfg_generator("qual", "x86-64")

cfg_gen.debug_mode = True
cfg_gen.batch_mode = True
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


call("opt -O3 qual.bc -o qual_opt.bc")
call("llvm-dis qual_opt.bc")
call("llvm-as qual_opt_mod.ll -o qual_opt.bc")

print("\n\n---------------------------------------")
print("Test Driver")
print("---------------------------------------")

call("clang -O0 -g -I ../../../mc-sema/common ../../../drivers/ELF_64_linux.S qual_opt.bc driver.c -o driver")
call("./driver")

print("\n\n---------------------------------------")
print("KLEE Driver")
print("---------------------------------------")

klee_include_dir = os.getenv("KLEE_INCLUDE_DIR")
if not klee_include_dir or klee_include_dir == "":
	print("Environment variable KLEE_INCLUDE_DIR not set.")
	exit(1)

call("clang -DDEMO_KLEE -I %s -I ../../../mc-sema/common -emit-llvm -c driver.c -o driver_klee.bc" % klee_include_dir)
call("llvm-link driver_klee.bc qual_opt.bc -o driver_klee_linked.bc")


print("\n\n---------------------------------------")
print("Running KLEE")
print("---------------------------------------")

call("klee driver_klee_linked.bc")

