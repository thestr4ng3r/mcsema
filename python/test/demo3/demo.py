
import sys
import os.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
import demo_common as common
from demo_common import call

common.begin()

from mcsema import mcsema

call("clang -O0 -m32 -o demo_test demo_test.c")

print("---------------------------------------")
print("Generate CFG")
print("---------------------------------------")

cfg_gen = common.cfg_generator("demo_test", "x86", "linux")
cfg_gen.func_maps = ["../../../tools/mcsema_disass/defs/linux.txt"]
cfg_gen.entry_symbols = ["main"]
cfg_gen.execute("demo_test.cfg")


print("\n\n---------------------------------------")
print("Translate to LLVM")
print("---------------------------------------")

cfg_to_llvm = mcsema.Lifter("linux", "x86", "demo_test.cfg")
cfg_to_llvm.entry_points = ["main"]
cfg_to_llvm.execute("demo_test.bc")


call("opt -O3 demo_test.bc -o demo_test_opt.bc")
call("llvm-dis demo_test_opt.bc")
call("llvm-dis demo_test.bc")


print("\n---------------------------------------")
print("Recompiling and testing")
print("---------------------------------------")

call("clang -m32 ../../../generated/ELF_32_linux.S demo_test_opt.bc -o demo_recompiled")
call("./demo_recompiled 191")
