
from mcsema import mcsema

print("\n\n---------------------------------------")
print("Translate to LLVM")
print("---------------------------------------")

mcsema.initialize()

cfg_to_llvm = mcsema.CFGToLLVM("x86_64-pc-linux-gnu", "test.cfg")
cfg_to_llvm.entry_points = ["sym.core"]
cfg_to_llvm.execute("test.bc")




#call("opt -O3 demo_test.bc -o demo_test_opt.bc", shell=True)
#call("llvm-dis demo_test_opt.bc", shell=True)
#llvm_code = open("demo_test_opt.ll").read()