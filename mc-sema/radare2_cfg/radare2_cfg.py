
from __future__ import print_function

import CFG_pb2
import r2pipe

from pprint import pprint


path = "test.o"
out_file = "test.cfg"
out_file_text = "test_text.cfg"

entries = ["sym.core"]

r = r2pipe.open(path)
r.cmd("aa")


M = CFG_pb2.Module()
M.module_name = path

functions = r.cmdj("aflj")

addr_offset = 0x08000040

def addr(vaddr):
	return vaddr - addr_offset

for func in functions:
	print("\n-----------------------------")
	print("Function " + func["name"])
	print("-----------------------------")

	if func["name"] not in ["sym.vermillion", "sym.core", "entry0"]:
		continue

	if func["name"] in entries:
		E = M.entries.add()
		E.entry_name = func["name"]
		E.entry_address = addr(func["offset"])

	F = M.internal_funcs.add()
	F.entry_address = addr(func["offset"])
	F.symbol_name = func["name"]

	graph = r.cmdj("agj @ " + str(func["offset"]))

	blocks = graph[0]["blocks"]

	for block in blocks:
		B = F.blocks.add()
		B.base_address = addr(block["offset"])

		print("Block at %x" % addr(block["offset"]))

		for k in ["jump", "fail"]:
			if k in block:
				B.block_follows.append(addr(block[k]))

		for op in block["ops"]:
			I = B.insts.add()
			I.inst_bytes = op["bytes"].decode("hex")
			I.inst_addr = addr(op["offset"])
			I.inst_len = op["size"]

			print("\t%4x\t%s" % (addr(op["offset"]), op["bytes"]))

			if addr(op["offset"]) == 0x2a:
				pprint(op)

			if "jump" in op:
				I.true_target = addr(op["jump"])

			if "fail" in op:
				I.false_target = addr(op["fail"])





outf = open(out_file, "wb")
outf.write(M.SerializeToString())
outf.close()

from google.protobuf import text_format

outf = open(out_file_text, "wb")
outf.write(text_format.MessageToString(M))
outf.close()






