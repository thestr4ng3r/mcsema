
from __future__ import print_function

import CFG_pb2
import r2pipe

from pprint import pprint


path = "test.o"
out_file = "test.cfg"
out_file_text = "test_text.cfg"

entries = ["sym.core"]

r = r2pipe.open(path)
r.cmd("af@@ sym.*")



functions = r.cmdj("aflj")
relocs = r.cmdj("irj")
refs = r.cmdj("axj")


addr_offset = 0x08000000
def addr(vaddr):
	return vaddr - addr_offset



def recover_op(op, B):
	I = B.insts.add()
	I.inst_bytes = op["bytes"].decode("hex")
	I.inst_addr = addr(op["offset"])
	I.inst_len = op["size"]

	print("\t%4x\t%s" % (addr(op["offset"]), op["opcode"]))

	if "jump" in op:
		I.true_target = addr(op["jump"])

	if "fail" in op:
		I.false_target = addr(op["fail"])

	# relocations

	#if "j" in op["opcode"]:
	#	return

	for reloc in relocs:
		reloc_addr = reloc["vaddr"]

		if reloc_addr >= op["offset"] and reloc_addr < op["offset"] + op["size"]:
			print("\t\treloc " + reloc["name"] + " at %x" % reloc_addr)

			I.mem_reloc_offset = reloc_addr - op["offset"]
			I.mem_reference = refs[str(reloc_addr)]
			# TODO: check if there is a function, otherwise set DataRef
			I.mem_ref_type = CFG_pb2.Instruction.CodeRef

			print("\t\toffset %d; reference %x" % (I.mem_reloc_offset, I.mem_reference))

			break


def recover_block(block, F):
	B = F.blocks.add()
	B.base_address = addr(block["offset"])

	print("Block at %x" % addr(block["offset"]))

	for k in ["jump", "fail"]:
		if k in block:
			B.block_follows.append(addr(block[k]))

	for op in block["ops"]:
		recover_op(op, B)




def recover_function(func, M):
	print("\n-----------------------------")
	print("Function " + func["name"])
	print("-----------------------------")

	F = M.internal_funcs.add()
	F.entry_address = addr(func["offset"])
	F.symbol_name = func["name"]

	graph = r.cmdj("agj @ " + str(func["offset"]))

	blocks = graph[0]["blocks"]

	for block in blocks:
		recover_block(block, F)


def recover_entry(func, M):
	E = M.entries.add()
	E.entry_name = func["name"]
	E.entry_address = addr(func["offset"])








def main():
	M = CFG_pb2.Module()
	M.module_name = path

	for func in functions:
		recover_function(func, M)

		if func["name"] in entries:
			recover_entry(func, M)

	outf = open(out_file, "wb")
	outf.write(M.SerializeToString())
	outf.close()

	from google.protobuf import text_format

	outf = open(out_file_text, "wb")
	outf.write(text_format.MessageToString(M))
	outf.close()

main()






