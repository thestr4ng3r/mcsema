from __future__ import print_function

import CFG_pb2
import r2pipe

from pprint import pprint


class Radare2CFGRecover:
	def __init__(self):
		pass

	def recover_cfg(self, path, out_file, out_file_text, entries):
		self.r = r2pipe.open(path)
		self.r.cmd("aaa")

		self.functions = self.r.cmdj("aflj")
		self.relocs = self.r.cmdj("irj")
		self.refs = self.r.cmdj("axj")
		self.imports = self.r.cmdj("iij")
		self.import_offsets = [i["plt"] for i in self.imports]

		self.M = CFG_pb2.Module()
		self.M.module_name = path

		for func in self.functions:
			if func["offset"] not in self.import_offsets:
				self.recover_function(func)
			else:
				print("function " + func["name"] + " is an import")

			if func["name"] in entries:
				self.recover_entry(func)

		outf = open(out_file, "wb")
		outf.write(self.M.SerializeToString())
		outf.close()

		from google.protobuf import text_format

		outf = open(out_file_text, "wb")
		outf.write(text_format.MessageToString(self.M))
		outf.close()

	# addr_offset = 0x08000000
	# def addr(vaddr):
	#		return vaddr - addr_offset



	def recover_op(self, op, B):
		if "bytes" not in op:
			print("invalid instruction: " + str(op))
			return False

		I = B.insts.add()
		I.inst_bytes = op["bytes"].decode("hex")
		I.inst_addr = op["offset"]
		I.inst_len = op["size"]

		# print("\t%4x\t%s" % (addr(op["offset"]), op["opcode"]))

		if "jump" in op:
			I.true_target = op["jump"]

		if "fail" in op:
			I.false_target = op["fail"]

		# relocations

		# if "j" in op["opcode"]:
		#	return

		for reloc in self.relocs:
			reloc_addr = reloc["vaddr"]

			if reloc_addr >= op["offset"] and reloc_addr < op["offset"] + op[
				"size"]:
				print("\t\treloc " + reloc["name"] + " at %x" % reloc_addr)

				I.mem_reloc_offset = reloc_addr - op["offset"]
				I.mem_reference = self.refs[str(reloc_addr)]
				# TODO: check if there is a function, otherwise set DataRef
				I.mem_ref_type = CFG_pb2.Instruction.CodeRef

				# print("\t\toffset %d; reference %x" % (I.mem_reloc_offset, I.mem_reference))

				break

		return True

	def recover_block(self, block, F):
		B = F.blocks.add()
		B.base_address = block["offset"]

		# print("Block at %x" % addr(block["offset"]))

		for k in ["jump", "fail"]:
			if k in block:
				B.block_follows.append(block[k])

		for op in block["ops"]:
			if not self.recover_op(op, B):
				return False

		return True

	def recover_function(self, func):
		print("\n-----------------------------")
		print("Function " + func["name"])
		print("-----------------------------")

		F = self.M.internal_funcs.add()
		F.entry_address = func["offset"]
		F.symbol_name = func["name"]

		graph = self.r.cmdj("agj @ " + str(func["offset"]))

		blocks = graph[0]["blocks"]

		for block in blocks:
			if not self.recover_block(block, F):
				print("function recovery failed")
				self.M.internal_funcs.remove(F)
				return

	def recover_entry(self, func):
		E = self.M.entries.add()
		E.entry_name = func["name"]
		E.entry_address = func["offset"]
		print("Recovered entry " + func["name"])

# main()
