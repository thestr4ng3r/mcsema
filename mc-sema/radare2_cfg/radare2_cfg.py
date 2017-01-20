
import CFG_pb2
import r2pipe

from pprint import pprint


path = "test_ex"
out_file = "test.cfg"
out_file_text = "test_text.cfg"

entries = ["sym.core"]

r = r2pipe.open(path)
r.cmd("aa")


M = CFG_pb2.Module()
M.module_name = path

functions = r.cmdj("aflj")


for func in functions:
	print("Function " + func["name"])

	if func["name"] not in ["sym.vermillion", "sym.core"]:
		continue

	if func["name"] in entries:
		E = M.entries.add()
		E.entry_name = func["name"]
		E.entry_address = func["offset"]

	F = M.internal_funcs.add()
	F.entry_address = func["offset"]
	F.symbol_name = func["name"]

	graph = r.cmdj("agj @ " + str(func["offset"]))

	blocks = graph[0]["blocks"]

	for block in blocks:
		B = F.blocks.add()
		B.base_address = block["offset"]

		for k in ["jump", "fail"]:
			if k in block:
				B.block_follows.append(block[k])

		for op in block["ops"]:
			I = B.insts.add()
			I.inst_bytes = op["bytes"].decode("hex")
			I.inst_addr = op["offset"]
			I.inst_len = op["size"]

			#print("-------------------")

			#pprint(op)

			if "jump" in op:
				I.true_target = op["jump"]

			if "fail" in op:
				I.false_target = op["fail"]





outf = open(out_file, "wb")
outf.write(M.SerializeToString())
outf.close()

from google.protobuf import text_format

outf = open(out_file_text, "wb")
outf.write(text_format.MessageToString(M))
outf.close()






