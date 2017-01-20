
import CFG_pb2
import r2pipe


path = "test.o"
out_file = "test.cfg"
out_file_text = "test_text.cfg"


r = r2pipe.open("test.o")
r.cmd("aa")


M = CFG_pb2.Module()
M.module_name = path

functions = r.cmdj("aflj")


for func in functions:
	print("Function " + func["name"])

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






