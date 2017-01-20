

from r2.r_core import *
import CFG_pb2
import ctypes

path = "test.o"
out_file = "test.cfg"
text_out_file = "test_text.cfg"

rc = RCore()
rc.file_open(path, 0, 0)
rc.bin_load(None, 0)

if not rc.anal_all():
	print("Anal failed")
	exit(1)


M = CFG_pb2.Module()
M.module_name = path


print(dir(rc.anal))

funcs = rc.anal.get_fcns()
for f in funcs:
	blocks = f.get_bbs()
	print("+" + (72 * "-"))
	print("| FUNCTION: %s @ 0x%x" % (f.name, f.addr))
	print("| (%d blocks)" % (len (blocks)))
	print("+" + (72 * "-"))

	F = M.internal_funcs.add()
	F.entry_address = f.addr
	F.symbol_name = f.name


	for b in blocks:
		print("---[ Block @ 0x%x ]---" % (b.addr))
		print("   | type:        %x" % (b.type))
		print("   | size:        %d" % (b.size))
		print("   | jump:        0x%x" % (b.jump))
		print("   | fail:        0x%x" % (b.fail))
		print("   | conditional: %d" % (b.conditional))
		print("   | return:      %d" % (b.returnbb))


		B = F.blocks.add()
		B.base_address = b.addr

		#for succ in [b.jump, b.fail]:
		#	if succ == -1:
		#		continue
		#	B.block_follows.extend(succ)

		cur_byte = b.addr
		end_byte = b.addr + b.size

		while cur_byte < end_byte:
			op = rc.disassemble(cur_byte)

			if op:
				if op.size == 0:
					print("Bogus op")
					break
			else:
				print("Invalid at" + f.addr)
				break

			print("0x%x %s" % (cur_byte, op.buf_asm))

			buf = ctypes.string_at(int(op.buf), op.size)

			I = B.insts.add()
			I.inst_addr = cur_byte
			I.inst_bytes = buf
			I.inst_len = op.size

			if op.jump:
				I.true_target = op.jump

			if op.fail:
				I.false_target = op.fail

			cur_byte += op.size


from google.protobuf import text_format

outf = open(out_file, "wb")
outf.write(M.SerializeToString())
outf.close()

outf = open(text_out_file, "w")
outf.write(text_format.MessageToString(M))
outf.close()