

from r2.r_core import *
import CFG_pb2

path = "test.o"

rc = RCore()
rc.file_open(path, 0, 0)
rc.bin_load(None, 0)

if not rc.anal_all():
	print("Anal failed")
	exit(1)


M = CFG_pb2.Module()
M.module_name = path

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
		b.base_address = b.addr

		#for succ in [b.jump, b.fail]:
		#	if succ == -1:
		#		continue
		#	B.block_follows.extend(succ)

		cur_byte = b.addr
		end_byte = b.addr + b.size

		while cur_byte < end_byte:
			asm_op = rc.disassemble(cur_byte)

			if asm_op:
				if asm_op.size == 0:
					print("Bogus op")
					break

				print("0x%x %s" % (cur_byte, asm_op.buf_asm))

				cur_byte += asm_op.size
			else:
				print("Invalid at" + f.addr)
				break





