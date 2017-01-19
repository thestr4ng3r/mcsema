

from r2.r_core import *

path = "../../mcsema-python/test/demo4/demo_test.o"

rc = RCore()
rc.file_open(path, 0, 0)
rc.bin_load(None, 0)

if not rc.anal_all():
	print("Anal failed")
	exit(1)


funcs = rc.anal.get_fcns()
for f in funcs:
	blocks = f.get_bbs()
	print("+" + (72 * "-"))
	print("| FUNCTION: %s @ 0x%x" % (f.name, f.addr))
	print("| (%d blocks)" % (len (blocks)))
	print("+" + (72 * "-"))


	for b in blocks:
		print("---[ Block @ 0x%x ]---" % (b.addr))
		print("   | type:        %x" % (b.type))
		print("   | size:        %d" % (b.size))
		print("   | jump:        0x%x" % (b.jump))
		print("   | fail:        0x%x" % (b.fail))
		print("   | conditional: %d" % (b.conditional))
		print("   | return:      %d" % (b.returnbb))





