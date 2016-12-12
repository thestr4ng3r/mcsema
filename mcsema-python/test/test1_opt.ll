; ModuleID = 'test1_opt.bc'
target datalayout = "e-p:32:32-f64:32:64-f80:32-n8:16:32-S128"
target triple = "i686-pc-linux-gnu"

%struct.rlimit = type { i32, i32 }

define i32 @demo_entry(i32 %".1") {
driverBlock:
  %res = add i32 %".1", 1
  ret i32 %res

;#  %rl = alloca %struct.rlimit, align 8
;#  %1 = getelementptr inbounds %struct.rlimit* %rl, i32 0, i32 0
;#  store i32 0, i32* %1, align 8
;#  %2 = ptrtoint %struct.rlimit* %rl to i32
;#  %3 = call i32 @getrlimit(i32 3, i32 %2)
;#  %4 = load i32* %1, align 8
;#  %5 = call i32 @mmap(i32 0, i32 %4, i32 3, i32 131106, i32 -1, i32 0)
;#  %6 = add i32 %4, -52
;#  %7 = add i32 %6, %5
;#  %8 = inttoptr i32 %7 to i32*
;#  store i32 %0, i32* %8, align 4
;#  %rl1 = alloca %struct.rlimit, align 8
;#  %9 = getelementptr inbounds %struct.rlimit* %rl1, i32 0, i32 0
;#  store i32 0, i32* %9, align 8
;#  %10 = ptrtoint %struct.rlimit* %rl1 to i32
;#  %11 = call i32 @getrlimit(i32 3, i32 %10)
;#  %12 = load i32* %9, align 8
;#  %13 = tail call i32 @munmap(i32 %5, i32 %12)
;#  ret i32 undef
}

declare i32 @getrlimit(i32, i32)

declare i32 @mmap(i32, i32, i32, i32, i32, i32)

declare i32 @munmap(i32, i32)

!llvm.module.flags = !{!0, !1}

!0 = metadata !{i32 1, metadata !"Debug Info Version", i32 1}
!1 = metadata !{i32 1, metadata !"Dwarf Version", i32 3}
