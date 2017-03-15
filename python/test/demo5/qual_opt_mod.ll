; ModuleID = 'qual_opt.bc'
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

;module asm "  .globl sub_400680;"
;module asm "  .globl callback_sub_400680;"
;module asm "  .type callback_sub_400680,@function"
;module asm "callback_sub_400680:"
;module asm "  .cfi_startproc;"
;module asm "  pushq %rax;"
;module asm "  leaq sub_400680@plt(%rip), %rax;"
;module asm "  xchgq (%rsp), %rax;"
;module asm "  jmp __mcsema_attach_call;"
;module asm "0:"
;module asm "  .size callback_sub_400680,0b-callback_sub_400680;"
;module asm "  .cfi_endproc;"
;module asm "  .globl sub_400660;"
;module asm "  .globl callback_sub_400660;"
;module asm "  .type callback_sub_400660,@function"
;module asm "callback_sub_400660:"
;module asm "  .cfi_startproc;"
;module asm "  pushq %rax;"
;module asm "  leaq sub_400660@plt(%rip), %rax;"
;module asm "  xchgq (%rsp), %rax;"
;module asm "  jmp __mcsema_attach_call;"
;module asm "0:"
;module asm "  .size callback_sub_400660,0b-callback_sub_400660;"
;module asm "  .cfi_endproc;"
;module asm "  .globl malloc;"
;module asm "  .globl _malloc;"
;module asm "  .type _malloc,@function"
;module asm "_malloc:"
;module asm "  .cfi_startproc;"
;module asm "  pushq %rax;"
;module asm "  leaq malloc@plt(%rip), %rax;"
;module asm "  xchgq (%rsp), %rax;"
;module asm "  jmp __mcsema_detach_call;"
;module asm "0:"
;module asm "  .size _malloc,0b-_malloc;"
;module asm "  .cfi_endproc;"
;module asm "  .globl exit;"
;module asm "  .globl _exit;"
;module asm "  .type _exit,@function"
;module asm "_exit:"
;module asm "  .cfi_startproc;"
;module asm "  pushq %rax;"
;module asm "  leaq exit@plt(%rip), %rax;"
;module asm "  xchgq (%rsp), %rax;"
;module asm "  jmp __mcsema_detach_call;"
;module asm "0:"
;module asm "  .size _exit,0b-_exit;"
;module asm "  .cfi_endproc;"
;module asm "  .globl memcpy;"
;module asm "  .globl _memcpy;"
;module asm "  .type _memcpy,@function"
;module asm "_memcpy:"
;module asm "  .cfi_startproc;"
;module asm "  pushq %rax;"
;module asm "  leaq memcpy@plt(%rip), %rax;"
;module asm "  xchgq (%rsp), %rax;"
;module asm "  jmp __mcsema_detach_call;"
;module asm "0:"
;module asm "  .size _memcpy,0b-_memcpy;"
;module asm "  .cfi_endproc;"
;module asm "  .globl puts;"
;module asm "  .globl _puts;"
;module asm "  .type _puts,@function"
;module asm "_puts:"
;module asm "  .cfi_startproc;"
;module asm "  pushq %rax;"
;module asm "  leaq puts@plt(%rip), %rax;"
;module asm "  xchgq (%rsp), %rax;"
;module asm "  jmp __mcsema_detach_call;"
;module asm "0:"
;module asm "  .size _puts,0b-_puts;"
;module asm "  .cfi_endproc;"
;module asm "  .globl fgets;"
;module asm "  .globl _fgets;"
;module asm "  .type _fgets,@function"
;module asm "_fgets:"
;module asm "  .cfi_startproc;"
;module asm "  pushq %rax;"
;module asm "  leaq fgets@plt(%rip), %rax;"
;module asm "  xchgq (%rsp), %rax;"
;module asm "  jmp __mcsema_detach_call;"
;module asm "0:"
;module asm "  .size _fgets,0b-_fgets;"
;module asm "  .cfi_endproc;"
;module asm "  .globl free;"
;module asm "  .globl _free;"
;module asm "  .type _free,@function"
;module asm "_free:"
;module asm "  .cfi_startproc;"
;module asm "  pushq %rax;"
;module asm "  leaq free@plt(%rip), %rax;"
;module asm "  xchgq (%rsp), %rax;"
;module asm "  jmp __mcsema_detach_call;"
;module asm "0:"
;module asm "  .size _free,0b-_free;"
;module asm "  .cfi_endproc;"
;module asm "  .globl sub_40079f;"
;module asm "  .globl main;"
;module asm "  .type main,@function"
;module asm "main:"
;module asm "  .cfi_startproc;"
;module asm "  pushq %rax;"
;module asm "  leaq sub_40079f(%rip), %rax;"
;module asm "  xchgq (%rsp), %rax;"
;module asm "  jmp __mcsema_attach_call;"
;module asm "0:"
;module asm "  .size main,0b-main;"
;module asm "  .cfi_endproc;"

%0 = type <{ [656 x i8] }>
%1 = type <{ [8 x i8] }>
%2 = type <{ [288 x i8] }>
%RegState = type { i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i8, i8, i8, i8, i8, i8, i8, x86_fp80, x86_fp80, x86_fp80, x86_fp80, x86_fp80, x86_fp80, x86_fp80, x86_fp80, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, [10 x i8], i128, i128, i128, i128, i128, i128, i128, i128, i128, i128, i128, i128, i128, i128, i128, i128 }

@stdin = external global [8 x i8]
@data_4009a0 = internal constant %0 <{ [656 x i8] c"\01\00\02\00\00\00\00\00Welcome. Please enter your base64 encoded input:\00\00\00\00\00\00\00\00Please send your solution to kirschju@sec.in.tum.de\00\00\00\00\00I know this is probably harder than what I could expect the average student to solve. Try the best you can and send me your write-up if time is tight.\00\00\1B[32mCongratz, you win!\1B[39m\00\1B[31mNope.\1B[39m\00Z3 SMT\00http://angr.io\00\00\00\00\00\00\00\00\00\00\00\00\00\00\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF>\FF\FF\FF?456789:;<=\FF\FF\FF\FF\FF\FF\FF\00\01\02\03\04\05\06\07\08\09\0A\0B\0C\0D\0E\0F\10\11\12\13\14\15\16\17\18\19\FF\FF\FF\FF\FF\FF\1A\1B\1C\1D\1E\1F !\22#$%&'()*+,-./0123\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\A8;l\05\FC\DA\19\0A\5C\BF\1A #H4\9F\19\BCP\9D\1F\F4\ABM\8Fni<M\09\AF\C4\EF\BE\AD\DE\00\F07\13BBBB\EE\FF\C0\00" }>, align 64
@data_601010 = internal global %1 zeroinitializer, align 64
@data_601280 = internal global %2 zeroinitializer, align 64

; Function Attrs: naked
declare void @__mcsema_detach_call_value() #0

; Function Attrs: noinline
define x86_64_sysvcc void @sub_400680(%RegState*) #1 {
entry:
  %RIP_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 0, !mcsema_real_eip !0
  %RAX_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 1, !mcsema_real_eip !0
  %RSI_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 5, !mcsema_real_eip !0
  %RDI_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 6, !mcsema_real_eip !0
  %RSP_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 7, !mcsema_real_eip !0
  %RBP_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 8, !mcsema_real_eip !0
  %CF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 17, !mcsema_real_eip !0
  %PF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 18, !mcsema_real_eip !0
  %AF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 19, !mcsema_real_eip !0
  %ZF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 20, !mcsema_real_eip !0
  %SF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 21, !mcsema_real_eip !0
  %OF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 22, !mcsema_real_eip !0
  store volatile i64 4195968, i64* %RIP_write, align 8, !mcsema_real_eip !1
  store volatile i64 zext (i32 ptrtoint (%1* @data_601010 to i32) to i64), i64* %RDI_write, align 8, !mcsema_real_eip !1
  store volatile i64 4195973, i64* %RIP_write, align 8, !mcsema_real_eip !2
  %1 = bitcast i64* %RDI_write to i64**
  %2 = load i64*, i64** %1, align 8
  %3 = load i64, i64* %2, align 8, !mcsema_real_eip !2
  store volatile i8 0, i8* %AF_write, align 1, !mcsema_real_eip !2
  %4 = trunc i64 %3 to i8, !mcsema_real_eip !2
  %5 = tail call i8 @llvm.ctpop.i8(i8 %4), !mcsema_real_eip !2
  %6 = and i8 %5, 1
  %7 = xor i8 %6, 1
  store volatile i8 %7, i8* %PF_write, align 1, !mcsema_real_eip !2
  %8 = icmp eq i64 %3, 0, !mcsema_real_eip !2
  %9 = zext i1 %8 to i8, !mcsema_real_eip !2
  store volatile i8 %9, i8* %ZF_write, align 1, !mcsema_real_eip !2
  %.lobit = lshr i64 %3, 63
  %10 = trunc i64 %.lobit to i8
  store volatile i8 %10, i8* %SF_write, align 1, !mcsema_real_eip !2
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !2
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !2
  store volatile i64 4195977, i64* %RIP_write, align 8, !mcsema_real_eip !3
  %11 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !3
  %12 = and i8 %11, 1
  %13 = icmp eq i8 %12, 0
  br i1 %13, label %block_400690, label %block_40068b, !mcsema_real_eip !3

block_400620:                                     ; preds = %block_40069a, %block_40068b
  store volatile i64 4195872, i64* %RIP_write, align 8, !mcsema_real_eip !0
  store volatile i64 6296176, i64* %RSI_write, align 8, !mcsema_real_eip !0
  store volatile i64 4195877, i64* %RIP_write, align 8, !mcsema_real_eip !4
  %14 = load i64, i64* %RBP_write, align 8, !mcsema_real_eip !4
  %15 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !4
  %16 = add i64 %15, -8
  %17 = inttoptr i64 %16 to i64*, !mcsema_real_eip !4
  store i64 %14, i64* %17, align 8, !mcsema_real_eip !4
  store volatile i64 %16, i64* %RSP_write, align 8, !mcsema_real_eip !4
  store volatile i64 4195878, i64* %RIP_write, align 8, !mcsema_real_eip !5
  %18 = load i64, i64* %RSI_write, align 8, !mcsema_real_eip !5
  %19 = add i64 %18, -6296176
  %20 = xor i64 %19, %18, !mcsema_real_eip !5
  %21 = lshr i64 %20, 4
  %.lobit1 = and i64 %21, 1
  %22 = xor i64 %.lobit1, 1
  %23 = trunc i64 %22 to i8
  store volatile i8 %23, i8* %AF_write, align 1, !mcsema_real_eip !5
  %24 = trunc i64 %19 to i8, !mcsema_real_eip !5
  %25 = tail call i8 @llvm.ctpop.i8(i8 %24), !mcsema_real_eip !5
  %26 = and i8 %25, 1
  %27 = xor i8 %26, 1
  store volatile i8 %27, i8* %PF_write, align 1, !mcsema_real_eip !5
  %28 = icmp eq i64 %19, 0, !mcsema_real_eip !5
  %29 = zext i1 %28 to i8, !mcsema_real_eip !5
  store volatile i8 %29, i8* %ZF_write, align 1, !mcsema_real_eip !5
  %.lobit2 = lshr i64 %19, 63
  %30 = trunc i64 %.lobit2 to i8
  store volatile i8 %30, i8* %SF_write, align 1, !mcsema_real_eip !5
  %31 = icmp ult i64 %18, 6296176, !mcsema_real_eip !5
  %32 = zext i1 %31 to i8, !mcsema_real_eip !5
  store volatile i8 %32, i8* %CF_write, align 1, !mcsema_real_eip !5
  %33 = and i64 %20, %18, !mcsema_real_eip !5
  %.lobit3 = lshr i64 %33, 63
  %34 = trunc i64 %.lobit3 to i8
  store volatile i8 %34, i8* %OF_write, align 1, !mcsema_real_eip !5
  store volatile i64 %19, i64* %RSI_write, align 8, !mcsema_real_eip !5
  store volatile i64 4195885, i64* %RIP_write, align 8, !mcsema_real_eip !6
  %35 = load i64, i64* %RSI_write, align 8, !mcsema_real_eip !6
  %36 = lshr i64 %35, 2
  %37 = ashr i64 %35, 3
  %38 = load i8, i8* %OF_write, align 1, !mcsema_real_eip !6
  %39 = and i8 %38, 1
  store volatile i8 %39, i8* %OF_write, align 1, !mcsema_real_eip !6
  %.tr = trunc i64 %36 to i8
  %40 = and i8 %.tr, 1
  store volatile i8 %40, i8* %CF_write, align 1, !mcsema_real_eip !6
  %41 = icmp eq i64 %37, 0, !mcsema_real_eip !6
  %42 = zext i1 %41 to i8, !mcsema_real_eip !6
  store volatile i8 %42, i8* %ZF_write, align 1, !mcsema_real_eip !6
  %.lobit4 = lshr i64 %37, 63
  %43 = trunc i64 %.lobit4 to i8
  store volatile i8 %43, i8* %SF_write, align 1, !mcsema_real_eip !6
  %44 = trunc i64 %37 to i8, !mcsema_real_eip !6
  %45 = tail call i8 @llvm.ctpop.i8(i8 %44), !mcsema_real_eip !6
  %46 = and i8 %45, 1
  %47 = xor i8 %46, 1
  store volatile i8 %47, i8* %PF_write, align 1, !mcsema_real_eip !6
  store volatile i8 %47, i8* %PF_write, align 1, !mcsema_real_eip !6
  store volatile i64 %37, i64* %RSI_write, align 8, !mcsema_real_eip !6
  store volatile i64 4195889, i64* %RIP_write, align 8, !mcsema_real_eip !7
  %48 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !7
  store volatile i64 %48, i64* %RBP_write, align 8, !mcsema_real_eip !7
  store volatile i64 4195892, i64* %RIP_write, align 8, !mcsema_real_eip !8
  %49 = load i64, i64* %RSI_write, align 8, !mcsema_real_eip !8
  store volatile i64 %49, i64* %RAX_write, align 8, !mcsema_real_eip !8
  store volatile i64 4195895, i64* %RIP_write, align 8, !mcsema_real_eip !9
  %50 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !9
  %51 = lshr i64 %50, 62, !mcsema_real_eip !9
  %52 = lshr i64 %50, 63
  %53 = load i8, i8* %OF_write, align 1, !mcsema_real_eip !9
  %54 = and i8 %53, 1
  store volatile i8 %54, i8* %OF_write, align 1, !mcsema_real_eip !9
  %.tr5 = trunc i64 %51 to i8
  %55 = and i8 %.tr5, 1
  store volatile i8 %55, i8* %CF_write, align 1, !mcsema_real_eip !9
  %56 = xor i64 %52, 1
  %57 = trunc i64 %56 to i8
  store volatile i8 %57, i8* %ZF_write, align 1, !mcsema_real_eip !9
  store volatile i8 0, i8* %SF_write, align 1, !mcsema_real_eip !9
  %58 = trunc i64 %52 to i8, !mcsema_real_eip !9
  %59 = xor i8 %58, 1
  store volatile i8 %59, i8* %PF_write, align 1, !mcsema_real_eip !9
  store volatile i8 %59, i8* %PF_write, align 1, !mcsema_real_eip !9
  store volatile i64 %52, i64* %RAX_write, align 8, !mcsema_real_eip !9
  store volatile i64 4195899, i64* %RIP_write, align 8, !mcsema_real_eip !10
  %60 = load i64, i64* %RSI_write, align 8, !mcsema_real_eip !10
  %61 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !10
  %62 = add i64 %61, %60, !mcsema_real_eip !10
  %63 = xor i64 %62, %60, !mcsema_real_eip !10
  %64 = xor i64 %63, %61, !mcsema_real_eip !10
  %65 = lshr i64 %64, 4
  %.tr7 = trunc i64 %65 to i8
  %66 = and i8 %.tr7, 1
  store volatile i8 %66, i8* %AF_write, align 1, !mcsema_real_eip !10
  %.lobit8 = lshr i64 %62, 63
  %67 = trunc i64 %.lobit8 to i8
  store volatile i8 %67, i8* %SF_write, align 1, !mcsema_real_eip !10
  %68 = icmp eq i64 %62, 0, !mcsema_real_eip !10
  %69 = zext i1 %68 to i8, !mcsema_real_eip !10
  store volatile i8 %69, i8* %ZF_write, align 1, !mcsema_real_eip !10
  %70 = xor i64 %60, -9223372036854775808, !mcsema_real_eip !10
  %71 = xor i64 %70, %61, !mcsema_real_eip !10
  %72 = and i64 %63, %71, !mcsema_real_eip !10
  %.lobit9 = lshr i64 %72, 63
  %73 = trunc i64 %.lobit9 to i8
  store volatile i8 %73, i8* %OF_write, align 1, !mcsema_real_eip !10
  %74 = trunc i64 %62 to i8, !mcsema_real_eip !10
  %75 = tail call i8 @llvm.ctpop.i8(i8 %74), !mcsema_real_eip !10
  %76 = and i8 %75, 1
  %77 = xor i8 %76, 1
  store volatile i8 %77, i8* %PF_write, align 1, !mcsema_real_eip !10
  %78 = icmp ult i64 %62, %60, !mcsema_real_eip !10
  %79 = zext i1 %78 to i8, !mcsema_real_eip !10
  store volatile i8 %79, i8* %CF_write, align 1, !mcsema_real_eip !10
  store volatile i64 %62, i64* %RSI_write, align 8, !mcsema_real_eip !10
  store volatile i64 4195902, i64* %RIP_write, align 8, !mcsema_real_eip !11
  %80 = load i64, i64* %RSI_write, align 8, !mcsema_real_eip !11
  %81 = ashr i64 %80, 1, !mcsema_real_eip !11
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !11
  %.tr10 = trunc i64 %80 to i8
  %82 = and i8 %.tr10, 1
  store volatile i8 %82, i8* %CF_write, align 1, !mcsema_real_eip !11
  %83 = icmp eq i64 %81, 0, !mcsema_real_eip !11
  %84 = zext i1 %83 to i8, !mcsema_real_eip !11
  store volatile i8 %84, i8* %ZF_write, align 1, !mcsema_real_eip !11
  %.lobit11 = lshr i64 %81, 63
  %85 = trunc i64 %.lobit11 to i8
  store volatile i8 %85, i8* %SF_write, align 1, !mcsema_real_eip !11
  %86 = trunc i64 %81 to i8, !mcsema_real_eip !11
  %87 = tail call i8 @llvm.ctpop.i8(i8 %86), !mcsema_real_eip !11
  %88 = and i8 %87, 1
  %89 = xor i8 %88, 1
  store volatile i8 %89, i8* %PF_write, align 1, !mcsema_real_eip !11
  store volatile i8 %89, i8* %PF_write, align 1, !mcsema_real_eip !11
  store volatile i64 %81, i64* %RSI_write, align 8, !mcsema_real_eip !11
  store volatile i64 4195905, i64* %RIP_write, align 8, !mcsema_real_eip !12
  %90 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !12
  %91 = and i8 %90, 1
  %92 = icmp eq i8 %91, 0
  br i1 %92, label %block_400643, label %block_400658, !mcsema_real_eip !12

block_400643:                                     ; preds = %block_400620
  store volatile i64 4195907, i64* %RIP_write, align 8, !mcsema_real_eip !13
  store volatile i64 0, i64* %RAX_write, align 8, !mcsema_real_eip !13
  store volatile i64 4195912, i64* %RIP_write, align 8, !mcsema_real_eip !14
  %93 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !14
  %94 = icmp eq i64 %93, 0, !mcsema_real_eip !14
  %95 = zext i1 %94 to i8, !mcsema_real_eip !14
  store volatile i8 %95, i8* %ZF_write, align 1, !mcsema_real_eip !14
  %.lobit12 = lshr i64 %93, 63
  %96 = trunc i64 %.lobit12 to i8
  store volatile i8 %96, i8* %SF_write, align 1, !mcsema_real_eip !14
  %97 = trunc i64 %93 to i8, !mcsema_real_eip !14
  %98 = tail call i8 @llvm.ctpop.i8(i8 %97), !mcsema_real_eip !14
  %99 = and i8 %98, 1
  %100 = xor i8 %99, 1
  store volatile i8 %100, i8* %PF_write, align 1, !mcsema_real_eip !14
  store volatile i8 %100, i8* %PF_write, align 1, !mcsema_real_eip !14
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !14
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !14
  store volatile i64 4195915, i64* %RIP_write, align 8, !mcsema_real_eip !15
  %101 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !15
  %102 = and i8 %101, 1
  %103 = icmp eq i8 %102, 0
  br i1 %103, label %block_40064d, label %block_400658, !mcsema_real_eip !15

block_40064d:                                     ; preds = %block_400643
  store volatile i64 4195917, i64* %RIP_write, align 8, !mcsema_real_eip !16
  %104 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !16
  %105 = inttoptr i64 %104 to i64*, !mcsema_real_eip !16
  %106 = load i64, i64* %105, align 8, !mcsema_real_eip !16
  store volatile i64 %106, i64* %RBP_write, align 8, !mcsema_real_eip !16
  %107 = add i64 %104, 8, !mcsema_real_eip !16
  store volatile i64 %107, i64* %RSP_write, align 8, !mcsema_real_eip !16
  store volatile i64 4195918, i64* %RIP_write, align 8, !mcsema_real_eip !17
  store volatile i64 6296176, i64* %RDI_write, align 8, !mcsema_real_eip !17
  store volatile i64 4195923, i64* %RIP_write, align 8, !mcsema_real_eip !18
  %108 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !18
  store volatile i64 %108, i64* %RIP_write, align 8, !mcsema_real_eip !18
  tail call void @__mcsema_detach_call_value(), !mcsema_real_eip !18
  ret void, !mcsema_real_eip !18

block_400658:                                     ; preds = %block_400643, %block_400620
  store volatile i64 4195928, i64* %RIP_write, align 8, !mcsema_real_eip !19
  %109 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !19
  %110 = inttoptr i64 %109 to i64*, !mcsema_real_eip !19
  %111 = load i64, i64* %110, align 8, !mcsema_real_eip !19
  store volatile i64 %111, i64* %RBP_write, align 8, !mcsema_real_eip !19
  %112 = add i64 %109, 8, !mcsema_real_eip !19
  store volatile i64 %112, i64* %RSP_write, align 8, !mcsema_real_eip !19
  store volatile i64 4195929, i64* %RIP_write, align 8, !mcsema_real_eip !20
  %113 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !20
  %114 = add i64 %113, 8, !mcsema_real_eip !20
  %115 = inttoptr i64 %113 to i64*, !mcsema_real_eip !20
  %116 = load i64, i64* %115, align 8, !mcsema_real_eip !20
  store volatile i64 %116, i64* %RIP_write, align 8, !mcsema_real_eip !20
  store volatile i64 %114, i64* %RSP_write, align 8, !mcsema_real_eip !20
  ret void, !mcsema_real_eip !20

block_40068b:                                     ; preds = %entry, %block_400690
  store volatile i64 4195979, i64* %RIP_write, align 8, !mcsema_real_eip !21
  br label %block_400620, !mcsema_real_eip !21

block_400690:                                     ; preds = %entry
  store volatile i64 4195984, i64* %RIP_write, align 8, !mcsema_real_eip !22
  store volatile i64 0, i64* %RAX_write, align 8, !mcsema_real_eip !22
  store volatile i64 4195989, i64* %RIP_write, align 8, !mcsema_real_eip !23
  %117 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !23
  %118 = icmp eq i64 %117, 0, !mcsema_real_eip !23
  %119 = zext i1 %118 to i8, !mcsema_real_eip !23
  store volatile i8 %119, i8* %ZF_write, align 1, !mcsema_real_eip !23
  %.lobit13 = lshr i64 %117, 63
  %120 = trunc i64 %.lobit13 to i8
  store volatile i8 %120, i8* %SF_write, align 1, !mcsema_real_eip !23
  %121 = trunc i64 %117 to i8, !mcsema_real_eip !23
  %122 = tail call i8 @llvm.ctpop.i8(i8 %121), !mcsema_real_eip !23
  %123 = and i8 %122, 1
  %124 = xor i8 %123, 1
  store volatile i8 %124, i8* %PF_write, align 1, !mcsema_real_eip !23
  store volatile i8 %124, i8* %PF_write, align 1, !mcsema_real_eip !23
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !23
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !23
  store volatile i64 4195992, i64* %RIP_write, align 8, !mcsema_real_eip !24
  %125 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !24
  %126 = and i8 %125, 1
  %127 = icmp eq i8 %126, 0
  br i1 %127, label %block_40069a, label %block_40068b, !mcsema_real_eip !24

block_40069a:                                     ; preds = %block_400690
  store volatile i64 4195994, i64* %RIP_write, align 8, !mcsema_real_eip !25
  %128 = load i64, i64* %RBP_write, align 8, !mcsema_real_eip !25
  %129 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !25
  %130 = add i64 %129, -8
  %131 = inttoptr i64 %130 to i64*, !mcsema_real_eip !25
  store i64 %128, i64* %131, align 8, !mcsema_real_eip !25
  store volatile i64 %130, i64* %RSP_write, align 8, !mcsema_real_eip !25
  store volatile i64 4195995, i64* %RIP_write, align 8, !mcsema_real_eip !26
  %132 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !26
  store volatile i64 %132, i64* %RBP_write, align 8, !mcsema_real_eip !26
  store volatile i64 4195998, i64* %RIP_write, align 8, !mcsema_real_eip !27
  %133 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !27
  store volatile i64 %133, i64* %RIP_write, align 8, !mcsema_real_eip !27
  %134 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !27
  %135 = add i64 %134, -8
  %136 = inttoptr i64 %135 to i64*, !mcsema_real_eip !27
  store i64 -2415393069852865332, i64* %136, align 8, !mcsema_real_eip !27
  store volatile i64 %135, i64* %RSP_write, align 8, !mcsema_real_eip !27
  tail call void @__mcsema_detach_call_value(), !mcsema_real_eip !27
  store volatile i64 4196000, i64* %RIP_write, align 8, !mcsema_real_eip !28
  %137 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !28
  %138 = inttoptr i64 %137 to i64*, !mcsema_real_eip !28
  %139 = load i64, i64* %138, align 8, !mcsema_real_eip !28
  store volatile i64 %139, i64* %RBP_write, align 8, !mcsema_real_eip !28
  %140 = add i64 %137, 8, !mcsema_real_eip !28
  store volatile i64 %140, i64* %RSP_write, align 8, !mcsema_real_eip !28
  store volatile i64 4196001, i64* %RIP_write, align 8, !mcsema_real_eip !29
  br label %block_400620, !mcsema_real_eip !29
}

; Function Attrs: noinline
define internal x86_64_sysvcc void @b64d(%RegState*) unnamed_addr #1 {
entry:
  %RIP_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 0, !mcsema_real_eip !30
  %RAX_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 1, !mcsema_real_eip !30
  %EAX_read = bitcast i64* %RAX_write to i32*, !mcsema_real_eip !30
  %AL_write = bitcast i64* %RAX_write to i8*
  %RBX_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 2, !mcsema_real_eip !30
  %RCX_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 3, !mcsema_real_eip !30
  %ECX_read = bitcast i64* %RCX_write to i32*, !mcsema_real_eip !30
  %RDX_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 4, !mcsema_real_eip !30
  %EDX_read = bitcast i64* %RDX_write to i32*, !mcsema_real_eip !30
  %DL_write = bitcast i64* %RDX_write to i8*
  %RSI_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 5, !mcsema_real_eip !30
  %ESI_read = bitcast i64* %RSI_write to i32*, !mcsema_real_eip !30
  %RDI_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 6, !mcsema_real_eip !30
  %DIL_write = bitcast i64* %RDI_write to i8*
  %RSP_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 7, !mcsema_real_eip !30
  %RBP_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 8, !mcsema_real_eip !30
  %R8_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 9, !mcsema_real_eip !30
  %CF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 17, !mcsema_real_eip !30
  %PF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 18, !mcsema_real_eip !30
  %AF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 19, !mcsema_real_eip !30
  %ZF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 20, !mcsema_real_eip !30
  %SF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 21, !mcsema_real_eip !30
  %OF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 22, !mcsema_real_eip !30
  %DF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 23, !mcsema_real_eip !30
  store volatile i64 4196006, i64* %RIP_write, align 8, !mcsema_real_eip !30
  %1 = load i64, i64* %RBP_write, align 8, !mcsema_real_eip !30
  %2 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !30
  %3 = add i64 %2, -8
  %4 = inttoptr i64 %3 to i64*, !mcsema_real_eip !30
  store i64 %1, i64* %4, align 8, !mcsema_real_eip !30
  store volatile i64 %3, i64* %RSP_write, align 8, !mcsema_real_eip !30
  store volatile i64 4196007, i64* %RIP_write, align 8, !mcsema_real_eip !31
  %5 = load i64, i64* %RBX_write, align 8, !mcsema_real_eip !31
  %6 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !31
  %7 = add i64 %6, -8
  %8 = inttoptr i64 %7 to i64*, !mcsema_real_eip !31
  store i64 %5, i64* %8, align 8, !mcsema_real_eip !31
  store volatile i64 %7, i64* %RSP_write, align 8, !mcsema_real_eip !31
  store volatile i64 4196008, i64* %RIP_write, align 8, !mcsema_real_eip !32
  %9 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !32
  %10 = add i64 %9, -200
  %11 = xor i64 %10, %9, !mcsema_real_eip !32
  %12 = lshr i64 %11, 4
  %.tr = trunc i64 %12 to i8
  %13 = and i8 %.tr, 1
  store volatile i8 %13, i8* %AF_write, align 1, !mcsema_real_eip !32
  %14 = trunc i64 %10 to i8, !mcsema_real_eip !32
  %15 = tail call i8 @llvm.ctpop.i8(i8 %14), !mcsema_real_eip !32
  %16 = and i8 %15, 1
  %17 = xor i8 %16, 1
  store volatile i8 %17, i8* %PF_write, align 1, !mcsema_real_eip !32
  %18 = icmp eq i64 %10, 0, !mcsema_real_eip !32
  %19 = zext i1 %18 to i8, !mcsema_real_eip !32
  store volatile i8 %19, i8* %ZF_write, align 1, !mcsema_real_eip !32
  %.lobit = lshr i64 %10, 63
  %20 = trunc i64 %.lobit to i8
  store volatile i8 %20, i8* %SF_write, align 1, !mcsema_real_eip !32
  %21 = icmp ult i64 %9, 200, !mcsema_real_eip !32
  %22 = zext i1 %21 to i8, !mcsema_real_eip !32
  store volatile i8 %22, i8* %CF_write, align 1, !mcsema_real_eip !32
  %23 = and i64 %11, %9, !mcsema_real_eip !32
  %.lobit1 = lshr i64 %23, 63
  %24 = trunc i64 %.lobit1 to i8
  store volatile i8 %24, i8* %OF_write, align 1, !mcsema_real_eip !32
  store volatile i64 %10, i64* %RSP_write, align 8, !mcsema_real_eip !32
  store volatile i64 4196015, i64* %RIP_write, align 8, !mcsema_real_eip !33
  %25 = load i64, i64* %RDI_write, align 8, !mcsema_real_eip !33
  store volatile i64 %25, i64* %R8_write, align 8, !mcsema_real_eip !33
  store volatile i64 4196018, i64* %RIP_write, align 8, !mcsema_real_eip !34
  %26 = load i64, i64* %RSI_write, align 8, !mcsema_real_eip !34
  store volatile i64 %26, i64* %RBP_write, align 8, !mcsema_real_eip !34
  store volatile i64 4196021, i64* %RIP_write, align 8, !mcsema_real_eip !35
  %27 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !35
  store volatile i64 %27, i64* %RDI_write, align 8, !mcsema_real_eip !35
  store volatile i64 4196024, i64* %RIP_write, align 8, !mcsema_real_eip !36
  store volatile i64 24, i64* %RCX_write, align 8, !mcsema_real_eip !36
  store volatile i64 4196029, i64* %RIP_write, align 8, !mcsema_real_eip !37
  store volatile i64 0, i64* %RAX_write, align 8, !mcsema_real_eip !37
  store volatile i64 4196034, i64* %RIP_write, align 8, !mcsema_real_eip !38
  %28 = load i64, i64* %RCX_write, align 8, !mcsema_real_eip !38
  %29 = icmp eq i64 %28, 0, !mcsema_real_eip !38
  br i1 %29, label %.loopexit, label %.preheader.preheader, !mcsema_real_eip !38

.preheader.preheader:                             ; preds = %entry
  br label %.preheader

block_4006d1:                                     ; preds = %block_400712
  store volatile i64 4196049, i64* %RIP_write, align 8, !mcsema_real_eip !39
  %30 = load i32, i32* %EAX_read, align 4, !mcsema_real_eip !39
  %31 = shl i32 %30, 6
  %32 = load i8, i8* %OF_write, align 1, !mcsema_real_eip !39
  %33 = and i8 %32, 1
  store volatile i8 %33, i8* %OF_write, align 1, !mcsema_real_eip !39
  %34 = lshr i32 %30, 26
  %.tr36 = trunc i32 %34 to i8
  %35 = and i8 %.tr36, 1
  store volatile i8 %35, i8* %CF_write, align 1, !mcsema_real_eip !39
  %36 = icmp eq i32 %31, 0, !mcsema_real_eip !39
  %37 = zext i1 %36 to i8, !mcsema_real_eip !39
  store volatile i8 %37, i8* %ZF_write, align 1, !mcsema_real_eip !39
  %38 = lshr i32 %30, 25
  %.tr38 = trunc i32 %38 to i8
  %39 = and i8 %.tr38, 1
  store volatile i8 %39, i8* %SF_write, align 1, !mcsema_real_eip !39
  %40 = trunc i32 %31 to i8, !mcsema_real_eip !39
  %41 = tail call i8 @llvm.ctpop.i8(i8 %40), !mcsema_real_eip !39
  %42 = and i8 %41, 1
  %43 = xor i8 %42, 1
  store volatile i8 %43, i8* %PF_write, align 1, !mcsema_real_eip !39
  store volatile i8 %43, i8* %PF_write, align 1, !mcsema_real_eip !39
  %44 = zext i32 %31 to i64, !mcsema_real_eip !39
  store volatile i64 %44, i64* %RAX_write, align 8, !mcsema_real_eip !39
  store volatile i64 4196052, i64* %RIP_write, align 8, !mcsema_real_eip !40
  %45 = load i8, i8* %DL_write, align 1, !mcsema_real_eip !40
  %46 = zext i8 %45 to i64
  store volatile i64 %46, i64* %RDX_write, align 8, !mcsema_real_eip !40
  store volatile i64 4196055, i64* %RIP_write, align 8, !mcsema_real_eip !41
  %47 = load i32, i32* %EAX_read, align 4, !mcsema_real_eip !41
  %48 = load i32, i32* %EDX_read, align 4, !mcsema_real_eip !41
  %49 = or i32 %48, %47, !mcsema_real_eip !41
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !41
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !41
  %.lobit39 = lshr i32 %49, 31
  %50 = trunc i32 %.lobit39 to i8
  store volatile i8 %50, i8* %SF_write, align 1, !mcsema_real_eip !41
  %51 = icmp eq i32 %49, 0, !mcsema_real_eip !41
  %52 = zext i1 %51 to i8, !mcsema_real_eip !41
  store volatile i8 %52, i8* %ZF_write, align 1, !mcsema_real_eip !41
  %53 = trunc i32 %49 to i8, !mcsema_real_eip !41
  %54 = tail call i8 @llvm.ctpop.i8(i8 %53), !mcsema_real_eip !41
  %55 = and i8 %54, 1
  %56 = xor i8 %55, 1
  store volatile i8 %56, i8* %PF_write, align 1, !mcsema_real_eip !41
  %57 = zext i32 %49 to i64, !mcsema_real_eip !41
  store volatile i64 %57, i64* %RAX_write, align 8, !mcsema_real_eip !41
  store volatile i64 4196057, i64* %RIP_write, align 8, !mcsema_real_eip !42
  %58 = load i64, i64* %RSI_write, align 8, !mcsema_real_eip !42
  %59 = add i64 %58, -2
  %60 = xor i64 %59, %58, !mcsema_real_eip !42
  %61 = lshr i64 %60, 4
  %.tr41 = trunc i64 %61 to i8
  %62 = and i8 %.tr41, 1
  store volatile i8 %62, i8* %AF_write, align 1, !mcsema_real_eip !42
  %63 = trunc i64 %59 to i8, !mcsema_real_eip !42
  %64 = tail call i8 @llvm.ctpop.i8(i8 %63), !mcsema_real_eip !42
  %65 = and i8 %64, 1
  %66 = xor i8 %65, 1
  store volatile i8 %66, i8* %PF_write, align 1, !mcsema_real_eip !42
  %67 = icmp eq i64 %59, 0, !mcsema_real_eip !42
  %68 = zext i1 %67 to i8, !mcsema_real_eip !42
  store volatile i8 %68, i8* %ZF_write, align 1, !mcsema_real_eip !42
  %.lobit42 = lshr i64 %59, 63
  %69 = trunc i64 %.lobit42 to i8
  store volatile i8 %69, i8* %SF_write, align 1, !mcsema_real_eip !42
  %70 = icmp ult i64 %58, 2, !mcsema_real_eip !42
  %71 = zext i1 %70 to i8, !mcsema_real_eip !42
  store volatile i8 %71, i8* %CF_write, align 1, !mcsema_real_eip !42
  %72 = and i64 %60, %58, !mcsema_real_eip !42
  %.lobit43 = lshr i64 %72, 63
  %73 = trunc i64 %.lobit43 to i8
  store volatile i8 %73, i8* %OF_write, align 1, !mcsema_real_eip !42
  store volatile i64 4196061, i64* %RIP_write, align 8, !mcsema_real_eip !43
  %74 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !43
  %75 = load i8, i8* %CF_write, align 1, !mcsema_real_eip !43
  %76 = or i8 %75, %74
  %77 = and i8 %76, 1
  %78 = icmp eq i8 %77, 0
  br i1 %78, label %block_4006e5, label %block_4006df, !mcsema_real_eip !43

block_4006df:                                     ; preds = %block_4006d1
  store volatile i64 4196063, i64* %RIP_write, align 8, !mcsema_real_eip !44
  %79 = load i64, i64* %RSI_write, align 8, !mcsema_real_eip !44
  %80 = add i64 %79, 1, !mcsema_real_eip !44
  %81 = xor i64 %80, %79, !mcsema_real_eip !44
  %82 = lshr i64 %81, 4
  %.tr45 = trunc i64 %82 to i8
  %83 = and i8 %.tr45, 1
  store volatile i8 %83, i8* %AF_write, align 1, !mcsema_real_eip !44
  %.lobit46 = lshr i64 %80, 63
  %84 = trunc i64 %.lobit46 to i8
  store volatile i8 %84, i8* %SF_write, align 1, !mcsema_real_eip !44
  %85 = icmp eq i64 %80, 0, !mcsema_real_eip !44
  %86 = zext i1 %85 to i8, !mcsema_real_eip !44
  store volatile i8 %86, i8* %ZF_write, align 1, !mcsema_real_eip !44
  %87 = xor i64 %79, -9223372036854775808, !mcsema_real_eip !44
  %88 = and i64 %81, %87, !mcsema_real_eip !44
  %.lobit47 = lshr i64 %88, 63
  %89 = trunc i64 %.lobit47 to i8
  store volatile i8 %89, i8* %OF_write, align 1, !mcsema_real_eip !44
  %90 = trunc i64 %80 to i8, !mcsema_real_eip !44
  %91 = tail call i8 @llvm.ctpop.i8(i8 %90), !mcsema_real_eip !44
  %92 = and i8 %91, 1
  %93 = xor i8 %92, 1
  store volatile i8 %93, i8* %PF_write, align 1, !mcsema_real_eip !44
  %94 = icmp eq i64 %79, -1
  %95 = zext i1 %94 to i8, !mcsema_real_eip !44
  store volatile i8 %95, i8* %CF_write, align 1, !mcsema_real_eip !44
  store volatile i64 %80, i64* %RSI_write, align 8, !mcsema_real_eip !44
  store volatile i64 4196067, i64* %RIP_write, align 8, !mcsema_real_eip !45
  br label %block_400712.backedge, !mcsema_real_eip !45

block_400712.backedge:                            ; preds = %block_4006df, %block_4006e5
  br label %block_400712

block_4006e5:                                     ; preds = %block_4006d1
  store volatile i64 4196069, i64* %RIP_write, align 8, !mcsema_real_eip !46
  %96 = load i32, i32* %EAX_read, align 4, !mcsema_real_eip !46
  %97 = zext i32 %96 to i64, !mcsema_real_eip !46
  store volatile i64 %97, i64* %RDX_write, align 8, !mcsema_real_eip !46
  store volatile i64 4196071, i64* %RIP_write, align 8, !mcsema_real_eip !47
  %98 = load i32, i32* %EDX_read, align 4, !mcsema_real_eip !47
  %99 = and i32 %98, 16711680, !mcsema_real_eip !47
  store volatile i8 0, i8* %SF_write, align 1, !mcsema_real_eip !47
  %100 = icmp eq i32 %99, 0, !mcsema_real_eip !47
  %101 = zext i1 %100 to i8, !mcsema_real_eip !47
  store volatile i8 %101, i8* %ZF_write, align 1, !mcsema_real_eip !47
  store volatile i8 1, i8* %PF_write, align 1, !mcsema_real_eip !47
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !47
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !47
  %102 = zext i32 %99 to i64, !mcsema_real_eip !47
  store volatile i64 %102, i64* %RDX_write, align 8, !mcsema_real_eip !47
  store volatile i64 4196077, i64* %RIP_write, align 8, !mcsema_real_eip !48
  %103 = load i32, i32* %EDX_read, align 4, !mcsema_real_eip !48
  %104 = zext i32 %103 to i64, !mcsema_real_eip !48
  store volatile i64 %104, i64* %RSI_write, align 8, !mcsema_real_eip !48
  store volatile i64 4196079, i64* %RIP_write, align 8, !mcsema_real_eip !49
  %105 = load i32, i32* %ESI_read, align 4, !mcsema_real_eip !49
  %106 = lshr i32 %105, 15, !mcsema_real_eip !49
  %107 = lshr i32 %105, 16
  %108 = load i8, i8* %OF_write, align 1, !mcsema_real_eip !49
  %109 = and i8 %108, 1
  store volatile i8 %109, i8* %OF_write, align 1, !mcsema_real_eip !49
  %.tr48 = trunc i32 %106 to i8
  %110 = and i8 %.tr48, 1
  store volatile i8 %110, i8* %CF_write, align 1, !mcsema_real_eip !49
  %111 = icmp eq i32 %107, 0, !mcsema_real_eip !49
  %112 = zext i1 %111 to i8, !mcsema_real_eip !49
  store volatile i8 %112, i8* %ZF_write, align 1, !mcsema_real_eip !49
  store volatile i8 0, i8* %SF_write, align 1, !mcsema_real_eip !49
  %113 = trunc i32 %107 to i8, !mcsema_real_eip !49
  %114 = tail call i8 @llvm.ctpop.i8(i8 %113), !mcsema_real_eip !49
  %115 = and i8 %114, 1
  %116 = xor i8 %115, 1
  store volatile i8 %116, i8* %PF_write, align 1, !mcsema_real_eip !49
  store volatile i8 %116, i8* %PF_write, align 1, !mcsema_real_eip !49
  %117 = zext i32 %107 to i64, !mcsema_real_eip !49
  store volatile i64 %117, i64* %RSI_write, align 8, !mcsema_real_eip !49
  store volatile i64 4196082, i64* %RIP_write, align 8, !mcsema_real_eip !50
  %118 = load i8, i8* %AL_write, align 1, !mcsema_real_eip !50
  %119 = zext i8 %118 to i64
  store volatile i64 %119, i64* %RDX_write, align 8, !mcsema_real_eip !50
  store volatile i64 4196085, i64* %RIP_write, align 8, !mcsema_real_eip !51
  %120 = load i32, i32* %EDX_read, align 4, !mcsema_real_eip !51
  %121 = shl i32 %120, 16
  %122 = load i8, i8* %OF_write, align 1, !mcsema_real_eip !51
  %123 = and i8 %122, 1
  store volatile i8 %123, i8* %OF_write, align 1, !mcsema_real_eip !51
  %124 = lshr i32 %120, 16
  %.tr50 = trunc i32 %124 to i8
  %125 = and i8 %.tr50, 1
  store volatile i8 %125, i8* %CF_write, align 1, !mcsema_real_eip !51
  %126 = icmp eq i32 %121, 0, !mcsema_real_eip !51
  %127 = zext i1 %126 to i8, !mcsema_real_eip !51
  store volatile i8 %127, i8* %ZF_write, align 1, !mcsema_real_eip !51
  %128 = lshr i32 %120, 15
  %.tr52 = trunc i32 %128 to i8
  %129 = and i8 %.tr52, 1
  store volatile i8 %129, i8* %SF_write, align 1, !mcsema_real_eip !51
  store volatile i8 1, i8* %PF_write, align 1, !mcsema_real_eip !51
  store volatile i8 1, i8* %PF_write, align 1, !mcsema_real_eip !51
  %130 = zext i32 %121 to i64, !mcsema_real_eip !51
  store volatile i64 %130, i64* %RDX_write, align 8, !mcsema_real_eip !51
  store volatile i64 4196088, i64* %RIP_write, align 8, !mcsema_real_eip !52
  %131 = load i32, i32* %EDX_read, align 4, !mcsema_real_eip !52
  %132 = load i32, i32* %ESI_read, align 4, !mcsema_real_eip !52
  %133 = or i32 %132, %131, !mcsema_real_eip !52
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !52
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !52
  %.lobit53 = lshr i32 %133, 31
  %134 = trunc i32 %.lobit53 to i8
  store volatile i8 %134, i8* %SF_write, align 1, !mcsema_real_eip !52
  %135 = icmp eq i32 %133, 0, !mcsema_real_eip !52
  %136 = zext i1 %135 to i8, !mcsema_real_eip !52
  store volatile i8 %136, i8* %ZF_write, align 1, !mcsema_real_eip !52
  %137 = trunc i32 %133 to i8, !mcsema_real_eip !52
  %138 = tail call i8 @llvm.ctpop.i8(i8 %137), !mcsema_real_eip !52
  %139 = and i8 %138, 1
  %140 = xor i8 %139, 1
  store volatile i8 %140, i8* %PF_write, align 1, !mcsema_real_eip !52
  %141 = zext i32 %133 to i64, !mcsema_real_eip !52
  store volatile i64 %141, i64* %RDX_write, align 8, !mcsema_real_eip !52
  store volatile i64 4196090, i64* %RIP_write, align 8, !mcsema_real_eip !53
  %142 = load i32, i32* %EAX_read, align 4, !mcsema_real_eip !53
  %143 = and i32 %142, 65280, !mcsema_real_eip !53
  store volatile i8 0, i8* %SF_write, align 1, !mcsema_real_eip !53
  %144 = icmp eq i32 %143, 0, !mcsema_real_eip !53
  %145 = zext i1 %144 to i8, !mcsema_real_eip !53
  store volatile i8 %145, i8* %ZF_write, align 1, !mcsema_real_eip !53
  store volatile i8 1, i8* %PF_write, align 1, !mcsema_real_eip !53
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !53
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !53
  %146 = zext i32 %143 to i64, !mcsema_real_eip !53
  store volatile i64 %146, i64* %RAX_write, align 8, !mcsema_real_eip !53
  store volatile i64 4196095, i64* %RIP_write, align 8, !mcsema_real_eip !54
  %147 = load i32, i32* %EAX_read, align 4, !mcsema_real_eip !54
  %148 = load i32, i32* %EDX_read, align 4, !mcsema_real_eip !54
  %149 = or i32 %148, %147, !mcsema_real_eip !54
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !54
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !54
  %.lobit54 = lshr i32 %149, 31
  %150 = trunc i32 %.lobit54 to i8
  store volatile i8 %150, i8* %SF_write, align 1, !mcsema_real_eip !54
  %151 = icmp eq i32 %149, 0, !mcsema_real_eip !54
  %152 = zext i1 %151 to i8, !mcsema_real_eip !54
  store volatile i8 %152, i8* %ZF_write, align 1, !mcsema_real_eip !54
  %153 = trunc i32 %149 to i8, !mcsema_real_eip !54
  %154 = tail call i8 @llvm.ctpop.i8(i8 %153), !mcsema_real_eip !54
  %155 = and i8 %154, 1
  %156 = xor i8 %155, 1
  store volatile i8 %156, i8* %PF_write, align 1, !mcsema_real_eip !54
  %157 = zext i32 %149 to i64, !mcsema_real_eip !54
  store volatile i64 %157, i64* %RAX_write, align 8, !mcsema_real_eip !54
  store volatile i64 4196097, i64* %RIP_write, align 8, !mcsema_real_eip !55
  %158 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !55
  %159 = load i64, i64* %RBX_write, align 8, !mcsema_real_eip !55
  %160 = add i64 %159, %158, !mcsema_real_eip !55
  %161 = load i32, i32* %EAX_read, align 4, !mcsema_real_eip !55
  %162 = inttoptr i64 %160 to i32*, !mcsema_real_eip !55
  store i32 %161, i32* %162, align 4, !mcsema_real_eip !55
  store volatile i64 4196100, i64* %RIP_write, align 8, !mcsema_real_eip !56
  %163 = load i64, i64* %RBX_write, align 8, !mcsema_real_eip !56
  %164 = add i64 %163, 3, !mcsema_real_eip !56
  %165 = xor i64 %164, %163, !mcsema_real_eip !56
  %166 = lshr i64 %165, 4
  %.tr56 = trunc i64 %166 to i8
  %167 = and i8 %.tr56, 1
  store volatile i8 %167, i8* %AF_write, align 1, !mcsema_real_eip !56
  %.lobit57 = lshr i64 %164, 63
  %168 = trunc i64 %.lobit57 to i8
  store volatile i8 %168, i8* %SF_write, align 1, !mcsema_real_eip !56
  %169 = icmp eq i64 %164, 0, !mcsema_real_eip !56
  %170 = zext i1 %169 to i8, !mcsema_real_eip !56
  store volatile i8 %170, i8* %ZF_write, align 1, !mcsema_real_eip !56
  %171 = xor i64 %163, -9223372036854775808, !mcsema_real_eip !56
  %172 = and i64 %165, %171, !mcsema_real_eip !56
  %.lobit58 = lshr i64 %172, 63
  %173 = trunc i64 %.lobit58 to i8
  store volatile i8 %173, i8* %OF_write, align 1, !mcsema_real_eip !56
  %174 = trunc i64 %164 to i8, !mcsema_real_eip !56
  %175 = tail call i8 @llvm.ctpop.i8(i8 %174), !mcsema_real_eip !56
  %176 = and i8 %175, 1
  %177 = xor i8 %176, 1
  store volatile i8 %177, i8* %PF_write, align 1, !mcsema_real_eip !56
  %178 = icmp ugt i64 %163, -4
  %179 = zext i1 %178 to i8, !mcsema_real_eip !56
  store volatile i8 %179, i8* %CF_write, align 1, !mcsema_real_eip !56
  store volatile i64 %164, i64* %RBX_write, align 8, !mcsema_real_eip !56
  store volatile i64 4196104, i64* %RIP_write, align 8, !mcsema_real_eip !57
  store volatile i64 0, i64* %RAX_write, align 8, !mcsema_real_eip !57
  store volatile i64 4196109, i64* %RIP_write, align 8, !mcsema_real_eip !58
  store volatile i64 0, i64* %RSI_write, align 8, !mcsema_real_eip !58
  br label %block_400712.backedge, !mcsema_real_eip !59

block_400712:                                     ; preds = %block_400712.backedge, %.loopexit
  store volatile i64 4196114, i64* %RIP_write, align 8, !mcsema_real_eip !59
  %180 = load i64, i64* %RCX_write, align 8, !mcsema_real_eip !59
  %181 = add i64 %180, 1, !mcsema_real_eip !59
  %182 = xor i64 %181, %180, !mcsema_real_eip !59
  %183 = lshr i64 %182, 4
  %.tr3 = trunc i64 %183 to i8
  %184 = and i8 %.tr3, 1
  store volatile i8 %184, i8* %AF_write, align 1, !mcsema_real_eip !59
  %.lobit4 = lshr i64 %181, 63
  %185 = trunc i64 %.lobit4 to i8
  store volatile i8 %185, i8* %SF_write, align 1, !mcsema_real_eip !59
  %186 = icmp eq i64 %181, 0, !mcsema_real_eip !59
  %187 = zext i1 %186 to i8, !mcsema_real_eip !59
  store volatile i8 %187, i8* %ZF_write, align 1, !mcsema_real_eip !59
  %188 = xor i64 %180, -9223372036854775808, !mcsema_real_eip !59
  %189 = and i64 %182, %188, !mcsema_real_eip !59
  %.lobit5 = lshr i64 %189, 63
  %190 = trunc i64 %.lobit5 to i8
  store volatile i8 %190, i8* %OF_write, align 1, !mcsema_real_eip !59
  %191 = trunc i64 %181 to i8, !mcsema_real_eip !59
  %192 = tail call i8 @llvm.ctpop.i8(i8 %191), !mcsema_real_eip !59
  %193 = and i8 %192, 1
  %194 = xor i8 %193, 1
  store volatile i8 %194, i8* %PF_write, align 1, !mcsema_real_eip !59
  %195 = icmp eq i64 %180, -1
  %196 = zext i1 %195 to i8, !mcsema_real_eip !59
  store volatile i8 %196, i8* %CF_write, align 1, !mcsema_real_eip !59
  store volatile i64 %181, i64* %RCX_write, align 8, !mcsema_real_eip !59
  store volatile i64 4196118, i64* %RIP_write, align 8, !mcsema_real_eip !60
  %197 = load i64, i64* %R8_write, align 8, !mcsema_real_eip !60
  %198 = add i64 %197, -1, !mcsema_real_eip !60
  %199 = load i64, i64* %RCX_write, align 8, !mcsema_real_eip !60
  %200 = add i64 %198, %199, !mcsema_real_eip !60
  %201 = inttoptr i64 %200 to i8*, !mcsema_real_eip !60
  %202 = load i8, i8* %201, align 1, !mcsema_real_eip !60
  %203 = zext i8 %202 to i64
  store volatile i64 %203, i64* %RDI_write, align 8, !mcsema_real_eip !60
  store volatile i64 4196124, i64* %RIP_write, align 8, !mcsema_real_eip !61
  %204 = load i8, i8* %DIL_write, align 1, !mcsema_real_eip !61
  %205 = zext i8 %204 to i64
  store volatile i64 %205, i64* %RDX_write, align 8, !mcsema_real_eip !61
  store volatile i64 4196128, i64* %RIP_write, align 8, !mcsema_real_eip !62
  %206 = load i64, i64* %RDX_write, align 8, !mcsema_real_eip !62
  %207 = add i64 %206, add (i64 ptrtoint (%0* @data_4009a0 to i64), i64 352), !mcsema_real_eip !62
  %208 = inttoptr i64 %207 to i8*, !mcsema_real_eip !62
  %209 = load i8, i8* %208, align 1, !mcsema_real_eip !62
  %210 = zext i8 %209 to i64
  store volatile i64 %210, i64* %RDX_write, align 8, !mcsema_real_eip !62
  store volatile i64 4196135, i64* %RIP_write, align 8, !mcsema_real_eip !63
  %211 = load i8, i8* %DL_write, align 1, !mcsema_real_eip !63
  %212 = add i8 %211, 1
  %213 = xor i8 %212, %211, !mcsema_real_eip !63
  %214 = lshr i8 %213, 4
  %.lobit6 = and i8 %214, 1
  %215 = xor i8 %.lobit6, 1
  store volatile i8 %215, i8* %AF_write, align 1, !mcsema_real_eip !63
  %216 = tail call i8 @llvm.ctpop.i8(i8 %212), !mcsema_real_eip !63
  %217 = and i8 %216, 1
  %218 = xor i8 %217, 1
  store volatile i8 %218, i8* %PF_write, align 1, !mcsema_real_eip !63
  %219 = icmp eq i8 %212, 0, !mcsema_real_eip !63
  %220 = zext i1 %219 to i8, !mcsema_real_eip !63
  store volatile i8 %220, i8* %ZF_write, align 1, !mcsema_real_eip !63
  %.lobit7 = lshr i8 %212, 7
  store volatile i8 %.lobit7, i8* %SF_write, align 1, !mcsema_real_eip !63
  %221 = icmp ne i8 %211, -1
  %222 = zext i1 %221 to i8, !mcsema_real_eip !63
  store volatile i8 %222, i8* %CF_write, align 1, !mcsema_real_eip !63
  %223 = xor i8 %211, -128, !mcsema_real_eip !63
  %224 = and i8 %213, %223, !mcsema_real_eip !63
  %.lobit8 = lshr i8 %224, 7
  store volatile i8 %.lobit8, i8* %OF_write, align 1, !mcsema_real_eip !63
  store volatile i64 4196138, i64* %RIP_write, align 8, !mcsema_real_eip !64
  %225 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !64
  %226 = and i8 %225, 1
  %227 = icmp eq i8 %226, 0
  br i1 %227, label %block_4006d1, label %block_40072c, !mcsema_real_eip !64

block_40072c:                                     ; preds = %block_400712
  store volatile i64 4196140, i64* %RIP_write, align 8, !mcsema_real_eip !65
  %228 = load i8, i8* %DIL_write, align 1, !mcsema_real_eip !65
  %229 = add i8 %228, -61
  %230 = xor i8 %229, %228, !mcsema_real_eip !65
  %231 = lshr i8 %230, 4
  %.lobit9 = and i8 %231, 1
  %232 = xor i8 %.lobit9, 1
  store volatile i8 %232, i8* %AF_write, align 1, !mcsema_real_eip !65
  %233 = tail call i8 @llvm.ctpop.i8(i8 %229), !mcsema_real_eip !65
  %234 = and i8 %233, 1
  %235 = xor i8 %234, 1
  store volatile i8 %235, i8* %PF_write, align 1, !mcsema_real_eip !65
  %236 = icmp eq i8 %229, 0, !mcsema_real_eip !65
  %237 = zext i1 %236 to i8, !mcsema_real_eip !65
  store volatile i8 %237, i8* %ZF_write, align 1, !mcsema_real_eip !65
  %.lobit10 = lshr i8 %229, 7
  store volatile i8 %.lobit10, i8* %SF_write, align 1, !mcsema_real_eip !65
  %238 = icmp ult i8 %228, 61, !mcsema_real_eip !65
  %239 = zext i1 %238 to i8, !mcsema_real_eip !65
  store volatile i8 %239, i8* %CF_write, align 1, !mcsema_real_eip !65
  %240 = and i8 %230, %228, !mcsema_real_eip !65
  %.lobit11 = lshr i8 %240, 7
  store volatile i8 %.lobit11, i8* %OF_write, align 1, !mcsema_real_eip !65
  store volatile i64 4196144, i64* %RIP_write, align 8, !mcsema_real_eip !66
  %241 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !66
  %242 = and i8 %241, 1
  %243 = icmp eq i8 %242, 0
  br i1 %243, label %block_400769, label %block_400732, !mcsema_real_eip !66

block_400732:                                     ; preds = %block_40072c
  store volatile i64 4196146, i64* %RIP_write, align 8, !mcsema_real_eip !67
  %244 = load i32, i32* %EAX_read, align 4, !mcsema_real_eip !67
  %245 = shl i32 %244, 6
  %246 = load i8, i8* %OF_write, align 1, !mcsema_real_eip !67
  %247 = and i8 %246, 1
  store volatile i8 %247, i8* %OF_write, align 1, !mcsema_real_eip !67
  %248 = lshr i32 %244, 26
  %.tr13 = trunc i32 %248 to i8
  %249 = and i8 %.tr13, 1
  store volatile i8 %249, i8* %CF_write, align 1, !mcsema_real_eip !67
  %250 = icmp eq i32 %245, 0, !mcsema_real_eip !67
  %251 = zext i1 %250 to i8, !mcsema_real_eip !67
  store volatile i8 %251, i8* %ZF_write, align 1, !mcsema_real_eip !67
  %252 = lshr i32 %244, 25
  %.tr15 = trunc i32 %252 to i8
  %253 = and i8 %.tr15, 1
  store volatile i8 %253, i8* %SF_write, align 1, !mcsema_real_eip !67
  %254 = trunc i32 %245 to i8, !mcsema_real_eip !67
  %255 = tail call i8 @llvm.ctpop.i8(i8 %254), !mcsema_real_eip !67
  %256 = and i8 %255, 1
  %257 = xor i8 %256, 1
  store volatile i8 %257, i8* %PF_write, align 1, !mcsema_real_eip !67
  store volatile i8 %257, i8* %PF_write, align 1, !mcsema_real_eip !67
  %258 = zext i32 %245 to i64, !mcsema_real_eip !67
  store volatile i64 %258, i64* %RAX_write, align 8, !mcsema_real_eip !67
  store volatile i64 4196149, i64* %RIP_write, align 8, !mcsema_real_eip !68
  %259 = load i64, i64* %RBX_write, align 8, !mcsema_real_eip !68
  %260 = add i64 %259, 2, !mcsema_real_eip !68
  store volatile i64 %260, i64* %RSI_write, align 8, !mcsema_real_eip !68
  store volatile i64 4196153, i64* %RIP_write, align 8, !mcsema_real_eip !69
  %261 = load i64, i64* %R8_write, align 8, !mcsema_real_eip !69
  %262 = load i64, i64* %RCX_write, align 8, !mcsema_real_eip !69
  %263 = add i64 %262, %261, !mcsema_real_eip !69
  %264 = inttoptr i64 %263 to i8*, !mcsema_real_eip !69
  %265 = load i8, i8* %264, align 1, !mcsema_real_eip !69
  %266 = add i8 %265, -61
  %267 = xor i8 %266, %265, !mcsema_real_eip !69
  %268 = lshr i8 %267, 4
  %.lobit16 = and i8 %268, 1
  %269 = xor i8 %.lobit16, 1
  store volatile i8 %269, i8* %AF_write, align 1, !mcsema_real_eip !69
  %270 = tail call i8 @llvm.ctpop.i8(i8 %266), !mcsema_real_eip !69
  %271 = and i8 %270, 1
  %272 = xor i8 %271, 1
  store volatile i8 %272, i8* %PF_write, align 1, !mcsema_real_eip !69
  %273 = icmp eq i8 %266, 0, !mcsema_real_eip !69
  %274 = zext i1 %273 to i8, !mcsema_real_eip !69
  store volatile i8 %274, i8* %ZF_write, align 1, !mcsema_real_eip !69
  %.lobit17 = lshr i8 %266, 7
  store volatile i8 %.lobit17, i8* %SF_write, align 1, !mcsema_real_eip !69
  %275 = icmp ult i8 %265, 61, !mcsema_real_eip !69
  %276 = zext i1 %275 to i8, !mcsema_real_eip !69
  store volatile i8 %276, i8* %CF_write, align 1, !mcsema_real_eip !69
  %277 = and i8 %267, %265, !mcsema_real_eip !69
  %.lobit18 = lshr i8 %277, 7
  store volatile i8 %.lobit18, i8* %OF_write, align 1, !mcsema_real_eip !69
  store volatile i64 4196158, i64* %RIP_write, align 8, !mcsema_real_eip !70
  %278 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !70
  %279 = and i8 %278, 1
  %280 = icmp eq i8 %279, 0
  br i1 %280, label %block_400747, label %block_400740, !mcsema_real_eip !70

block_400740:                                     ; preds = %block_400732
  store volatile i64 4196160, i64* %RIP_write, align 8, !mcsema_real_eip !71
  %281 = load i32, i32* %EAX_read, align 4, !mcsema_real_eip !71
  %282 = shl i32 %281, 6
  %283 = load i8, i8* %OF_write, align 1, !mcsema_real_eip !71
  %284 = and i8 %283, 1
  store volatile i8 %284, i8* %OF_write, align 1, !mcsema_real_eip !71
  %285 = lshr i32 %281, 26
  %.tr20 = trunc i32 %285 to i8
  %286 = and i8 %.tr20, 1
  store volatile i8 %286, i8* %CF_write, align 1, !mcsema_real_eip !71
  %287 = icmp eq i32 %282, 0, !mcsema_real_eip !71
  %288 = zext i1 %287 to i8, !mcsema_real_eip !71
  store volatile i8 %288, i8* %ZF_write, align 1, !mcsema_real_eip !71
  %289 = lshr i32 %281, 25
  %.tr22 = trunc i32 %289 to i8
  %290 = and i8 %.tr22, 1
  store volatile i8 %290, i8* %SF_write, align 1, !mcsema_real_eip !71
  %291 = trunc i32 %282 to i8, !mcsema_real_eip !71
  %292 = tail call i8 @llvm.ctpop.i8(i8 %291), !mcsema_real_eip !71
  %293 = and i8 %292, 1
  %294 = xor i8 %293, 1
  store volatile i8 %294, i8* %PF_write, align 1, !mcsema_real_eip !71
  store volatile i8 %294, i8* %PF_write, align 1, !mcsema_real_eip !71
  %295 = zext i32 %282 to i64, !mcsema_real_eip !71
  store volatile i64 %295, i64* %RAX_write, align 8, !mcsema_real_eip !71
  store volatile i64 4196163, i64* %RIP_write, align 8, !mcsema_real_eip !72
  %296 = load i64, i64* %RBX_write, align 8, !mcsema_real_eip !72
  %297 = add i64 %296, 1, !mcsema_real_eip !72
  store volatile i64 %297, i64* %RSI_write, align 8, !mcsema_real_eip !72
  br label %block_400747, !mcsema_real_eip !73

block_400747:                                     ; preds = %block_400732, %block_400740
  store volatile i64 4196167, i64* %RIP_write, align 8, !mcsema_real_eip !73
  %298 = load i32, i32* %EAX_read, align 4, !mcsema_real_eip !73
  %299 = zext i32 %298 to i64, !mcsema_real_eip !73
  store volatile i64 %299, i64* %RDX_write, align 8, !mcsema_real_eip !73
  store volatile i64 4196169, i64* %RIP_write, align 8, !mcsema_real_eip !74
  %300 = load i32, i32* %EDX_read, align 4, !mcsema_real_eip !74
  %301 = and i32 %300, 16711680, !mcsema_real_eip !74
  store volatile i8 0, i8* %SF_write, align 1, !mcsema_real_eip !74
  %302 = icmp eq i32 %301, 0, !mcsema_real_eip !74
  %303 = zext i1 %302 to i8, !mcsema_real_eip !74
  store volatile i8 %303, i8* %ZF_write, align 1, !mcsema_real_eip !74
  store volatile i8 1, i8* %PF_write, align 1, !mcsema_real_eip !74
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !74
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !74
  %304 = zext i32 %301 to i64, !mcsema_real_eip !74
  store volatile i64 %304, i64* %RDX_write, align 8, !mcsema_real_eip !74
  store volatile i64 4196175, i64* %RIP_write, align 8, !mcsema_real_eip !75
  %305 = load i32, i32* %EDX_read, align 4, !mcsema_real_eip !75
  %306 = zext i32 %305 to i64, !mcsema_real_eip !75
  store volatile i64 %306, i64* %RCX_write, align 8, !mcsema_real_eip !75
  store volatile i64 4196177, i64* %RIP_write, align 8, !mcsema_real_eip !76
  %307 = load i32, i32* %ECX_read, align 4, !mcsema_real_eip !76
  %308 = lshr i32 %307, 15, !mcsema_real_eip !76
  %309 = lshr i32 %307, 16
  %310 = load i8, i8* %OF_write, align 1, !mcsema_real_eip !76
  %311 = and i8 %310, 1
  store volatile i8 %311, i8* %OF_write, align 1, !mcsema_real_eip !76
  %.tr23 = trunc i32 %308 to i8
  %312 = and i8 %.tr23, 1
  store volatile i8 %312, i8* %CF_write, align 1, !mcsema_real_eip !76
  %313 = icmp eq i32 %309, 0, !mcsema_real_eip !76
  %314 = zext i1 %313 to i8, !mcsema_real_eip !76
  store volatile i8 %314, i8* %ZF_write, align 1, !mcsema_real_eip !76
  store volatile i8 0, i8* %SF_write, align 1, !mcsema_real_eip !76
  %315 = trunc i32 %309 to i8, !mcsema_real_eip !76
  %316 = tail call i8 @llvm.ctpop.i8(i8 %315), !mcsema_real_eip !76
  %317 = and i8 %316, 1
  %318 = xor i8 %317, 1
  store volatile i8 %318, i8* %PF_write, align 1, !mcsema_real_eip !76
  store volatile i8 %318, i8* %PF_write, align 1, !mcsema_real_eip !76
  %319 = zext i32 %309 to i64, !mcsema_real_eip !76
  store volatile i64 %319, i64* %RCX_write, align 8, !mcsema_real_eip !76
  store volatile i64 4196180, i64* %RIP_write, align 8, !mcsema_real_eip !77
  %320 = load i8, i8* %AL_write, align 1, !mcsema_real_eip !77
  %321 = zext i8 %320 to i64
  store volatile i64 %321, i64* %RDX_write, align 8, !mcsema_real_eip !77
  store volatile i64 4196183, i64* %RIP_write, align 8, !mcsema_real_eip !78
  %322 = load i32, i32* %EDX_read, align 4, !mcsema_real_eip !78
  %323 = shl i32 %322, 16
  %324 = load i8, i8* %OF_write, align 1, !mcsema_real_eip !78
  %325 = and i8 %324, 1
  store volatile i8 %325, i8* %OF_write, align 1, !mcsema_real_eip !78
  %326 = lshr i32 %322, 16
  %.tr25 = trunc i32 %326 to i8
  %327 = and i8 %.tr25, 1
  store volatile i8 %327, i8* %CF_write, align 1, !mcsema_real_eip !78
  %328 = icmp eq i32 %323, 0, !mcsema_real_eip !78
  %329 = zext i1 %328 to i8, !mcsema_real_eip !78
  store volatile i8 %329, i8* %ZF_write, align 1, !mcsema_real_eip !78
  %330 = lshr i32 %322, 15
  %.tr27 = trunc i32 %330 to i8
  %331 = and i8 %.tr27, 1
  store volatile i8 %331, i8* %SF_write, align 1, !mcsema_real_eip !78
  store volatile i8 1, i8* %PF_write, align 1, !mcsema_real_eip !78
  store volatile i8 1, i8* %PF_write, align 1, !mcsema_real_eip !78
  %332 = zext i32 %323 to i64, !mcsema_real_eip !78
  store volatile i64 %332, i64* %RDX_write, align 8, !mcsema_real_eip !78
  store volatile i64 4196186, i64* %RIP_write, align 8, !mcsema_real_eip !79
  %333 = load i32, i32* %EDX_read, align 4, !mcsema_real_eip !79
  %334 = load i32, i32* %ECX_read, align 4, !mcsema_real_eip !79
  %335 = or i32 %334, %333, !mcsema_real_eip !79
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !79
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !79
  %.lobit28 = lshr i32 %335, 31
  %336 = trunc i32 %.lobit28 to i8
  store volatile i8 %336, i8* %SF_write, align 1, !mcsema_real_eip !79
  %337 = icmp eq i32 %335, 0, !mcsema_real_eip !79
  %338 = zext i1 %337 to i8, !mcsema_real_eip !79
  store volatile i8 %338, i8* %ZF_write, align 1, !mcsema_real_eip !79
  %339 = trunc i32 %335 to i8, !mcsema_real_eip !79
  %340 = tail call i8 @llvm.ctpop.i8(i8 %339), !mcsema_real_eip !79
  %341 = and i8 %340, 1
  %342 = xor i8 %341, 1
  store volatile i8 %342, i8* %PF_write, align 1, !mcsema_real_eip !79
  %343 = zext i32 %335 to i64, !mcsema_real_eip !79
  store volatile i64 %343, i64* %RDX_write, align 8, !mcsema_real_eip !79
  store volatile i64 4196188, i64* %RIP_write, align 8, !mcsema_real_eip !80
  %344 = load i32, i32* %EAX_read, align 4, !mcsema_real_eip !80
  %345 = and i32 %344, 65280, !mcsema_real_eip !80
  store volatile i8 0, i8* %SF_write, align 1, !mcsema_real_eip !80
  %346 = icmp eq i32 %345, 0, !mcsema_real_eip !80
  %347 = zext i1 %346 to i8, !mcsema_real_eip !80
  store volatile i8 %347, i8* %ZF_write, align 1, !mcsema_real_eip !80
  store volatile i8 1, i8* %PF_write, align 1, !mcsema_real_eip !80
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !80
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !80
  %348 = zext i32 %345 to i64, !mcsema_real_eip !80
  store volatile i64 %348, i64* %RAX_write, align 8, !mcsema_real_eip !80
  store volatile i64 4196193, i64* %RIP_write, align 8, !mcsema_real_eip !81
  %349 = load i32, i32* %EAX_read, align 4, !mcsema_real_eip !81
  %350 = load i32, i32* %EDX_read, align 4, !mcsema_real_eip !81
  %351 = or i32 %350, %349, !mcsema_real_eip !81
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !81
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !81
  %.lobit29 = lshr i32 %351, 31
  %352 = trunc i32 %.lobit29 to i8
  store volatile i8 %352, i8* %SF_write, align 1, !mcsema_real_eip !81
  %353 = icmp eq i32 %351, 0, !mcsema_real_eip !81
  %354 = zext i1 %353 to i8, !mcsema_real_eip !81
  store volatile i8 %354, i8* %ZF_write, align 1, !mcsema_real_eip !81
  %355 = trunc i32 %351 to i8, !mcsema_real_eip !81
  %356 = tail call i8 @llvm.ctpop.i8(i8 %355), !mcsema_real_eip !81
  %357 = and i8 %356, 1
  %358 = xor i8 %357, 1
  store volatile i8 %358, i8* %PF_write, align 1, !mcsema_real_eip !81
  %359 = zext i32 %351 to i64, !mcsema_real_eip !81
  store volatile i64 %359, i64* %RAX_write, align 8, !mcsema_real_eip !81
  store volatile i64 4196195, i64* %RIP_write, align 8, !mcsema_real_eip !82
  %360 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !82
  %361 = load i64, i64* %RBX_write, align 8, !mcsema_real_eip !82
  %362 = add i64 %361, %360, !mcsema_real_eip !82
  %363 = load i32, i32* %EAX_read, align 4, !mcsema_real_eip !82
  %364 = inttoptr i64 %362 to i32*, !mcsema_real_eip !82
  store i32 %363, i32* %364, align 4, !mcsema_real_eip !82
  store volatile i64 4196198, i64* %RIP_write, align 8, !mcsema_real_eip !83
  %365 = load i64, i64* %RSI_write, align 8, !mcsema_real_eip !83
  store volatile i64 %365, i64* %RBX_write, align 8, !mcsema_real_eip !83
  br label %block_400769, !mcsema_real_eip !84

block_400769:                                     ; preds = %block_40072c, %block_400747
  store volatile i64 4196201, i64* %RIP_write, align 8, !mcsema_real_eip !84
  %366 = load i64, i64* %RBX_write, align 8, !mcsema_real_eip !84
  store volatile i64 %366, i64* %RDI_write, align 8, !mcsema_real_eip !84
  store volatile i64 4196204, i64* %RIP_write, align 8, !mcsema_real_eip !85
  %367 = load i64, i64* %RDI_write, align 8, !mcsema_real_eip !85
  %368 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !85
  %369 = add i64 %368, -8
  %370 = inttoptr i64 %369 to i64*, !mcsema_real_eip !85
  store i64 -2415393069852865332, i64* %370, align 8, !mcsema_real_eip !85
  store volatile i64 %369, i64* %RSP_write, align 8, !mcsema_real_eip !85
  %371 = tail call x86_64_sysvcc i64 @_malloc(i64 %367), !mcsema_real_eip !85
  store volatile i64 %371, i64* %RAX_write, align 8, !mcsema_real_eip !85
  store volatile i64 4196209, i64* %RIP_write, align 8, !mcsema_real_eip !86
  %372 = bitcast i64* %RBP_write to i64**
  %373 = load i64*, i64** %372, align 8
  %374 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !86
  store i64 %374, i64* %373, align 8, !mcsema_real_eip !86
  store volatile i64 4196213, i64* %RIP_write, align 8, !mcsema_real_eip !87
  %375 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !87
  %376 = icmp eq i64 %375, 0, !mcsema_real_eip !87
  %377 = zext i1 %376 to i8, !mcsema_real_eip !87
  store volatile i8 %377, i8* %ZF_write, align 1, !mcsema_real_eip !87
  %.lobit30 = lshr i64 %375, 63
  %378 = trunc i64 %.lobit30 to i8
  store volatile i8 %378, i8* %SF_write, align 1, !mcsema_real_eip !87
  %379 = trunc i64 %375 to i8, !mcsema_real_eip !87
  %380 = tail call i8 @llvm.ctpop.i8(i8 %379), !mcsema_real_eip !87
  %381 = and i8 %380, 1
  %382 = xor i8 %381, 1
  store volatile i8 %382, i8* %PF_write, align 1, !mcsema_real_eip !87
  store volatile i8 %382, i8* %PF_write, align 1, !mcsema_real_eip !87
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !87
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !87
  store volatile i64 4196216, i64* %RIP_write, align 8, !mcsema_real_eip !88
  %383 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !88
  %384 = and i8 %383, 1
  %385 = icmp eq i8 %384, 0
  br i1 %385, label %block_400784, label %block_40077a, !mcsema_real_eip !88

block_40077a:                                     ; preds = %block_400769
  store volatile i64 4196218, i64* %RIP_write, align 8, !mcsema_real_eip !89
  store volatile i64 4294967295, i64* %RDI_write, align 8, !mcsema_real_eip !89
  store volatile i64 4196223, i64* %RIP_write, align 8, !mcsema_real_eip !90
  %386 = load i64, i64* %RDI_write, align 8, !mcsema_real_eip !90
  %387 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !90
  %388 = add i64 %387, -8
  %389 = inttoptr i64 %388 to i64*, !mcsema_real_eip !90
  store i64 -2415393069852865332, i64* %389, align 8, !mcsema_real_eip !90
  store volatile i64 %388, i64* %RSP_write, align 8, !mcsema_real_eip !90
  %390 = tail call x86_64_sysvcc i64 @_exit(i64 %386), !mcsema_real_eip !90
  store volatile i64 %390, i64* %RAX_write, align 8, !mcsema_real_eip !90
  br label %block_400784, !mcsema_real_eip !91

block_400784:                                     ; preds = %block_400769, %block_40077a
  store volatile i64 4196228, i64* %RIP_write, align 8, !mcsema_real_eip !91
  %391 = load i64, i64* %RBX_write, align 8, !mcsema_real_eip !91
  store volatile i64 %391, i64* %RDX_write, align 8, !mcsema_real_eip !91
  store volatile i64 4196231, i64* %RIP_write, align 8, !mcsema_real_eip !92
  %392 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !92
  store volatile i64 %392, i64* %RSI_write, align 8, !mcsema_real_eip !92
  store volatile i64 4196234, i64* %RIP_write, align 8, !mcsema_real_eip !93
  %393 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !93
  store volatile i64 %393, i64* %RDI_write, align 8, !mcsema_real_eip !93
  store volatile i64 4196237, i64* %RIP_write, align 8, !mcsema_real_eip !94
  %394 = load i64, i64* %RDI_write, align 8, !mcsema_real_eip !94
  %395 = load i64, i64* %RSI_write, align 8, !mcsema_real_eip !94
  %396 = load i64, i64* %RDX_write, align 8, !mcsema_real_eip !94
  %397 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !94
  %398 = add i64 %397, -8
  %399 = inttoptr i64 %398 to i64*, !mcsema_real_eip !94
  store i64 -2415393069852865332, i64* %399, align 8, !mcsema_real_eip !94
  store volatile i64 %398, i64* %RSP_write, align 8, !mcsema_real_eip !94
  %400 = tail call x86_64_sysvcc i64 @_memcpy(i64 %394, i64 %395, i64 %396), !mcsema_real_eip !94
  store volatile i64 %400, i64* %RAX_write, align 8, !mcsema_real_eip !94
  store volatile i64 4196242, i64* %RIP_write, align 8, !mcsema_real_eip !95
  %401 = load i64, i64* %RBX_write, align 8, !mcsema_real_eip !95
  store volatile i64 %401, i64* %RAX_write, align 8, !mcsema_real_eip !95
  store volatile i64 4196245, i64* %RIP_write, align 8, !mcsema_real_eip !96
  %402 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !96
  %403 = add i64 %402, 200, !mcsema_real_eip !96
  %404 = xor i64 %403, %402, !mcsema_real_eip !96
  %405 = lshr i64 %404, 4
  %.tr32 = trunc i64 %405 to i8
  %406 = and i8 %.tr32, 1
  store volatile i8 %406, i8* %AF_write, align 1, !mcsema_real_eip !96
  %.lobit33 = lshr i64 %403, 63
  %407 = trunc i64 %.lobit33 to i8
  store volatile i8 %407, i8* %SF_write, align 1, !mcsema_real_eip !96
  %408 = icmp eq i64 %403, 0, !mcsema_real_eip !96
  %409 = zext i1 %408 to i8, !mcsema_real_eip !96
  store volatile i8 %409, i8* %ZF_write, align 1, !mcsema_real_eip !96
  %410 = xor i64 %402, -9223372036854775808, !mcsema_real_eip !96
  %411 = and i64 %404, %410, !mcsema_real_eip !96
  %.lobit34 = lshr i64 %411, 63
  %412 = trunc i64 %.lobit34 to i8
  store volatile i8 %412, i8* %OF_write, align 1, !mcsema_real_eip !96
  %413 = trunc i64 %403 to i8, !mcsema_real_eip !96
  %414 = tail call i8 @llvm.ctpop.i8(i8 %413), !mcsema_real_eip !96
  %415 = and i8 %414, 1
  %416 = xor i8 %415, 1
  store volatile i8 %416, i8* %PF_write, align 1, !mcsema_real_eip !96
  %417 = icmp ugt i64 %402, -201
  %418 = zext i1 %417 to i8, !mcsema_real_eip !96
  store volatile i8 %418, i8* %CF_write, align 1, !mcsema_real_eip !96
  store volatile i64 %403, i64* %RSP_write, align 8, !mcsema_real_eip !96
  store volatile i64 4196252, i64* %RIP_write, align 8, !mcsema_real_eip !97
  %419 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !97
  %420 = inttoptr i64 %419 to i64*, !mcsema_real_eip !97
  %421 = load i64, i64* %420, align 8, !mcsema_real_eip !97
  store volatile i64 %421, i64* %RBX_write, align 8, !mcsema_real_eip !97
  %422 = add i64 %419, 8, !mcsema_real_eip !97
  store volatile i64 %422, i64* %RSP_write, align 8, !mcsema_real_eip !97
  store volatile i64 4196253, i64* %RIP_write, align 8, !mcsema_real_eip !98
  %423 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !98
  %424 = inttoptr i64 %423 to i64*, !mcsema_real_eip !98
  %425 = load i64, i64* %424, align 8, !mcsema_real_eip !98
  store volatile i64 %425, i64* %RBP_write, align 8, !mcsema_real_eip !98
  %426 = add i64 %423, 8, !mcsema_real_eip !98
  store volatile i64 %426, i64* %RSP_write, align 8, !mcsema_real_eip !98
  store volatile i64 4196254, i64* %RIP_write, align 8, !mcsema_real_eip !99
  %427 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !99
  %428 = add i64 %427, 8, !mcsema_real_eip !99
  %429 = inttoptr i64 %427 to i64*, !mcsema_real_eip !99
  %430 = load i64, i64* %429, align 8, !mcsema_real_eip !99
  store volatile i64 %430, i64* %RIP_write, align 8, !mcsema_real_eip !99
  store volatile i64 %428, i64* %RSP_write, align 8, !mcsema_real_eip !99
  ret void, !mcsema_real_eip !99

.preheader:                                       ; preds = %.preheader.preheader, %.preheader
  %431 = load i64, i64* %RDI_write, align 8, !mcsema_real_eip !38
  %432 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !38
  %433 = inttoptr i64 %431 to i64*, !mcsema_real_eip !38
  store i64 %432, i64* %433, align 8, !mcsema_real_eip !38
  %434 = load i8, i8* %DF_write, align 1, !mcsema_real_eip !38
  %435 = and i8 %434, 1
  %436 = zext i8 %435 to i64
  %437 = shl nuw nsw i64 %436, 4
  %438 = xor i64 %437, 16
  %439 = add i64 %431, -8
  %440 = add i64 %439, %438
  store volatile i64 %440, i64* %RDI_write, align 8, !mcsema_real_eip !38
  %441 = load i64, i64* %RCX_write, align 8, !mcsema_real_eip !38
  %442 = add i64 %441, -1
  store volatile i64 %442, i64* %RCX_write, align 8, !mcsema_real_eip !38
  %443 = icmp eq i64 %442, 0, !mcsema_real_eip !38
  br i1 %443, label %.loopexit.loopexit, label %.preheader, !mcsema_real_eip !38

.loopexit.loopexit:                               ; preds = %.preheader
  br label %.loopexit

.loopexit:                                        ; preds = %.loopexit.loopexit, %entry
  store volatile i64 4196037, i64* %RIP_write, align 8, !mcsema_real_eip !100
  store volatile i64 0, i64* %RBX_write, align 8, !mcsema_real_eip !100
  store volatile i64 4196042, i64* %RIP_write, align 8, !mcsema_real_eip !101
  store volatile i64 0, i64* %RSI_write, align 8, !mcsema_real_eip !101
  store volatile i64 4196047, i64* %RIP_write, align 8, !mcsema_real_eip !102
  br label %block_400712, !mcsema_real_eip !102
}

; Function Attrs: noinline
define internal x86_64_sysvcc void @deregister_tm_clones(%RegState* nocapture) unnamed_addr #1 {
entry:
  %RIP_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 0, !mcsema_real_eip !103
  %RAX_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 1, !mcsema_real_eip !103
  %RDI_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 6, !mcsema_real_eip !103
  %RSP_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 7, !mcsema_real_eip !103
  %RBP_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 8, !mcsema_real_eip !103
  %CF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 17, !mcsema_real_eip !103
  %PF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 18, !mcsema_real_eip !103
  %AF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 19, !mcsema_real_eip !103
  %ZF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 20, !mcsema_real_eip !103
  %SF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 21, !mcsema_real_eip !103
  %OF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 22, !mcsema_real_eip !103
  store volatile i64 4195808, i64* %RIP_write, align 8, !mcsema_real_eip !103
  store volatile i64 6296183, i64* %RAX_write, align 8, !mcsema_real_eip !103
  store volatile i64 4195813, i64* %RIP_write, align 8, !mcsema_real_eip !104
  %1 = load i64, i64* %RBP_write, align 8, !mcsema_real_eip !104
  %2 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !104
  %3 = add i64 %2, -8
  %4 = inttoptr i64 %3 to i64*, !mcsema_real_eip !104
  store i64 %1, i64* %4, align 8, !mcsema_real_eip !104
  store volatile i64 %3, i64* %RSP_write, align 8, !mcsema_real_eip !104
  store volatile i64 4195814, i64* %RIP_write, align 8, !mcsema_real_eip !105
  %5 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !105
  %6 = add i64 %5, -6296176
  %7 = xor i64 %6, %5, !mcsema_real_eip !105
  %8 = lshr i64 %7, 4
  %.lobit = and i64 %8, 1
  %9 = xor i64 %.lobit, 1
  %10 = trunc i64 %9 to i8
  store volatile i8 %10, i8* %AF_write, align 1, !mcsema_real_eip !105
  %11 = trunc i64 %6 to i8, !mcsema_real_eip !105
  %12 = tail call i8 @llvm.ctpop.i8(i8 %11), !mcsema_real_eip !105
  %13 = and i8 %12, 1
  %14 = xor i8 %13, 1
  store volatile i8 %14, i8* %PF_write, align 1, !mcsema_real_eip !105
  %15 = icmp eq i64 %6, 0, !mcsema_real_eip !105
  %16 = zext i1 %15 to i8, !mcsema_real_eip !105
  store volatile i8 %16, i8* %ZF_write, align 1, !mcsema_real_eip !105
  %.lobit1 = lshr i64 %6, 63
  %17 = trunc i64 %.lobit1 to i8
  store volatile i8 %17, i8* %SF_write, align 1, !mcsema_real_eip !105
  %18 = icmp ult i64 %5, 6296176, !mcsema_real_eip !105
  %19 = zext i1 %18 to i8, !mcsema_real_eip !105
  store volatile i8 %19, i8* %CF_write, align 1, !mcsema_real_eip !105
  %20 = and i64 %7, %5, !mcsema_real_eip !105
  %.lobit2 = lshr i64 %20, 63
  %21 = trunc i64 %.lobit2 to i8
  store volatile i8 %21, i8* %OF_write, align 1, !mcsema_real_eip !105
  store volatile i64 %6, i64* %RAX_write, align 8, !mcsema_real_eip !105
  store volatile i64 4195820, i64* %RIP_write, align 8, !mcsema_real_eip !106
  %22 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !106
  %23 = add i64 %22, -14
  %24 = xor i64 %23, %22, !mcsema_real_eip !106
  %25 = lshr i64 %24, 4
  %.tr = trunc i64 %25 to i8
  %26 = and i8 %.tr, 1
  store volatile i8 %26, i8* %AF_write, align 1, !mcsema_real_eip !106
  %27 = trunc i64 %23 to i8, !mcsema_real_eip !106
  %28 = tail call i8 @llvm.ctpop.i8(i8 %27), !mcsema_real_eip !106
  %29 = and i8 %28, 1
  %30 = xor i8 %29, 1
  store volatile i8 %30, i8* %PF_write, align 1, !mcsema_real_eip !106
  %31 = icmp eq i64 %23, 0, !mcsema_real_eip !106
  %32 = zext i1 %31 to i8, !mcsema_real_eip !106
  store volatile i8 %32, i8* %ZF_write, align 1, !mcsema_real_eip !106
  %.lobit4 = lshr i64 %23, 63
  %33 = trunc i64 %.lobit4 to i8
  store volatile i8 %33, i8* %SF_write, align 1, !mcsema_real_eip !106
  %34 = icmp ult i64 %22, 14, !mcsema_real_eip !106
  %35 = zext i1 %34 to i8, !mcsema_real_eip !106
  store volatile i8 %35, i8* %CF_write, align 1, !mcsema_real_eip !106
  %36 = and i64 %24, %22, !mcsema_real_eip !106
  %.lobit5 = lshr i64 %36, 63
  %37 = trunc i64 %.lobit5 to i8
  store volatile i8 %37, i8* %OF_write, align 1, !mcsema_real_eip !106
  store volatile i64 4195824, i64* %RIP_write, align 8, !mcsema_real_eip !107
  %38 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !107
  store volatile i64 %38, i64* %RBP_write, align 8, !mcsema_real_eip !107
  store volatile i64 4195827, i64* %RIP_write, align 8, !mcsema_real_eip !108
  %39 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !108
  %40 = load i8, i8* %CF_write, align 1, !mcsema_real_eip !108
  %41 = or i8 %40, %39
  %42 = and i8 %41, 1
  %43 = icmp eq i8 %42, 0
  br i1 %43, label %block_4005f5, label %block_400610, !mcsema_real_eip !108

block_4005f5:                                     ; preds = %entry
  store volatile i64 4195829, i64* %RIP_write, align 8, !mcsema_real_eip !109
  store volatile i64 0, i64* %RAX_write, align 8, !mcsema_real_eip !109
  store volatile i64 4195834, i64* %RIP_write, align 8, !mcsema_real_eip !110
  %44 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !110
  %45 = icmp eq i64 %44, 0, !mcsema_real_eip !110
  %46 = zext i1 %45 to i8, !mcsema_real_eip !110
  store volatile i8 %46, i8* %ZF_write, align 1, !mcsema_real_eip !110
  %.lobit6 = lshr i64 %44, 63
  %47 = trunc i64 %.lobit6 to i8
  store volatile i8 %47, i8* %SF_write, align 1, !mcsema_real_eip !110
  %48 = trunc i64 %44 to i8, !mcsema_real_eip !110
  %49 = tail call i8 @llvm.ctpop.i8(i8 %48), !mcsema_real_eip !110
  %50 = and i8 %49, 1
  %51 = xor i8 %50, 1
  store volatile i8 %51, i8* %PF_write, align 1, !mcsema_real_eip !110
  store volatile i8 %51, i8* %PF_write, align 1, !mcsema_real_eip !110
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !110
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !110
  store volatile i64 4195837, i64* %RIP_write, align 8, !mcsema_real_eip !111
  %52 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !111
  %53 = and i8 %52, 1
  %54 = icmp eq i8 %53, 0
  br i1 %54, label %block_4005ff, label %block_400610, !mcsema_real_eip !111

block_4005ff:                                     ; preds = %block_4005f5
  store volatile i64 4195839, i64* %RIP_write, align 8, !mcsema_real_eip !112
  %55 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !112
  %56 = inttoptr i64 %55 to i64*, !mcsema_real_eip !112
  %57 = load i64, i64* %56, align 8, !mcsema_real_eip !112
  store volatile i64 %57, i64* %RBP_write, align 8, !mcsema_real_eip !112
  %58 = add i64 %55, 8, !mcsema_real_eip !112
  store volatile i64 %58, i64* %RSP_write, align 8, !mcsema_real_eip !112
  store volatile i64 4195840, i64* %RIP_write, align 8, !mcsema_real_eip !113
  store volatile i64 6296176, i64* %RDI_write, align 8, !mcsema_real_eip !113
  store volatile i64 4195845, i64* %RIP_write, align 8, !mcsema_real_eip !114
  %59 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !114
  store volatile i64 %59, i64* %RIP_write, align 8, !mcsema_real_eip !114
  tail call void @__mcsema_detach_call_value(), !mcsema_real_eip !114
  ret void, !mcsema_real_eip !114

block_400610:                                     ; preds = %block_4005f5, %entry
  store volatile i64 4195856, i64* %RIP_write, align 8, !mcsema_real_eip !115
  %60 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !115
  %61 = inttoptr i64 %60 to i64*, !mcsema_real_eip !115
  %62 = load i64, i64* %61, align 8, !mcsema_real_eip !115
  store volatile i64 %62, i64* %RBP_write, align 8, !mcsema_real_eip !115
  %63 = add i64 %60, 8, !mcsema_real_eip !115
  store volatile i64 %63, i64* %RSP_write, align 8, !mcsema_real_eip !115
  store volatile i64 4195857, i64* %RIP_write, align 8, !mcsema_real_eip !116
  %64 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !116
  %65 = add i64 %64, 8, !mcsema_real_eip !116
  %66 = inttoptr i64 %64 to i64*, !mcsema_real_eip !116
  %67 = load i64, i64* %66, align 8, !mcsema_real_eip !116
  store volatile i64 %67, i64* %RIP_write, align 8, !mcsema_real_eip !116
  store volatile i64 %65, i64* %RSP_write, align 8, !mcsema_real_eip !116
  ret void, !mcsema_real_eip !116
}

; Function Attrs: noinline
define x86_64_sysvcc void @sub_40079f(%RegState*) #1 {
entry:
  %RIP_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 0, !mcsema_real_eip !117
  %RAX_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 1, !mcsema_real_eip !117
  %EAX_read = bitcast i64* %RAX_write to i32*, !mcsema_real_eip !117
  %RCX_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 3, !mcsema_real_eip !117
  %RDX_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 4, !mcsema_real_eip !117
  %RSI_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 5, !mcsema_real_eip !117
  %RDI_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 6, !mcsema_real_eip !117
  %RSP_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 7, !mcsema_real_eip !117
  %R8_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 9, !mcsema_real_eip !117
  %R9_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 10, !mcsema_real_eip !117
  %R10_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 11, !mcsema_real_eip !117
  %CF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 17, !mcsema_real_eip !117
  %PF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 18, !mcsema_real_eip !117
  %AF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 19, !mcsema_real_eip !117
  %ZF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 20, !mcsema_real_eip !117
  %SF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 21, !mcsema_real_eip !117
  %OF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 22, !mcsema_real_eip !117
  %DF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 23, !mcsema_real_eip !117
  store volatile i64 4196255, i64* %RIP_write, align 8, !mcsema_real_eip !117
  %1 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !117
  %2 = add i64 %1, -56
  %3 = xor i64 %2, %1, !mcsema_real_eip !117
  %4 = lshr i64 %3, 4
  %.lobit = and i64 %4, 1
  %5 = xor i64 %.lobit, 1
  %6 = trunc i64 %5 to i8
  store volatile i8 %6, i8* %AF_write, align 1, !mcsema_real_eip !117
  %7 = trunc i64 %2 to i8, !mcsema_real_eip !117
  %8 = tail call i8 @llvm.ctpop.i8(i8 %7), !mcsema_real_eip !117
  %9 = and i8 %8, 1
  %10 = xor i8 %9, 1
  store volatile i8 %10, i8* %PF_write, align 1, !mcsema_real_eip !117
  %11 = icmp eq i64 %2, 0, !mcsema_real_eip !117
  %12 = zext i1 %11 to i8, !mcsema_real_eip !117
  store volatile i8 %12, i8* %ZF_write, align 1, !mcsema_real_eip !117
  %.lobit1 = lshr i64 %2, 63
  %13 = trunc i64 %.lobit1 to i8
  store volatile i8 %13, i8* %SF_write, align 1, !mcsema_real_eip !117
  %14 = icmp ult i64 %1, 56, !mcsema_real_eip !117
  %15 = zext i1 %14 to i8, !mcsema_real_eip !117
  store volatile i8 %15, i8* %CF_write, align 1, !mcsema_real_eip !117
  %16 = and i64 %3, %1, !mcsema_real_eip !117
  %.lobit2 = lshr i64 %16, 63
  %17 = trunc i64 %.lobit2 to i8
  store volatile i8 %17, i8* %OF_write, align 1, !mcsema_real_eip !117
  store volatile i64 %2, i64* %RSP_write, align 8, !mcsema_real_eip !117
  store volatile i64 4196259, i64* %RIP_write, align 8, !mcsema_real_eip !118
  %18 = bitcast i64* %RSP_write to i64**
  %19 = load i64*, i64** %18, align 8
  store i64 0, i64* %19, align 8, !mcsema_real_eip !118
  store volatile i64 4196267, i64* %RIP_write, align 8, !mcsema_real_eip !119
  %20 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !119
  %21 = add i64 %20, 8, !mcsema_real_eip !119
  %22 = inttoptr i64 %21 to i64*, !mcsema_real_eip !119
  store i64 0, i64* %22, align 8, !mcsema_real_eip !119
  store volatile i64 4196276, i64* %RIP_write, align 8, !mcsema_real_eip !120
  %23 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !120
  %24 = add i64 %23, 16, !mcsema_real_eip !120
  %25 = inttoptr i64 %24 to i64*, !mcsema_real_eip !120
  store i64 0, i64* %25, align 8, !mcsema_real_eip !120
  store volatile i64 4196285, i64* %RIP_write, align 8, !mcsema_real_eip !121
  %26 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !121
  %27 = add i64 %26, 24, !mcsema_real_eip !121
  %28 = inttoptr i64 %27 to i64*, !mcsema_real_eip !121
  store i64 0, i64* %28, align 8, !mcsema_real_eip !121
  store volatile i64 4196294, i64* %RIP_write, align 8, !mcsema_real_eip !122
  store volatile i64 zext (i32 add (i32 ptrtoint (%0* @data_4009a0 to i32), i32 8) to i64), i64* %RDI_write, align 8, !mcsema_real_eip !122
  store volatile i64 4196299, i64* %RIP_write, align 8, !mcsema_real_eip !123
  %29 = load i64, i64* %RDI_write, align 8, !mcsema_real_eip !123
  %30 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !123
  %31 = add i64 %30, -8
  %32 = inttoptr i64 %31 to i64*, !mcsema_real_eip !123
  store i64 -2415393069852865332, i64* %32, align 8, !mcsema_real_eip !123
  store volatile i64 %31, i64* %RSP_write, align 8, !mcsema_real_eip !123
  %33 = tail call x86_64_sysvcc i64 @_puts(i64 %29), !mcsema_real_eip !123
  store volatile i64 %33, i64* %RAX_write, align 8, !mcsema_real_eip !123
  store volatile i64 4196304, i64* %RIP_write, align 8, !mcsema_real_eip !124
  %34 = load i64, i64* bitcast ([8 x i8]* @stdin to i64*), align 8, !mcsema_real_eip !124
  store volatile i64 %34, i64* %RDX_write, align 8, !mcsema_real_eip !124
  store volatile i64 4196311, i64* %RIP_write, align 8, !mcsema_real_eip !125
  store volatile i64 256, i64* %RSI_write, align 8, !mcsema_real_eip !125
  store volatile i64 4196316, i64* %RIP_write, align 8, !mcsema_real_eip !126
  store volatile i64 zext (i32 add (i32 ptrtoint (%2* @data_601280 to i32), i32 32) to i64), i64* %RDI_write, align 8, !mcsema_real_eip !126
  store volatile i64 4196321, i64* %RIP_write, align 8, !mcsema_real_eip !127
  %35 = load i64, i64* %RDI_write, align 8, !mcsema_real_eip !127
  %36 = load i64, i64* %RSI_write, align 8, !mcsema_real_eip !127
  %37 = load i64, i64* %RDX_write, align 8, !mcsema_real_eip !127
  %38 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !127
  %39 = add i64 %38, -8
  %40 = inttoptr i64 %39 to i64*, !mcsema_real_eip !127
  store i64 -2415393069852865332, i64* %40, align 8, !mcsema_real_eip !127
  store volatile i64 %39, i64* %RSP_write, align 8, !mcsema_real_eip !127
  %41 = tail call x86_64_sysvcc i64 @_fgets(i64 %35, i64 %36, i64 %37), !mcsema_real_eip !127
  store volatile i64 %41, i64* %RAX_write, align 8, !mcsema_real_eip !127
  store volatile i64 4196326, i64* %RIP_write, align 8, !mcsema_real_eip !128
  store volatile i64 zext (i32 add (i32 ptrtoint (%2* @data_601280 to i32), i32 32) to i64), i64* %RDI_write, align 8, !mcsema_real_eip !128
  store volatile i64 4196331, i64* %RIP_write, align 8, !mcsema_real_eip !129
  store volatile i64 0, i64* %RAX_write, align 8, !mcsema_real_eip !129
  store volatile i64 4196336, i64* %RIP_write, align 8, !mcsema_real_eip !130
  store volatile i64 -1, i64* %RCX_write, align 8, !mcsema_real_eip !130
  store volatile i64 4196343, i64* %RIP_write, align 8, !mcsema_real_eip !131
  %42 = load i64, i64* %RCX_write, align 8, !mcsema_real_eip !131
  %43 = icmp eq i64 %42, 0, !mcsema_real_eip !131
  br i1 %43, label %.loopexit, label %.preheader.preheader, !mcsema_real_eip !131

.preheader.preheader:                             ; preds = %entry
  br label %.preheader

block_400805:                                     ; preds = %.loopexit
  store volatile i64 4196357, i64* %RIP_write, align 8, !mcsema_real_eip !132
  %44 = load i64, i64* %RCX_write, align 8, !mcsema_real_eip !132
  %45 = add i64 %44, add (i64 ptrtoint (%2* @data_601280 to i64), i64 30), !mcsema_real_eip !132
  %46 = inttoptr i64 %45 to i8*, !mcsema_real_eip !132
  store i8 0, i8* %46, align 1, !mcsema_real_eip !132
  br label %block_40080c, !mcsema_real_eip !133

block_40080c:                                     ; preds = %.loopexit, %block_400805
  store volatile i64 4196364, i64* %RIP_write, align 8, !mcsema_real_eip !133
  %47 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !133
  %48 = add i64 %47, 40, !mcsema_real_eip !133
  store volatile i64 %48, i64* %RSI_write, align 8, !mcsema_real_eip !133
  store volatile i64 4196369, i64* %RIP_write, align 8, !mcsema_real_eip !134
  store volatile i64 zext (i32 add (i32 ptrtoint (%2* @data_601280 to i32), i32 32) to i64), i64* %RDI_write, align 8, !mcsema_real_eip !134
  store volatile i64 4196374, i64* %RIP_write, align 8, !mcsema_real_eip !135
  %49 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !135
  %50 = add i64 %49, -8
  %51 = inttoptr i64 %50 to i64*, !mcsema_real_eip !135
  store i64 4196379, i64* %51, align 8, !mcsema_real_eip !135
  store volatile i64 %50, i64* %RSP_write, align 8, !mcsema_real_eip !135
  tail call x86_64_sysvcc void @b64d_fake(%RegState* nonnull %0), !mcsema_real_eip !135
  store volatile i64 4196379, i64* %RIP_write, align 8, !mcsema_real_eip !136
  %52 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !136
  %53 = add i64 %52, -16
  %54 = xor i64 %53, %52, !mcsema_real_eip !136
  %55 = lshr i64 %54, 4
  %.lobit6 = and i64 %55, 1
  %56 = xor i64 %.lobit6, 1
  %57 = trunc i64 %56 to i8
  store volatile i8 %57, i8* %AF_write, align 1, !mcsema_real_eip !136
  %58 = trunc i64 %53 to i8, !mcsema_real_eip !136
  %59 = tail call i8 @llvm.ctpop.i8(i8 %58), !mcsema_real_eip !136
  %60 = and i8 %59, 1
  %61 = xor i8 %60, 1
  store volatile i8 %61, i8* %PF_write, align 1, !mcsema_real_eip !136
  %62 = icmp eq i64 %53, 0, !mcsema_real_eip !136
  %63 = zext i1 %62 to i8, !mcsema_real_eip !136
  store volatile i8 %63, i8* %ZF_write, align 1, !mcsema_real_eip !136
  %.lobit7 = lshr i64 %53, 63
  %64 = trunc i64 %.lobit7 to i8
  store volatile i8 %64, i8* %SF_write, align 1, !mcsema_real_eip !136
  %65 = icmp ult i64 %52, 16, !mcsema_real_eip !136
  %66 = zext i1 %65 to i8, !mcsema_real_eip !136
  store volatile i8 %66, i8* %CF_write, align 1, !mcsema_real_eip !136
  %67 = and i64 %54, %52, !mcsema_real_eip !136
  %.lobit8 = lshr i64 %67, 63
  %68 = trunc i64 %.lobit8 to i8
  store volatile i8 %68, i8* %OF_write, align 1, !mcsema_real_eip !136
  store volatile i64 4196383, i64* %RIP_write, align 8, !mcsema_real_eip !137
  %69 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !137
  %70 = and i8 %69, 1
  %71 = icmp eq i8 %70, 0
  br i1 %71, label %block_4008ea, label %block_400825, !mcsema_real_eip !137

block_400825:                                     ; preds = %block_40080c
  store volatile i64 4196389, i64* %RIP_write, align 8, !mcsema_real_eip !138
  %72 = load i64*, i64** %18, align 8
  %73 = load i64, i64* %72, align 8, !mcsema_real_eip !138
  store volatile i64 %73, i64* %RCX_write, align 8, !mcsema_real_eip !138
  store volatile i64 4196393, i64* %RIP_write, align 8, !mcsema_real_eip !139
  %74 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !139
  %75 = add i64 %74, 8, !mcsema_real_eip !139
  %76 = inttoptr i64 %75 to i64*, !mcsema_real_eip !139
  %77 = load i64, i64* %76, align 8, !mcsema_real_eip !139
  store volatile i64 %77, i64* %RSI_write, align 8, !mcsema_real_eip !139
  store volatile i64 4196398, i64* %RIP_write, align 8, !mcsema_real_eip !140
  %78 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !140
  %79 = add i64 %78, 16, !mcsema_real_eip !140
  %80 = inttoptr i64 %79 to i64*, !mcsema_real_eip !140
  %81 = load i64, i64* %80, align 8, !mcsema_real_eip !140
  store volatile i64 %81, i64* %RDI_write, align 8, !mcsema_real_eip !140
  store volatile i64 4196403, i64* %RIP_write, align 8, !mcsema_real_eip !141
  %82 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !141
  %83 = add i64 %82, 24, !mcsema_real_eip !141
  %84 = inttoptr i64 %83 to i64*, !mcsema_real_eip !141
  %85 = load i64, i64* %84, align 8, !mcsema_real_eip !141
  store volatile i64 %85, i64* %R10_write, align 8, !mcsema_real_eip !141
  store volatile i64 4196408, i64* %RIP_write, align 8, !mcsema_real_eip !142
  %86 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !142
  %87 = add i64 %86, 40, !mcsema_real_eip !142
  %88 = inttoptr i64 %87 to i64*, !mcsema_real_eip !142
  %89 = load i64, i64* %88, align 8, !mcsema_real_eip !142
  store volatile i64 %89, i64* %R9_write, align 8, !mcsema_real_eip !142
  store volatile i64 4196413, i64* %RIP_write, align 8, !mcsema_real_eip !143
  store volatile i64 0, i64* %R8_write, align 8, !mcsema_real_eip !143
  br label %block_400843, !mcsema_real_eip !144

block_400843:                                     ; preds = %block_400843, %block_400825
  store volatile i64 4196419, i64* %RIP_write, align 8, !mcsema_real_eip !144
  %90 = load i64, i64* %R8_write, align 8, !mcsema_real_eip !144
  %91 = shl i64 %90, 2
  store volatile i64 %91, i64* %RAX_write, align 8, !mcsema_real_eip !144
  store volatile i64 4196427, i64* %RIP_write, align 8, !mcsema_real_eip !145
  %92 = load i32, i32* %EAX_read, align 4, !mcsema_real_eip !145
  %93 = and i32 %92, 15, !mcsema_real_eip !145
  store volatile i8 0, i8* %SF_write, align 1, !mcsema_real_eip !145
  %94 = icmp eq i32 %93, 0, !mcsema_real_eip !145
  %95 = zext i1 %94 to i8, !mcsema_real_eip !145
  store volatile i8 %95, i8* %ZF_write, align 1, !mcsema_real_eip !145
  %96 = trunc i32 %93 to i8, !mcsema_real_eip !145
  %97 = tail call i8 @llvm.ctpop.i8(i8 %96), !mcsema_real_eip !145
  %98 = and i8 %97, 1
  %99 = xor i8 %98, 1
  store volatile i8 %99, i8* %PF_write, align 1, !mcsema_real_eip !145
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !145
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !145
  %100 = zext i32 %93 to i64, !mcsema_real_eip !145
  store volatile i64 %100, i64* %RAX_write, align 8, !mcsema_real_eip !145
  store volatile i64 4196430, i64* %RIP_write, align 8, !mcsema_real_eip !146
  %101 = load i64, i64* %R9_write, align 8, !mcsema_real_eip !146
  %102 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !146
  %103 = add i64 %102, %101, !mcsema_real_eip !146
  %104 = inttoptr i64 %103 to i32*, !mcsema_real_eip !146
  %105 = load i32, i32* %104, align 4, !mcsema_real_eip !146
  %106 = zext i32 %105 to i64, !mcsema_real_eip !146
  store volatile i64 %106, i64* %RDX_write, align 8, !mcsema_real_eip !146
  store volatile i64 4196434, i64* %RIP_write, align 8, !mcsema_real_eip !147
  %107 = load i64, i64* %R8_write, align 8, !mcsema_real_eip !147
  store volatile i64 %107, i64* %RAX_write, align 8, !mcsema_real_eip !147
  store volatile i64 4196437, i64* %RIP_write, align 8, !mcsema_real_eip !148
  %108 = load i32, i32* %EAX_read, align 4, !mcsema_real_eip !148
  %109 = and i32 %108, 3, !mcsema_real_eip !148
  store volatile i8 0, i8* %SF_write, align 1, !mcsema_real_eip !148
  %110 = icmp eq i32 %109, 0, !mcsema_real_eip !148
  %111 = zext i1 %110 to i8, !mcsema_real_eip !148
  store volatile i8 %111, i8* %ZF_write, align 1, !mcsema_real_eip !148
  %112 = trunc i32 %109 to i8, !mcsema_real_eip !148
  %113 = tail call i8 @llvm.ctpop.i8(i8 %112), !mcsema_real_eip !148
  %114 = and i8 %113, 1
  %115 = xor i8 %114, 1
  store volatile i8 %115, i8* %PF_write, align 1, !mcsema_real_eip !148
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !148
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !148
  %116 = zext i32 %109 to i64, !mcsema_real_eip !148
  store volatile i64 %116, i64* %RAX_write, align 8, !mcsema_real_eip !148
  store volatile i64 4196440, i64* %RIP_write, align 8, !mcsema_real_eip !149
  %117 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !149
  %118 = shl i64 %117, 2
  %119 = add i64 %118, add (i64 ptrtoint (%0* @data_4009a0 to i64), i64 640), !mcsema_real_eip !149
  %120 = inttoptr i64 %119 to i32*, !mcsema_real_eip !149
  %121 = load i32, i32* %120, align 4, !mcsema_real_eip !149
  %122 = zext i32 %121 to i64, !mcsema_real_eip !149
  store volatile i64 %122, i64* %RAX_write, align 8, !mcsema_real_eip !149
  store volatile i64 4196447, i64* %RIP_write, align 8, !mcsema_real_eip !150
  %123 = load i64, i64* %RCX_write, align 8, !mcsema_real_eip !150
  %124 = lshr i64 %123, 63, !mcsema_real_eip !150
  %125 = shl i64 %123, 1
  %126 = or i64 %125, %124
  %127 = lshr i64 %123, 62
  %128 = and i64 %127, 1
  %129 = shl i64 %126, 1
  %130 = or i64 %129, %128
  %131 = lshr i64 %123, 61
  %132 = and i64 %131, 1
  %133 = shl i64 %130, 1
  %134 = or i64 %133, %132
  %135 = lshr i64 %123, 60
  %136 = and i64 %135, 1
  %137 = shl i64 %134, 1
  %138 = or i64 %137, %136
  %139 = lshr i64 %123, 59
  %140 = and i64 %139, 1
  %141 = shl i64 %138, 1
  %142 = or i64 %141, %140
  %143 = lshr i64 %123, 58
  %144 = and i64 %143, 1
  %145 = shl i64 %142, 1
  %146 = or i64 %145, %144
  %147 = lshr i64 %123, 57
  %148 = and i64 %147, 1
  %149 = shl i64 %146, 1
  %150 = or i64 %149, %148
  %151 = lshr i64 %123, 56
  %152 = and i64 %151, 1
  %153 = shl i64 %150, 1
  %154 = or i64 %153, %152
  %155 = lshr i64 %123, 55
  %156 = and i64 %155, 1
  %157 = shl i64 %154, 1
  %158 = or i64 %157, %156
  %159 = lshr i64 %123, 54
  %160 = and i64 %159, 1
  %161 = shl i64 %158, 1
  %162 = or i64 %161, %160
  %163 = lshr i64 %123, 53
  %164 = and i64 %163, 1
  %165 = shl i64 %162, 1
  %166 = or i64 %165, %164
  %167 = lshr i64 %123, 52
  %168 = and i64 %167, 1
  %169 = shl i64 %166, 1
  %170 = or i64 %169, %168
  %171 = lshr i64 %123, 51
  %172 = and i64 %171, 1
  %173 = shl i64 %170, 1
  %174 = or i64 %173, %172
  %.tr = trunc i64 %172 to i8
  store volatile i8 %.tr, i8* %CF_write, align 1, !mcsema_real_eip !150
  store volatile i8 1, i8* %OF_write, align 1, !mcsema_real_eip !150
  store volatile i64 %174, i64* %RCX_write, align 8, !mcsema_real_eip !150
  store volatile i64 4196451, i64* %RIP_write, align 8, !mcsema_real_eip !151
  %175 = load i64, i64* %RCX_write, align 8, !mcsema_real_eip !151
  %176 = load i64, i64* %RDX_write, align 8, !mcsema_real_eip !151
  %177 = xor i64 %176, %175, !mcsema_real_eip !151
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !151
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !151
  %.lobit9 = lshr i64 %177, 63
  %178 = trunc i64 %.lobit9 to i8
  store volatile i8 %178, i8* %SF_write, align 1, !mcsema_real_eip !151
  %179 = icmp eq i64 %175, %176
  %180 = zext i1 %179 to i8, !mcsema_real_eip !151
  store volatile i8 %180, i8* %ZF_write, align 1, !mcsema_real_eip !151
  %181 = trunc i64 %177 to i8, !mcsema_real_eip !151
  %182 = tail call i8 @llvm.ctpop.i8(i8 %181), !mcsema_real_eip !151
  %183 = and i8 %182, 1
  %184 = xor i8 %183, 1
  store volatile i8 %184, i8* %PF_write, align 1, !mcsema_real_eip !151
  store volatile i64 %177, i64* %RCX_write, align 8, !mcsema_real_eip !151
  store volatile i64 4196454, i64* %RIP_write, align 8, !mcsema_real_eip !152
  %185 = load i64, i64* %RCX_write, align 8, !mcsema_real_eip !152
  %186 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !152
  %187 = add i64 %186, %185, !mcsema_real_eip !152
  %188 = xor i64 %187, %185, !mcsema_real_eip !152
  %189 = xor i64 %188, %186, !mcsema_real_eip !152
  %190 = lshr i64 %189, 4
  %.tr11 = trunc i64 %190 to i8
  %191 = and i8 %.tr11, 1
  store volatile i8 %191, i8* %AF_write, align 1, !mcsema_real_eip !152
  %.lobit12 = lshr i64 %187, 63
  %192 = trunc i64 %.lobit12 to i8
  store volatile i8 %192, i8* %SF_write, align 1, !mcsema_real_eip !152
  %193 = icmp eq i64 %187, 0, !mcsema_real_eip !152
  %194 = zext i1 %193 to i8, !mcsema_real_eip !152
  store volatile i8 %194, i8* %ZF_write, align 1, !mcsema_real_eip !152
  %195 = xor i64 %185, -9223372036854775808, !mcsema_real_eip !152
  %196 = xor i64 %195, %186, !mcsema_real_eip !152
  %197 = and i64 %188, %196, !mcsema_real_eip !152
  %.lobit13 = lshr i64 %197, 63
  %198 = trunc i64 %.lobit13 to i8
  store volatile i8 %198, i8* %OF_write, align 1, !mcsema_real_eip !152
  %199 = trunc i64 %187 to i8, !mcsema_real_eip !152
  %200 = tail call i8 @llvm.ctpop.i8(i8 %199), !mcsema_real_eip !152
  %201 = and i8 %200, 1
  %202 = xor i8 %201, 1
  store volatile i8 %202, i8* %PF_write, align 1, !mcsema_real_eip !152
  %203 = icmp ult i64 %187, %185, !mcsema_real_eip !152
  %204 = zext i1 %203 to i8, !mcsema_real_eip !152
  store volatile i8 %204, i8* %CF_write, align 1, !mcsema_real_eip !152
  store volatile i64 %187, i64* %RCX_write, align 8, !mcsema_real_eip !152
  store volatile i64 4196457, i64* %RIP_write, align 8, !mcsema_real_eip !153
  %205 = load i64, i64* %RSI_write, align 8, !mcsema_real_eip !153
  %206 = lshr i64 %205, 1, !mcsema_real_eip !153
  %207 = shl i64 %205, 63, !mcsema_real_eip !153
  %208 = or i64 %206, %207
  %209 = lshr i64 %208, 1, !mcsema_real_eip !153
  %210 = shl i64 %206, 63, !mcsema_real_eip !153
  %211 = or i64 %209, %210
  %212 = lshr i64 %211, 1, !mcsema_real_eip !153
  %213 = shl i64 %209, 63, !mcsema_real_eip !153
  %214 = or i64 %212, %213
  %215 = lshr i64 %214, 1, !mcsema_real_eip !153
  %216 = shl i64 %212, 63, !mcsema_real_eip !153
  %217 = or i64 %215, %216
  %218 = lshr i64 %217, 1, !mcsema_real_eip !153
  %219 = shl i64 %215, 63, !mcsema_real_eip !153
  %220 = or i64 %218, %219
  %221 = lshr i64 %220, 1, !mcsema_real_eip !153
  %222 = shl i64 %218, 63, !mcsema_real_eip !153
  %223 = or i64 %221, %222
  %224 = lshr i64 %223, 1, !mcsema_real_eip !153
  %225 = shl i64 %221, 63, !mcsema_real_eip !153
  %226 = or i64 %224, %225
  %227 = lshr i64 %226, 1, !mcsema_real_eip !153
  %228 = shl i64 %224, 63, !mcsema_real_eip !153
  %229 = or i64 %227, %228
  %230 = lshr i64 %229, 1, !mcsema_real_eip !153
  %231 = shl i64 %227, 63, !mcsema_real_eip !153
  %232 = or i64 %230, %231
  %233 = lshr i64 %232, 1, !mcsema_real_eip !153
  %234 = shl i64 %230, 63, !mcsema_real_eip !153
  %235 = or i64 %233, %234
  %236 = lshr i64 %235, 1, !mcsema_real_eip !153
  %237 = shl i64 %233, 63, !mcsema_real_eip !153
  %238 = or i64 %236, %237
  %239 = lshr i64 %238, 1, !mcsema_real_eip !153
  %240 = shl i64 %236, 63, !mcsema_real_eip !153
  %241 = or i64 %239, %240
  %242 = lshr i64 %241, 1, !mcsema_real_eip !153
  %243 = shl i64 %239, 63, !mcsema_real_eip !153
  %244 = or i64 %242, %243
  %.tr67 = trunc i64 %239 to i8
  %245 = and i8 %.tr67, 1
  store volatile i8 %245, i8* %CF_write, align 1, !mcsema_real_eip !153
  store volatile i64 %244, i64* %RSI_write, align 8, !mcsema_real_eip !153
  store volatile i64 4196461, i64* %RIP_write, align 8, !mcsema_real_eip !154
  %246 = load i64, i64* %RSI_write, align 8, !mcsema_real_eip !154
  %247 = load i64, i64* %RDX_write, align 8, !mcsema_real_eip !154
  %248 = xor i64 %247, %246, !mcsema_real_eip !154
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !154
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !154
  %.lobit14 = lshr i64 %248, 63
  %249 = trunc i64 %.lobit14 to i8
  store volatile i8 %249, i8* %SF_write, align 1, !mcsema_real_eip !154
  %250 = icmp eq i64 %246, %247
  %251 = zext i1 %250 to i8, !mcsema_real_eip !154
  store volatile i8 %251, i8* %ZF_write, align 1, !mcsema_real_eip !154
  %252 = trunc i64 %248 to i8, !mcsema_real_eip !154
  %253 = tail call i8 @llvm.ctpop.i8(i8 %252), !mcsema_real_eip !154
  %254 = and i8 %253, 1
  %255 = xor i8 %254, 1
  store volatile i8 %255, i8* %PF_write, align 1, !mcsema_real_eip !154
  store volatile i64 %248, i64* %RSI_write, align 8, !mcsema_real_eip !154
  store volatile i64 4196464, i64* %RIP_write, align 8, !mcsema_real_eip !155
  %256 = load i64, i64* %RSI_write, align 8, !mcsema_real_eip !155
  %257 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !155
  %258 = sub i64 %256, %257, !mcsema_real_eip !155
  %259 = xor i64 %258, %256, !mcsema_real_eip !155
  %260 = xor i64 %259, %257, !mcsema_real_eip !155
  %261 = lshr i64 %260, 4
  %.tr16 = trunc i64 %261 to i8
  %262 = and i8 %.tr16, 1
  store volatile i8 %262, i8* %AF_write, align 1, !mcsema_real_eip !155
  %263 = trunc i64 %258 to i8, !mcsema_real_eip !155
  %264 = tail call i8 @llvm.ctpop.i8(i8 %263), !mcsema_real_eip !155
  %265 = and i8 %264, 1
  %266 = xor i8 %265, 1
  store volatile i8 %266, i8* %PF_write, align 1, !mcsema_real_eip !155
  %267 = icmp eq i64 %256, %257
  %268 = zext i1 %267 to i8, !mcsema_real_eip !155
  store volatile i8 %268, i8* %ZF_write, align 1, !mcsema_real_eip !155
  %.lobit17 = lshr i64 %258, 63
  %269 = trunc i64 %.lobit17 to i8
  store volatile i8 %269, i8* %SF_write, align 1, !mcsema_real_eip !155
  %270 = icmp ult i64 %256, %257, !mcsema_real_eip !155
  %271 = zext i1 %270 to i8, !mcsema_real_eip !155
  store volatile i8 %271, i8* %CF_write, align 1, !mcsema_real_eip !155
  %272 = xor i64 %257, %256, !mcsema_real_eip !155
  %273 = and i64 %259, %272, !mcsema_real_eip !155
  %.lobit18 = lshr i64 %273, 63
  %274 = trunc i64 %.lobit18 to i8
  store volatile i8 %274, i8* %OF_write, align 1, !mcsema_real_eip !155
  store volatile i64 %258, i64* %RSI_write, align 8, !mcsema_real_eip !155
  store volatile i64 4196467, i64* %RIP_write, align 8, !mcsema_real_eip !156
  %275 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !156
  %276 = shl i64 %275, 32
  %277 = load i8, i8* %OF_write, align 1, !mcsema_real_eip !156
  %278 = and i8 %277, 1
  store volatile i8 %278, i8* %OF_write, align 1, !mcsema_real_eip !156
  %279 = lshr i64 %275, 32
  %.tr20 = trunc i64 %279 to i8
  %280 = and i8 %.tr20, 1
  store volatile i8 %280, i8* %CF_write, align 1, !mcsema_real_eip !156
  %281 = icmp eq i64 %276, 0, !mcsema_real_eip !156
  %282 = zext i1 %281 to i8, !mcsema_real_eip !156
  store volatile i8 %282, i8* %ZF_write, align 1, !mcsema_real_eip !156
  %283 = lshr i64 %275, 31
  %.tr22 = trunc i64 %283 to i8
  %284 = and i8 %.tr22, 1
  store volatile i8 %284, i8* %SF_write, align 1, !mcsema_real_eip !156
  store volatile i8 1, i8* %PF_write, align 1, !mcsema_real_eip !156
  store volatile i8 1, i8* %PF_write, align 1, !mcsema_real_eip !156
  store volatile i64 %276, i64* %RAX_write, align 8, !mcsema_real_eip !156
  store volatile i64 4196471, i64* %RIP_write, align 8, !mcsema_real_eip !157
  %285 = load i64, i64* %RDI_write, align 8, !mcsema_real_eip !157
  %286 = lshr i64 %285, 1, !mcsema_real_eip !157
  %287 = shl i64 %285, 63, !mcsema_real_eip !157
  %288 = or i64 %286, %287
  %289 = lshr i64 %288, 1, !mcsema_real_eip !157
  %290 = shl i64 %286, 63, !mcsema_real_eip !157
  %291 = or i64 %289, %290
  %292 = lshr i64 %291, 1, !mcsema_real_eip !157
  %293 = shl i64 %289, 63, !mcsema_real_eip !157
  %294 = or i64 %292, %293
  %295 = lshr i64 %294, 1, !mcsema_real_eip !157
  %296 = shl i64 %292, 63, !mcsema_real_eip !157
  %297 = or i64 %295, %296
  %298 = lshr i64 %297, 1, !mcsema_real_eip !157
  %299 = shl i64 %295, 63, !mcsema_real_eip !157
  %300 = or i64 %298, %299
  %301 = lshr i64 %300, 1, !mcsema_real_eip !157
  %302 = shl i64 %298, 63, !mcsema_real_eip !157
  %303 = or i64 %301, %302
  %304 = lshr i64 %303, 1, !mcsema_real_eip !157
  %305 = shl i64 %301, 63, !mcsema_real_eip !157
  %306 = or i64 %304, %305
  %307 = lshr i64 %306, 1, !mcsema_real_eip !157
  %308 = shl i64 %304, 63, !mcsema_real_eip !157
  %309 = or i64 %307, %308
  %310 = lshr i64 %309, 1, !mcsema_real_eip !157
  %311 = shl i64 %307, 63, !mcsema_real_eip !157
  %312 = or i64 %310, %311
  %313 = lshr i64 %312, 1, !mcsema_real_eip !157
  %314 = shl i64 %310, 63, !mcsema_real_eip !157
  %315 = or i64 %313, %314
  %316 = lshr i64 %315, 1, !mcsema_real_eip !157
  %317 = shl i64 %313, 63, !mcsema_real_eip !157
  %318 = or i64 %316, %317
  %319 = lshr i64 %318, 1, !mcsema_real_eip !157
  %320 = shl i64 %316, 63, !mcsema_real_eip !157
  %321 = or i64 %319, %320
  %322 = lshr i64 %321, 1, !mcsema_real_eip !157
  %323 = shl i64 %319, 63, !mcsema_real_eip !157
  %324 = or i64 %322, %323
  %325 = lshr i64 %324, 1, !mcsema_real_eip !157
  %326 = shl i64 %322, 63, !mcsema_real_eip !157
  %327 = or i64 %325, %326
  %328 = lshr i64 %327, 1, !mcsema_real_eip !157
  %329 = shl i64 %325, 63, !mcsema_real_eip !157
  %330 = or i64 %328, %329
  %331 = lshr i64 %330, 1, !mcsema_real_eip !157
  %332 = shl i64 %328, 63, !mcsema_real_eip !157
  %333 = or i64 %331, %332
  %334 = lshr i64 %333, 1, !mcsema_real_eip !157
  %335 = shl i64 %331, 63, !mcsema_real_eip !157
  %336 = or i64 %334, %335
  %337 = lshr i64 %336, 1, !mcsema_real_eip !157
  %338 = shl i64 %334, 63, !mcsema_real_eip !157
  %339 = or i64 %337, %338
  %340 = lshr i64 %339, 1, !mcsema_real_eip !157
  %341 = shl i64 %337, 63, !mcsema_real_eip !157
  %342 = or i64 %340, %341
  %.tr68 = trunc i64 %337 to i8
  %343 = and i8 %.tr68, 1
  store volatile i8 %343, i8* %CF_write, align 1, !mcsema_real_eip !157
  store volatile i64 %342, i64* %RDI_write, align 8, !mcsema_real_eip !157
  store volatile i64 4196475, i64* %RIP_write, align 8, !mcsema_real_eip !158
  %344 = load i64, i64* %RDI_write, align 8, !mcsema_real_eip !158
  %345 = load i64, i64* %RDX_write, align 8, !mcsema_real_eip !158
  %346 = xor i64 %345, %344, !mcsema_real_eip !158
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !158
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !158
  %.lobit23 = lshr i64 %346, 63
  %347 = trunc i64 %.lobit23 to i8
  store volatile i8 %347, i8* %SF_write, align 1, !mcsema_real_eip !158
  %348 = icmp eq i64 %344, %345
  %349 = zext i1 %348 to i8, !mcsema_real_eip !158
  store volatile i8 %349, i8* %ZF_write, align 1, !mcsema_real_eip !158
  %350 = trunc i64 %346 to i8, !mcsema_real_eip !158
  %351 = tail call i8 @llvm.ctpop.i8(i8 %350), !mcsema_real_eip !158
  %352 = and i8 %351, 1
  %353 = xor i8 %352, 1
  store volatile i8 %353, i8* %PF_write, align 1, !mcsema_real_eip !158
  store volatile i64 %346, i64* %RDI_write, align 8, !mcsema_real_eip !158
  store volatile i64 4196478, i64* %RIP_write, align 8, !mcsema_real_eip !159
  %354 = load i64, i64* %RDI_write, align 8, !mcsema_real_eip !159
  %355 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !159
  %356 = add i64 %355, %354, !mcsema_real_eip !159
  %357 = xor i64 %356, %354, !mcsema_real_eip !159
  %358 = xor i64 %357, %355, !mcsema_real_eip !159
  %359 = lshr i64 %358, 4
  %.tr25 = trunc i64 %359 to i8
  %360 = and i8 %.tr25, 1
  store volatile i8 %360, i8* %AF_write, align 1, !mcsema_real_eip !159
  %.lobit26 = lshr i64 %356, 63
  %361 = trunc i64 %.lobit26 to i8
  store volatile i8 %361, i8* %SF_write, align 1, !mcsema_real_eip !159
  %362 = icmp eq i64 %356, 0, !mcsema_real_eip !159
  %363 = zext i1 %362 to i8, !mcsema_real_eip !159
  store volatile i8 %363, i8* %ZF_write, align 1, !mcsema_real_eip !159
  %364 = xor i64 %354, -9223372036854775808, !mcsema_real_eip !159
  %365 = xor i64 %364, %355, !mcsema_real_eip !159
  %366 = and i64 %357, %365, !mcsema_real_eip !159
  %.lobit27 = lshr i64 %366, 63
  %367 = trunc i64 %.lobit27 to i8
  store volatile i8 %367, i8* %OF_write, align 1, !mcsema_real_eip !159
  %368 = trunc i64 %356 to i8, !mcsema_real_eip !159
  %369 = tail call i8 @llvm.ctpop.i8(i8 %368), !mcsema_real_eip !159
  %370 = and i8 %369, 1
  %371 = xor i8 %370, 1
  store volatile i8 %371, i8* %PF_write, align 1, !mcsema_real_eip !159
  %372 = icmp ult i64 %356, %354, !mcsema_real_eip !159
  %373 = zext i1 %372 to i8, !mcsema_real_eip !159
  store volatile i8 %373, i8* %CF_write, align 1, !mcsema_real_eip !159
  store volatile i64 %356, i64* %RDI_write, align 8, !mcsema_real_eip !159
  store volatile i64 4196481, i64* %RIP_write, align 8, !mcsema_real_eip !160
  %374 = load i64, i64* %R10_write, align 8, !mcsema_real_eip !160
  %375 = lshr i64 %374, 63, !mcsema_real_eip !160
  %376 = shl i64 %374, 1
  %377 = or i64 %376, %375
  %378 = lshr i64 %374, 62
  %379 = and i64 %378, 1
  %380 = shl i64 %377, 1
  %381 = or i64 %380, %379
  %382 = lshr i64 %374, 61
  %383 = and i64 %382, 1
  %384 = shl i64 %381, 1
  %385 = or i64 %384, %383
  %386 = lshr i64 %374, 60
  %387 = and i64 %386, 1
  %388 = shl i64 %385, 1
  %389 = or i64 %388, %387
  %390 = lshr i64 %374, 59
  %391 = and i64 %390, 1
  %392 = shl i64 %389, 1
  %393 = or i64 %392, %391
  %394 = lshr i64 %374, 58
  %395 = and i64 %394, 1
  %396 = shl i64 %393, 1
  %397 = or i64 %396, %395
  %398 = lshr i64 %374, 57
  %399 = and i64 %398, 1
  %400 = shl i64 %397, 1
  %401 = or i64 %400, %399
  %402 = lshr i64 %374, 56
  %403 = and i64 %402, 1
  %404 = shl i64 %401, 1
  %405 = or i64 %404, %403
  %406 = lshr i64 %374, 55
  %407 = and i64 %406, 1
  %408 = shl i64 %405, 1
  %409 = or i64 %408, %407
  %410 = lshr i64 %374, 54
  %411 = and i64 %410, 1
  %412 = shl i64 %409, 1
  %413 = or i64 %412, %411
  %414 = lshr i64 %374, 53
  %415 = and i64 %414, 1
  %416 = shl i64 %413, 1
  %417 = or i64 %416, %415
  %418 = lshr i64 %374, 52
  %419 = and i64 %418, 1
  %420 = shl i64 %417, 1
  %421 = or i64 %420, %419
  %422 = lshr i64 %374, 51
  %423 = and i64 %422, 1
  %424 = shl i64 %421, 1
  %425 = or i64 %424, %423
  %426 = lshr i64 %374, 50
  %427 = and i64 %426, 1
  %428 = shl i64 %425, 1
  %429 = or i64 %428, %427
  %430 = lshr i64 %374, 49
  %431 = and i64 %430, 1
  %432 = shl i64 %429, 1
  %433 = or i64 %432, %431
  %434 = lshr i64 %374, 48
  %435 = and i64 %434, 1
  %436 = shl i64 %433, 1
  %437 = or i64 %436, %435
  %438 = lshr i64 %374, 47
  %439 = and i64 %438, 1
  %440 = shl i64 %437, 1
  %441 = or i64 %440, %439
  %442 = lshr i64 %374, 46
  %443 = and i64 %442, 1
  %444 = shl i64 %441, 1
  %445 = or i64 %444, %443
  %446 = lshr i64 %374, 45
  %447 = and i64 %446, 1
  %448 = shl i64 %445, 1
  %449 = or i64 %448, %447
  %.tr28 = trunc i64 %447 to i8
  store volatile i8 %.tr28, i8* %CF_write, align 1, !mcsema_real_eip !160
  store volatile i8 1, i8* %OF_write, align 1, !mcsema_real_eip !160
  store volatile i64 %449, i64* %R10_write, align 8, !mcsema_real_eip !160
  store volatile i64 4196485, i64* %RIP_write, align 8, !mcsema_real_eip !161
  %450 = load i64, i64* %RDX_write, align 8, !mcsema_real_eip !161
  %451 = load i64, i64* %R10_write, align 8, !mcsema_real_eip !161
  %452 = xor i64 %451, %450, !mcsema_real_eip !161
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !161
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !161
  %.lobit29 = lshr i64 %452, 63
  %453 = trunc i64 %.lobit29 to i8
  store volatile i8 %453, i8* %SF_write, align 1, !mcsema_real_eip !161
  %454 = icmp eq i64 %450, %451
  %455 = zext i1 %454 to i8, !mcsema_real_eip !161
  store volatile i8 %455, i8* %ZF_write, align 1, !mcsema_real_eip !161
  %456 = trunc i64 %452 to i8, !mcsema_real_eip !161
  %457 = tail call i8 @llvm.ctpop.i8(i8 %456), !mcsema_real_eip !161
  %458 = and i8 %457, 1
  %459 = xor i8 %458, 1
  store volatile i8 %459, i8* %PF_write, align 1, !mcsema_real_eip !161
  store volatile i64 %452, i64* %RDX_write, align 8, !mcsema_real_eip !161
  store volatile i64 4196488, i64* %RIP_write, align 8, !mcsema_real_eip !162
  %460 = load i64, i64* %RDX_write, align 8, !mcsema_real_eip !162
  %461 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !162
  %462 = sub i64 %460, %461, !mcsema_real_eip !162
  %463 = xor i64 %462, %460, !mcsema_real_eip !162
  %464 = xor i64 %463, %461, !mcsema_real_eip !162
  %465 = lshr i64 %464, 4
  %.tr31 = trunc i64 %465 to i8
  %466 = and i8 %.tr31, 1
  store volatile i8 %466, i8* %AF_write, align 1, !mcsema_real_eip !162
  %467 = trunc i64 %462 to i8, !mcsema_real_eip !162
  %468 = tail call i8 @llvm.ctpop.i8(i8 %467), !mcsema_real_eip !162
  %469 = and i8 %468, 1
  %470 = xor i8 %469, 1
  store volatile i8 %470, i8* %PF_write, align 1, !mcsema_real_eip !162
  %471 = icmp eq i64 %460, %461
  %472 = zext i1 %471 to i8, !mcsema_real_eip !162
  store volatile i8 %472, i8* %ZF_write, align 1, !mcsema_real_eip !162
  %.lobit32 = lshr i64 %462, 63
  %473 = trunc i64 %.lobit32 to i8
  store volatile i8 %473, i8* %SF_write, align 1, !mcsema_real_eip !162
  %474 = icmp ult i64 %460, %461, !mcsema_real_eip !162
  %475 = zext i1 %474 to i8, !mcsema_real_eip !162
  store volatile i8 %475, i8* %CF_write, align 1, !mcsema_real_eip !162
  %476 = xor i64 %461, %460, !mcsema_real_eip !162
  %477 = and i64 %463, %476, !mcsema_real_eip !162
  %.lobit33 = lshr i64 %477, 63
  %478 = trunc i64 %.lobit33 to i8
  store volatile i8 %478, i8* %OF_write, align 1, !mcsema_real_eip !162
  store volatile i64 %462, i64* %RDX_write, align 8, !mcsema_real_eip !162
  store volatile i64 4196491, i64* %RIP_write, align 8, !mcsema_real_eip !163
  %479 = load i64, i64* %RDX_write, align 8, !mcsema_real_eip !163
  store volatile i64 %479, i64* %R10_write, align 8, !mcsema_real_eip !163
  store volatile i64 4196494, i64* %RIP_write, align 8, !mcsema_real_eip !164
  %480 = load i64, i64* %R8_write, align 8, !mcsema_real_eip !164
  %481 = add i64 %480, 1, !mcsema_real_eip !164
  %482 = xor i64 %481, %480, !mcsema_real_eip !164
  %483 = lshr i64 %482, 4
  %.tr35 = trunc i64 %483 to i8
  %484 = and i8 %.tr35, 1
  store volatile i8 %484, i8* %AF_write, align 1, !mcsema_real_eip !164
  %.lobit36 = lshr i64 %481, 63
  %485 = trunc i64 %.lobit36 to i8
  store volatile i8 %485, i8* %SF_write, align 1, !mcsema_real_eip !164
  %486 = icmp eq i64 %481, 0, !mcsema_real_eip !164
  %487 = zext i1 %486 to i8, !mcsema_real_eip !164
  store volatile i8 %487, i8* %ZF_write, align 1, !mcsema_real_eip !164
  %488 = xor i64 %480, -9223372036854775808, !mcsema_real_eip !164
  %489 = and i64 %482, %488, !mcsema_real_eip !164
  %.lobit37 = lshr i64 %489, 63
  %490 = trunc i64 %.lobit37 to i8
  store volatile i8 %490, i8* %OF_write, align 1, !mcsema_real_eip !164
  %491 = trunc i64 %481 to i8, !mcsema_real_eip !164
  %492 = tail call i8 @llvm.ctpop.i8(i8 %491), !mcsema_real_eip !164
  %493 = and i8 %492, 1
  %494 = xor i8 %493, 1
  store volatile i8 %494, i8* %PF_write, align 1, !mcsema_real_eip !164
  %495 = icmp eq i64 %480, -1
  %496 = zext i1 %495 to i8, !mcsema_real_eip !164
  store volatile i8 %496, i8* %CF_write, align 1, !mcsema_real_eip !164
  store volatile i64 %481, i64* %R8_write, align 8, !mcsema_real_eip !164
  store volatile i64 4196498, i64* %RIP_write, align 8, !mcsema_real_eip !165
  %497 = load i64, i64* %R8_write, align 8, !mcsema_real_eip !165
  %498 = add i64 %497, -4
  %499 = xor i64 %498, %497, !mcsema_real_eip !165
  %500 = lshr i64 %499, 4
  %.tr39 = trunc i64 %500 to i8
  %501 = and i8 %.tr39, 1
  store volatile i8 %501, i8* %AF_write, align 1, !mcsema_real_eip !165
  %502 = trunc i64 %498 to i8, !mcsema_real_eip !165
  %503 = tail call i8 @llvm.ctpop.i8(i8 %502), !mcsema_real_eip !165
  %504 = and i8 %503, 1
  %505 = xor i8 %504, 1
  store volatile i8 %505, i8* %PF_write, align 1, !mcsema_real_eip !165
  %506 = icmp eq i64 %498, 0, !mcsema_real_eip !165
  %507 = zext i1 %506 to i8, !mcsema_real_eip !165
  store volatile i8 %507, i8* %ZF_write, align 1, !mcsema_real_eip !165
  %.lobit40 = lshr i64 %498, 63
  %508 = trunc i64 %.lobit40 to i8
  store volatile i8 %508, i8* %SF_write, align 1, !mcsema_real_eip !165
  %509 = icmp ult i64 %497, 4, !mcsema_real_eip !165
  %510 = zext i1 %509 to i8, !mcsema_real_eip !165
  store volatile i8 %510, i8* %CF_write, align 1, !mcsema_real_eip !165
  %511 = and i64 %499, %497, !mcsema_real_eip !165
  %.lobit41 = lshr i64 %511, 63
  %512 = trunc i64 %.lobit41 to i8
  store volatile i8 %512, i8* %OF_write, align 1, !mcsema_real_eip !165
  store volatile i64 4196502, i64* %RIP_write, align 8, !mcsema_real_eip !166
  %513 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !166
  %514 = and i8 %513, 1
  %515 = icmp eq i8 %514, 0
  br i1 %515, label %block_400843, label %block_400898, !mcsema_real_eip !166

block_400898:                                     ; preds = %block_400843
  store volatile i64 4196504, i64* %RIP_write, align 8, !mcsema_real_eip !167
  store volatile i64 727853590754638760, i64* %RAX_write, align 8, !mcsema_real_eip !167
  store volatile i64 4196514, i64* %RIP_write, align 8, !mcsema_real_eip !168
  %516 = load i64, i64* %RCX_write, align 8, !mcsema_real_eip !168
  %517 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !168
  %518 = sub i64 %516, %517, !mcsema_real_eip !168
  %519 = xor i64 %518, %516, !mcsema_real_eip !168
  %520 = xor i64 %519, %517, !mcsema_real_eip !168
  %521 = lshr i64 %520, 4
  %.tr43 = trunc i64 %521 to i8
  %522 = and i8 %.tr43, 1
  store volatile i8 %522, i8* %AF_write, align 1, !mcsema_real_eip !168
  %523 = trunc i64 %518 to i8, !mcsema_real_eip !168
  %524 = tail call i8 @llvm.ctpop.i8(i8 %523), !mcsema_real_eip !168
  %525 = and i8 %524, 1
  %526 = xor i8 %525, 1
  store volatile i8 %526, i8* %PF_write, align 1, !mcsema_real_eip !168
  %527 = icmp eq i64 %516, %517
  %528 = zext i1 %527 to i8, !mcsema_real_eip !168
  store volatile i8 %528, i8* %ZF_write, align 1, !mcsema_real_eip !168
  %.lobit44 = lshr i64 %518, 63
  %529 = trunc i64 %.lobit44 to i8
  store volatile i8 %529, i8* %SF_write, align 1, !mcsema_real_eip !168
  %530 = icmp ult i64 %516, %517, !mcsema_real_eip !168
  %531 = zext i1 %530 to i8, !mcsema_real_eip !168
  store volatile i8 %531, i8* %CF_write, align 1, !mcsema_real_eip !168
  %532 = xor i64 %517, %516, !mcsema_real_eip !168
  %533 = and i64 %519, %532, !mcsema_real_eip !168
  %.lobit45 = lshr i64 %533, 63
  %534 = trunc i64 %.lobit45 to i8
  store volatile i8 %534, i8* %OF_write, align 1, !mcsema_real_eip !168
  store volatile i64 4196517, i64* %RIP_write, align 8, !mcsema_real_eip !169
  %535 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !169
  %536 = and i8 %535, 1
  %537 = icmp eq i8 %536, 0
  br i1 %537, label %block_4008ea, label %block_4008a7, !mcsema_real_eip !169

block_4008a7:                                     ; preds = %block_400898
  store volatile i64 4196519, i64* %RIP_write, align 8, !mcsema_real_eip !170
  store volatile i64 -6974870607190376612, i64* %RAX_write, align 8, !mcsema_real_eip !170
  store volatile i64 4196529, i64* %RIP_write, align 8, !mcsema_real_eip !171
  %538 = load i64, i64* %RSI_write, align 8, !mcsema_real_eip !171
  %539 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !171
  %540 = sub i64 %538, %539, !mcsema_real_eip !171
  %541 = xor i64 %540, %538, !mcsema_real_eip !171
  %542 = xor i64 %541, %539, !mcsema_real_eip !171
  %543 = lshr i64 %542, 4
  %.tr47 = trunc i64 %543 to i8
  %544 = and i8 %.tr47, 1
  store volatile i8 %544, i8* %AF_write, align 1, !mcsema_real_eip !171
  %545 = trunc i64 %540 to i8, !mcsema_real_eip !171
  %546 = tail call i8 @llvm.ctpop.i8(i8 %545), !mcsema_real_eip !171
  %547 = and i8 %546, 1
  %548 = xor i8 %547, 1
  store volatile i8 %548, i8* %PF_write, align 1, !mcsema_real_eip !171
  %549 = icmp eq i64 %538, %539
  %550 = zext i1 %549 to i8, !mcsema_real_eip !171
  store volatile i8 %550, i8* %ZF_write, align 1, !mcsema_real_eip !171
  %.lobit48 = lshr i64 %540, 63
  %551 = trunc i64 %.lobit48 to i8
  store volatile i8 %551, i8* %SF_write, align 1, !mcsema_real_eip !171
  %552 = icmp ult i64 %538, %539, !mcsema_real_eip !171
  %553 = zext i1 %552 to i8, !mcsema_real_eip !171
  store volatile i8 %553, i8* %CF_write, align 1, !mcsema_real_eip !171
  %554 = xor i64 %539, %538, !mcsema_real_eip !171
  %555 = and i64 %541, %554, !mcsema_real_eip !171
  %.lobit49 = lshr i64 %555, 63
  %556 = trunc i64 %.lobit49 to i8
  store volatile i8 %556, i8* %OF_write, align 1, !mcsema_real_eip !171
  store volatile i64 4196532, i64* %RIP_write, align 8, !mcsema_real_eip !172
  %557 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !172
  %558 = and i8 %557, 1
  %559 = icmp eq i8 %558, 0
  br i1 %559, label %block_4008ea, label %block_4008b6, !mcsema_real_eip !172

block_4008b6:                                     ; preds = %block_4008a7
  store volatile i64 4196534, i64* %RIP_write, align 8, !mcsema_real_eip !173
  store volatile i64 5596835378558450713, i64* %RAX_write, align 8, !mcsema_real_eip !173
  store volatile i64 4196544, i64* %RIP_write, align 8, !mcsema_real_eip !174
  %560 = load i64, i64* %RDI_write, align 8, !mcsema_real_eip !174
  %561 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !174
  %562 = sub i64 %560, %561, !mcsema_real_eip !174
  %563 = xor i64 %562, %560, !mcsema_real_eip !174
  %564 = xor i64 %563, %561, !mcsema_real_eip !174
  %565 = lshr i64 %564, 4
  %.tr51 = trunc i64 %565 to i8
  %566 = and i8 %.tr51, 1
  store volatile i8 %566, i8* %AF_write, align 1, !mcsema_real_eip !174
  %567 = trunc i64 %562 to i8, !mcsema_real_eip !174
  %568 = tail call i8 @llvm.ctpop.i8(i8 %567), !mcsema_real_eip !174
  %569 = and i8 %568, 1
  %570 = xor i8 %569, 1
  store volatile i8 %570, i8* %PF_write, align 1, !mcsema_real_eip !174
  %571 = icmp eq i64 %560, %561
  %572 = zext i1 %571 to i8, !mcsema_real_eip !174
  store volatile i8 %572, i8* %ZF_write, align 1, !mcsema_real_eip !174
  %.lobit52 = lshr i64 %562, 63
  %573 = trunc i64 %.lobit52 to i8
  store volatile i8 %573, i8* %SF_write, align 1, !mcsema_real_eip !174
  %574 = icmp ult i64 %560, %561, !mcsema_real_eip !174
  %575 = zext i1 %574 to i8, !mcsema_real_eip !174
  store volatile i8 %575, i8* %CF_write, align 1, !mcsema_real_eip !174
  %576 = xor i64 %561, %560, !mcsema_real_eip !174
  %577 = and i64 %563, %576, !mcsema_real_eip !174
  %.lobit53 = lshr i64 %577, 63
  %578 = trunc i64 %.lobit53 to i8
  store volatile i8 %578, i8* %OF_write, align 1, !mcsema_real_eip !174
  store volatile i64 4196547, i64* %RIP_write, align 8, !mcsema_real_eip !175
  %579 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !175
  %580 = and i8 %579, 1
  %581 = icmp eq i8 %580, 0
  br i1 %581, label %block_4008ea, label %block_4008c5, !mcsema_real_eip !175

block_4008c5:                                     ; preds = %block_4008b6
  store volatile i64 4196549, i64* %RIP_write, align 8, !mcsema_real_eip !176
  store volatile i64 -4274187294020637041, i64* %RAX_write, align 8, !mcsema_real_eip !176
  store volatile i64 4196559, i64* %RIP_write, align 8, !mcsema_real_eip !177
  %582 = load i64, i64* %RDX_write, align 8, !mcsema_real_eip !177
  %583 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !177
  %584 = sub i64 %582, %583, !mcsema_real_eip !177
  %585 = xor i64 %584, %582, !mcsema_real_eip !177
  %586 = xor i64 %585, %583, !mcsema_real_eip !177
  %587 = lshr i64 %586, 4
  %.tr55 = trunc i64 %587 to i8
  %588 = and i8 %.tr55, 1
  store volatile i8 %588, i8* %AF_write, align 1, !mcsema_real_eip !177
  %589 = trunc i64 %584 to i8, !mcsema_real_eip !177
  %590 = tail call i8 @llvm.ctpop.i8(i8 %589), !mcsema_real_eip !177
  %591 = and i8 %590, 1
  %592 = xor i8 %591, 1
  store volatile i8 %592, i8* %PF_write, align 1, !mcsema_real_eip !177
  %593 = icmp eq i64 %582, %583
  %594 = zext i1 %593 to i8, !mcsema_real_eip !177
  store volatile i8 %594, i8* %ZF_write, align 1, !mcsema_real_eip !177
  %.lobit56 = lshr i64 %584, 63
  %595 = trunc i64 %.lobit56 to i8
  store volatile i8 %595, i8* %SF_write, align 1, !mcsema_real_eip !177
  %596 = icmp ult i64 %582, %583, !mcsema_real_eip !177
  %597 = zext i1 %596 to i8, !mcsema_real_eip !177
  store volatile i8 %597, i8* %CF_write, align 1, !mcsema_real_eip !177
  %598 = xor i64 %583, %582, !mcsema_real_eip !177
  %599 = and i64 %585, %598, !mcsema_real_eip !177
  %.lobit57 = lshr i64 %599, 63
  %600 = trunc i64 %.lobit57 to i8
  store volatile i8 %600, i8* %OF_write, align 1, !mcsema_real_eip !177
  store volatile i64 4196562, i64* %RIP_write, align 8, !mcsema_real_eip !178
  %601 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !178
  %602 = and i8 %601, 1
  %603 = icmp eq i8 %602, 0
  br i1 %603, label %block_4008ea, label %block_4008d4, !mcsema_real_eip !178

block_4008d4:                                     ; preds = %block_4008c5
  store volatile i64 4196564, i64* %RIP_write, align 8, !mcsema_real_eip !179
  store volatile i64 zext (i32 add (i32 ptrtoint (%0* @data_4009a0 to i32), i32 272) to i64), i64* %RDI_write, align 8, !mcsema_real_eip !179
  store volatile i64 4196569, i64* %RIP_write, align 8, !mcsema_real_eip !180
  %604 = load i64, i64* %RDI_write, align 8, !mcsema_real_eip !180
  %605 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !180
  %606 = add i64 %605, -8
  %607 = inttoptr i64 %606 to i64*, !mcsema_real_eip !180
  store i64 -2415393069852865332, i64* %607, align 8, !mcsema_real_eip !180
  store volatile i64 %606, i64* %RSP_write, align 8, !mcsema_real_eip !180
  %608 = tail call x86_64_sysvcc i64 @_puts(i64 %604), !mcsema_real_eip !180
  store volatile i64 %608, i64* %RAX_write, align 8, !mcsema_real_eip !180
  store volatile i64 4196574, i64* %RIP_write, align 8, !mcsema_real_eip !181
  store volatile i64 zext (i32 add (i32 ptrtoint (%0* @data_4009a0 to i32), i32 64) to i64), i64* %RDI_write, align 8, !mcsema_real_eip !181
  store volatile i64 4196579, i64* %RIP_write, align 8, !mcsema_real_eip !182
  %609 = load i64, i64* %RDI_write, align 8, !mcsema_real_eip !182
  %610 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !182
  %611 = add i64 %610, -8
  %612 = inttoptr i64 %611 to i64*, !mcsema_real_eip !182
  store i64 -2415393069852865332, i64* %612, align 8, !mcsema_real_eip !182
  store volatile i64 %611, i64* %RSP_write, align 8, !mcsema_real_eip !182
  %613 = tail call x86_64_sysvcc i64 @_puts(i64 %609), !mcsema_real_eip !182
  store volatile i64 %613, i64* %RAX_write, align 8, !mcsema_real_eip !182
  store volatile i64 4196584, i64* %RIP_write, align 8, !mcsema_real_eip !183
  br label %block_4008f4, !mcsema_real_eip !183

block_4008ea:                                     ; preds = %block_4008c5, %block_4008b6, %block_4008a7, %block_400898, %block_40080c
  store volatile i64 4196586, i64* %RIP_write, align 8, !mcsema_real_eip !184
  store volatile i64 zext (i32 add (i32 ptrtoint (%0* @data_4009a0 to i32), i32 301) to i64), i64* %RDI_write, align 8, !mcsema_real_eip !184
  store volatile i64 4196591, i64* %RIP_write, align 8, !mcsema_real_eip !185
  %614 = load i64, i64* %RDI_write, align 8, !mcsema_real_eip !185
  %615 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !185
  %616 = add i64 %615, -8
  %617 = inttoptr i64 %616 to i64*, !mcsema_real_eip !185
  store i64 -2415393069852865332, i64* %617, align 8, !mcsema_real_eip !185
  store volatile i64 %616, i64* %RSP_write, align 8, !mcsema_real_eip !185
  %618 = tail call x86_64_sysvcc i64 @_puts(i64 %614), !mcsema_real_eip !185
  store volatile i64 %618, i64* %RAX_write, align 8, !mcsema_real_eip !185
  br label %block_4008f4, !mcsema_real_eip !186

block_4008f4:                                     ; preds = %block_4008ea, %block_4008d4
  store volatile i64 4196596, i64* %RIP_write, align 8, !mcsema_real_eip !186
  %619 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !186
  %620 = add i64 %619, 40, !mcsema_real_eip !186
  %621 = inttoptr i64 %620 to i64*, !mcsema_real_eip !186
  %622 = load i64, i64* %621, align 8, !mcsema_real_eip !186
  store volatile i64 %622, i64* %RDI_write, align 8, !mcsema_real_eip !186
  store volatile i64 4196601, i64* %RIP_write, align 8, !mcsema_real_eip !187
  %623 = load i64, i64* %RDI_write, align 8, !mcsema_real_eip !187
  %624 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !187
  %625 = add i64 %624, -8
  %626 = inttoptr i64 %625 to i64*, !mcsema_real_eip !187
  store i64 -2415393069852865332, i64* %626, align 8, !mcsema_real_eip !187
  store volatile i64 %625, i64* %RSP_write, align 8, !mcsema_real_eip !187
  %627 = tail call x86_64_sysvcc i64 @_free(i64 %623), !mcsema_real_eip !187
  store volatile i64 %627, i64* %RAX_write, align 8, !mcsema_real_eip !187
  store volatile i64 4196606, i64* %RIP_write, align 8, !mcsema_real_eip !188
  store volatile i64 0, i64* %RAX_write, align 8, !mcsema_real_eip !188
  store volatile i64 4196611, i64* %RIP_write, align 8, !mcsema_real_eip !189
  %628 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !189
  %629 = add i64 %628, 56, !mcsema_real_eip !189
  %630 = xor i64 %629, %628, !mcsema_real_eip !189
  %631 = lshr i64 %630, 4
  %.lobit58 = and i64 %631, 1
  %632 = xor i64 %.lobit58, 1
  %633 = trunc i64 %632 to i8
  store volatile i8 %633, i8* %AF_write, align 1, !mcsema_real_eip !189
  %.lobit59 = lshr i64 %629, 63
  %634 = trunc i64 %.lobit59 to i8
  store volatile i8 %634, i8* %SF_write, align 1, !mcsema_real_eip !189
  %635 = icmp eq i64 %629, 0, !mcsema_real_eip !189
  %636 = zext i1 %635 to i8, !mcsema_real_eip !189
  store volatile i8 %636, i8* %ZF_write, align 1, !mcsema_real_eip !189
  %637 = xor i64 %628, -9223372036854775808, !mcsema_real_eip !189
  %638 = and i64 %630, %637, !mcsema_real_eip !189
  %.lobit60 = lshr i64 %638, 63
  %639 = trunc i64 %.lobit60 to i8
  store volatile i8 %639, i8* %OF_write, align 1, !mcsema_real_eip !189
  %640 = trunc i64 %629 to i8, !mcsema_real_eip !189
  %641 = tail call i8 @llvm.ctpop.i8(i8 %640), !mcsema_real_eip !189
  %642 = and i8 %641, 1
  %643 = xor i8 %642, 1
  store volatile i8 %643, i8* %PF_write, align 1, !mcsema_real_eip !189
  %644 = icmp ugt i64 %628, -57
  %645 = zext i1 %644 to i8, !mcsema_real_eip !189
  store volatile i8 %645, i8* %CF_write, align 1, !mcsema_real_eip !189
  store volatile i64 %629, i64* %RSP_write, align 8, !mcsema_real_eip !189
  store volatile i64 4196615, i64* %RIP_write, align 8, !mcsema_real_eip !190
  %646 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !190
  %647 = add i64 %646, 8, !mcsema_real_eip !190
  %648 = inttoptr i64 %646 to i64*, !mcsema_real_eip !190
  %649 = load i64, i64* %648, align 8, !mcsema_real_eip !190
  store volatile i64 %649, i64* %RIP_write, align 8, !mcsema_real_eip !190
  store volatile i64 %647, i64* %RSP_write, align 8, !mcsema_real_eip !190
  ret void, !mcsema_real_eip !190

.preheader:                                       ; preds = %.preheader.preheader, %.preheader
  %650 = load i64, i64* %RDI_write, align 8, !mcsema_real_eip !131
  %651 = inttoptr i64 %650 to i8*, !mcsema_real_eip !131
  %652 = load i8, i8* %651, align 1, !mcsema_real_eip !131
  %653 = load i64, i64* %RAX_write, align 8, !mcsema_real_eip !131
  %654 = trunc i64 %653 to i8, !mcsema_real_eip !131
  %655 = sub i8 %654, %652, !mcsema_real_eip !131
  %656 = tail call i8 @llvm.ctpop.i8(i8 %655), !mcsema_real_eip !131
  %657 = and i8 %656, 1
  %658 = xor i8 %657, 1
  store volatile i8 %658, i8* %PF_write, align 1, !mcsema_real_eip !131
  %659 = icmp eq i8 %654, %652
  %660 = zext i1 %659 to i8, !mcsema_real_eip !131
  store volatile i8 %660, i8* %ZF_write, align 1, !mcsema_real_eip !131
  %.lobit61 = lshr i8 %655, 7
  store volatile i8 %.lobit61, i8* %SF_write, align 1, !mcsema_real_eip !131
  %661 = icmp ult i8 %654, %652, !mcsema_real_eip !131
  %662 = zext i1 %661 to i8, !mcsema_real_eip !131
  store volatile i8 %662, i8* %CF_write, align 1, !mcsema_real_eip !131
  %663 = xor i8 %655, %654, !mcsema_real_eip !131
  %664 = xor i8 %663, %652, !mcsema_real_eip !131
  %665 = lshr i8 %664, 4
  %.lobit62 = and i8 %665, 1
  store volatile i8 %.lobit62, i8* %AF_write, align 1, !mcsema_real_eip !131
  %666 = xor i8 %654, %652, !mcsema_real_eip !131
  %667 = and i8 %663, %666, !mcsema_real_eip !131
  %.lobit63 = lshr i8 %667, 7
  store volatile i8 %.lobit63, i8* %OF_write, align 1, !mcsema_real_eip !131
  %668 = load i8, i8* %DF_write, align 1, !mcsema_real_eip !131
  %669 = and i8 %668, 1
  %670 = zext i8 %669 to i64
  %671 = shl nuw nsw i64 %670, 1
  %672 = xor i64 %671, 2
  %673 = add i64 %650, -1
  %674 = add i64 %673, %672
  store volatile i64 %674, i64* %RDI_write, align 8, !mcsema_real_eip !131
  %675 = load i64, i64* %RCX_write, align 8, !mcsema_real_eip !131
  %676 = add i64 %675, -1
  store volatile i64 %676, i64* %RCX_write, align 8, !mcsema_real_eip !131
  %677 = icmp eq i64 %676, 0, !mcsema_real_eip !131
  %678 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !131
  %679 = and i8 %678, 1
  %680 = icmp ne i8 %679, 0
  %681 = or i1 %677, %680, !mcsema_real_eip !131
  br i1 %681, label %.loopexit.loopexit, label %.preheader, !mcsema_real_eip !131

.loopexit.loopexit:                               ; preds = %.preheader
  br label %.loopexit

.loopexit:                                        ; preds = %.loopexit.loopexit, %entry
  store volatile i64 4196345, i64* %RIP_write, align 8, !mcsema_real_eip !191
  %682 = load i64, i64* %RCX_write, align 8, !mcsema_real_eip !191
  %683 = xor i64 %682, -1
  store volatile i64 %683, i64* %RCX_write, align 8, !mcsema_real_eip !191
  store volatile i64 4196348, i64* %RIP_write, align 8, !mcsema_real_eip !192
  %684 = load i64, i64* %RCX_write, align 8, !mcsema_real_eip !192
  %685 = add i64 %684, add (i64 ptrtoint (%2* @data_601280 to i64), i64 30), !mcsema_real_eip !192
  %686 = inttoptr i64 %685 to i8*, !mcsema_real_eip !192
  %687 = load i8, i8* %686, align 1, !mcsema_real_eip !192
  %688 = add i8 %687, -10
  %689 = xor i8 %688, %687, !mcsema_real_eip !192
  %690 = lshr i8 %689, 4
  %.lobit3 = and i8 %690, 1
  store volatile i8 %.lobit3, i8* %AF_write, align 1, !mcsema_real_eip !192
  %691 = tail call i8 @llvm.ctpop.i8(i8 %688), !mcsema_real_eip !192
  %692 = and i8 %691, 1
  %693 = xor i8 %692, 1
  store volatile i8 %693, i8* %PF_write, align 1, !mcsema_real_eip !192
  %694 = icmp eq i8 %688, 0, !mcsema_real_eip !192
  %695 = zext i1 %694 to i8, !mcsema_real_eip !192
  store volatile i8 %695, i8* %ZF_write, align 1, !mcsema_real_eip !192
  %.lobit4 = lshr i8 %688, 7
  store volatile i8 %.lobit4, i8* %SF_write, align 1, !mcsema_real_eip !192
  %696 = icmp ult i8 %687, 10, !mcsema_real_eip !192
  %697 = zext i1 %696 to i8, !mcsema_real_eip !192
  store volatile i8 %697, i8* %CF_write, align 1, !mcsema_real_eip !192
  %698 = and i8 %689, %687, !mcsema_real_eip !192
  %.lobit5 = lshr i8 %698, 7
  store volatile i8 %.lobit5, i8* %OF_write, align 1, !mcsema_real_eip !192
  store volatile i64 4196355, i64* %RIP_write, align 8, !mcsema_real_eip !193
  %699 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !193
  %700 = and i8 %699, 1
  %701 = icmp eq i8 %700, 0
  br i1 %701, label %block_40080c, label %block_400805, !mcsema_real_eip !193
}

; Function Attrs: noinline
define x86_64_sysvcc void @sub_400660(%RegState* nocapture) #1 {
entry:
  %RIP_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 0, !mcsema_real_eip !194
  %RSP_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 7, !mcsema_real_eip !194
  %RBP_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 8, !mcsema_real_eip !194
  %CF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 17, !mcsema_real_eip !194
  %PF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 18, !mcsema_real_eip !194
  %AF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 19, !mcsema_real_eip !194
  %ZF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 20, !mcsema_real_eip !194
  %SF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 21, !mcsema_real_eip !194
  %OF_write = getelementptr inbounds %RegState, %RegState* %0, i64 0, i32 22, !mcsema_real_eip !194
  store volatile i64 4195936, i64* %RIP_write, align 8, !mcsema_real_eip !194
  %1 = load i8, i8* inttoptr (i64 add (i64 ptrtoint (%2* @data_601280 to i64), i64 8) to i8*), align 8, !mcsema_real_eip !194
  store volatile i8 0, i8* %AF_write, align 1, !mcsema_real_eip !194
  %2 = tail call i8 @llvm.ctpop.i8(i8 %1), !mcsema_real_eip !194
  %3 = and i8 %2, 1
  %4 = xor i8 %3, 1
  store volatile i8 %4, i8* %PF_write, align 1, !mcsema_real_eip !194
  %5 = icmp eq i8 %1, 0, !mcsema_real_eip !194
  %6 = zext i1 %5 to i8, !mcsema_real_eip !194
  store volatile i8 %6, i8* %ZF_write, align 1, !mcsema_real_eip !194
  %.lobit = lshr i8 %1, 7
  store volatile i8 %.lobit, i8* %SF_write, align 1, !mcsema_real_eip !194
  store volatile i8 0, i8* %CF_write, align 1, !mcsema_real_eip !194
  store volatile i8 0, i8* %OF_write, align 1, !mcsema_real_eip !194
  store volatile i64 4195943, i64* %RIP_write, align 8, !mcsema_real_eip !195
  %7 = load i8, i8* %ZF_write, align 1, !mcsema_real_eip !195
  %8 = and i8 %7, 1
  %9 = icmp eq i8 %8, 0
  br i1 %9, label %block_40067a, label %block_400669, !mcsema_real_eip !195

block_400669:                                     ; preds = %entry
  store volatile i64 4195945, i64* %RIP_write, align 8, !mcsema_real_eip !196
  %10 = load i64, i64* %RBP_write, align 8, !mcsema_real_eip !196
  %11 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !196
  %12 = add i64 %11, -8
  %13 = inttoptr i64 %12 to i64*, !mcsema_real_eip !196
  store i64 %10, i64* %13, align 8, !mcsema_real_eip !196
  store volatile i64 %12, i64* %RSP_write, align 8, !mcsema_real_eip !196
  store volatile i64 4195946, i64* %RIP_write, align 8, !mcsema_real_eip !197
  %14 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !197
  store volatile i64 %14, i64* %RBP_write, align 8, !mcsema_real_eip !197
  store volatile i64 4195949, i64* %RIP_write, align 8, !mcsema_real_eip !198
  %15 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !198
  %16 = add i64 %15, -8
  %17 = inttoptr i64 %16 to i64*, !mcsema_real_eip !198
  store i64 4195954, i64* %17, align 8, !mcsema_real_eip !198
  store volatile i64 %16, i64* %RSP_write, align 8, !mcsema_real_eip !198
  tail call x86_64_sysvcc void @deregister_tm_clones(%RegState* nonnull %0), !mcsema_real_eip !198
  store volatile i64 4195954, i64* %RIP_write, align 8, !mcsema_real_eip !199
  %18 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !199
  %19 = inttoptr i64 %18 to i64*, !mcsema_real_eip !199
  %20 = load i64, i64* %19, align 8, !mcsema_real_eip !199
  store volatile i64 %20, i64* %RBP_write, align 8, !mcsema_real_eip !199
  %21 = add i64 %18, 8, !mcsema_real_eip !199
  store volatile i64 %21, i64* %RSP_write, align 8, !mcsema_real_eip !199
  store volatile i64 4195955, i64* %RIP_write, align 8, !mcsema_real_eip !200
  store i8 1, i8* inttoptr (i64 add (i64 ptrtoint (%2* @data_601280 to i64), i64 8) to i8*), align 8, !mcsema_real_eip !200
  br label %block_40067a, !mcsema_real_eip !201

block_40067a:                                     ; preds = %entry, %block_400669
  store volatile i64 4195962, i64* %RIP_write, align 8, !mcsema_real_eip !201
  store volatile i64 4195963, i64* %RIP_write, align 8, !mcsema_real_eip !202
  %22 = load i64, i64* %RSP_write, align 8, !mcsema_real_eip !202
  %23 = add i64 %22, 8, !mcsema_real_eip !202
  %24 = inttoptr i64 %22 to i64*, !mcsema_real_eip !202
  %25 = load i64, i64* %24, align 8, !mcsema_real_eip !202
  store volatile i64 %25, i64* %RIP_write, align 8, !mcsema_real_eip !202
  store volatile i64 %23, i64* %RSP_write, align 8, !mcsema_real_eip !202
  ret void, !mcsema_real_eip !202
}

declare x86_64_sysvcc void @b64d_fake(%RegState*) #0

; Function Attrs: nounwind readnone
declare i8 @llvm.ctpop.i8(i8) #2

; Function Attrs: naked noinline
declare x86_64_sysvcc i64 @_malloc(i64) #3

; Function Attrs: naked noinline
declare x86_64_sysvcc i64 @_exit(i64) #3

; Function Attrs: naked noinline
declare x86_64_sysvcc i64 @_memcpy(i64, i64, i64) #3

; Function Attrs: naked noinline
declare x86_64_sysvcc i64 @_puts(i64) #3

; Function Attrs: naked noinline
declare x86_64_sysvcc i64 @_fgets(i64, i64, i64) #3

; Function Attrs: naked noinline
declare x86_64_sysvcc i64 @_free(i64) #3

attributes #0 = { naked }
attributes #1 = { noinline }
attributes #2 = { nounwind readnone }
attributes #3 = { naked noinline }

!0 = !{i64 4195872}
!1 = !{i64 4195968}
!2 = !{i64 4195973}
!3 = !{i64 4195977}
!4 = !{i64 4195877}
!5 = !{i64 4195878}
!6 = !{i64 4195885}
!7 = !{i64 4195889}
!8 = !{i64 4195892}
!9 = !{i64 4195895}
!10 = !{i64 4195899}
!11 = !{i64 4195902}
!12 = !{i64 4195905}
!13 = !{i64 4195907}
!14 = !{i64 4195912}
!15 = !{i64 4195915}
!16 = !{i64 4195917}
!17 = !{i64 4195918}
!18 = !{i64 4195923}
!19 = !{i64 4195928}
!20 = !{i64 4195929}
!21 = !{i64 4195979}
!22 = !{i64 4195984}
!23 = !{i64 4195989}
!24 = !{i64 4195992}
!25 = !{i64 4195994}
!26 = !{i64 4195995}
!27 = !{i64 4195998}
!28 = !{i64 4196000}
!29 = !{i64 4196001}
!30 = !{i64 4196006}
!31 = !{i64 4196007}
!32 = !{i64 4196008}
!33 = !{i64 4196015}
!34 = !{i64 4196018}
!35 = !{i64 4196021}
!36 = !{i64 4196024}
!37 = !{i64 4196029}
!38 = !{i64 4196034}
!39 = !{i64 4196049}
!40 = !{i64 4196052}
!41 = !{i64 4196055}
!42 = !{i64 4196057}
!43 = !{i64 4196061}
!44 = !{i64 4196063}
!45 = !{i64 4196067}
!46 = !{i64 4196069}
!47 = !{i64 4196071}
!48 = !{i64 4196077}
!49 = !{i64 4196079}
!50 = !{i64 4196082}
!51 = !{i64 4196085}
!52 = !{i64 4196088}
!53 = !{i64 4196090}
!54 = !{i64 4196095}
!55 = !{i64 4196097}
!56 = !{i64 4196100}
!57 = !{i64 4196104}
!58 = !{i64 4196109}
!59 = !{i64 4196114}
!60 = !{i64 4196118}
!61 = !{i64 4196124}
!62 = !{i64 4196128}
!63 = !{i64 4196135}
!64 = !{i64 4196138}
!65 = !{i64 4196140}
!66 = !{i64 4196144}
!67 = !{i64 4196146}
!68 = !{i64 4196149}
!69 = !{i64 4196153}
!70 = !{i64 4196158}
!71 = !{i64 4196160}
!72 = !{i64 4196163}
!73 = !{i64 4196167}
!74 = !{i64 4196169}
!75 = !{i64 4196175}
!76 = !{i64 4196177}
!77 = !{i64 4196180}
!78 = !{i64 4196183}
!79 = !{i64 4196186}
!80 = !{i64 4196188}
!81 = !{i64 4196193}
!82 = !{i64 4196195}
!83 = !{i64 4196198}
!84 = !{i64 4196201}
!85 = !{i64 4196204}
!86 = !{i64 4196209}
!87 = !{i64 4196213}
!88 = !{i64 4196216}
!89 = !{i64 4196218}
!90 = !{i64 4196223}
!91 = !{i64 4196228}
!92 = !{i64 4196231}
!93 = !{i64 4196234}
!94 = !{i64 4196237}
!95 = !{i64 4196242}
!96 = !{i64 4196245}
!97 = !{i64 4196252}
!98 = !{i64 4196253}
!99 = !{i64 4196254}
!100 = !{i64 4196037}
!101 = !{i64 4196042}
!102 = !{i64 4196047}
!103 = !{i64 4195808}
!104 = !{i64 4195813}
!105 = !{i64 4195814}
!106 = !{i64 4195820}
!107 = !{i64 4195824}
!108 = !{i64 4195827}
!109 = !{i64 4195829}
!110 = !{i64 4195834}
!111 = !{i64 4195837}
!112 = !{i64 4195839}
!113 = !{i64 4195840}
!114 = !{i64 4195845}
!115 = !{i64 4195856}
!116 = !{i64 4195857}
!117 = !{i64 4196255}
!118 = !{i64 4196259}
!119 = !{i64 4196267}
!120 = !{i64 4196276}
!121 = !{i64 4196285}
!122 = !{i64 4196294}
!123 = !{i64 4196299}
!124 = !{i64 4196304}
!125 = !{i64 4196311}
!126 = !{i64 4196316}
!127 = !{i64 4196321}
!128 = !{i64 4196326}
!129 = !{i64 4196331}
!130 = !{i64 4196336}
!131 = !{i64 4196343}
!132 = !{i64 4196357}
!133 = !{i64 4196364}
!134 = !{i64 4196369}
!135 = !{i64 4196374}
!136 = !{i64 4196379}
!137 = !{i64 4196383}
!138 = !{i64 4196389}
!139 = !{i64 4196393}
!140 = !{i64 4196398}
!141 = !{i64 4196403}
!142 = !{i64 4196408}
!143 = !{i64 4196413}
!144 = !{i64 4196419}
!145 = !{i64 4196427}
!146 = !{i64 4196430}
!147 = !{i64 4196434}
!148 = !{i64 4196437}
!149 = !{i64 4196440}
!150 = !{i64 4196447}
!151 = !{i64 4196451}
!152 = !{i64 4196454}
!153 = !{i64 4196457}
!154 = !{i64 4196461}
!155 = !{i64 4196464}
!156 = !{i64 4196467}
!157 = !{i64 4196471}
!158 = !{i64 4196475}
!159 = !{i64 4196478}
!160 = !{i64 4196481}
!161 = !{i64 4196485}
!162 = !{i64 4196488}
!163 = !{i64 4196491}
!164 = !{i64 4196494}
!165 = !{i64 4196498}
!166 = !{i64 4196502}
!167 = !{i64 4196504}
!168 = !{i64 4196514}
!169 = !{i64 4196517}
!170 = !{i64 4196519}
!171 = !{i64 4196529}
!172 = !{i64 4196532}
!173 = !{i64 4196534}
!174 = !{i64 4196544}
!175 = !{i64 4196547}
!176 = !{i64 4196549}
!177 = !{i64 4196559}
!178 = !{i64 4196562}
!179 = !{i64 4196564}
!180 = !{i64 4196569}
!181 = !{i64 4196574}
!182 = !{i64 4196579}
!183 = !{i64 4196584}
!184 = !{i64 4196586}
!185 = !{i64 4196591}
!186 = !{i64 4196596}
!187 = !{i64 4196601}
!188 = !{i64 4196606}
!189 = !{i64 4196611}
!190 = !{i64 4196615}
!191 = !{i64 4196345}
!192 = !{i64 4196348}
!193 = !{i64 4196355}
!194 = !{i64 4195936}
!195 = !{i64 4195943}
!196 = !{i64 4195945}
!197 = !{i64 4195946}
!198 = !{i64 4195949}
!199 = !{i64 4195954}
!200 = !{i64 4195955}
!201 = !{i64 4195962}
!202 = !{i64 4195963}
