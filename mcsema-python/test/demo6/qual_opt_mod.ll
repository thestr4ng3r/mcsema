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
%RegState = type <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i8, i8, i8, i8, i8, i8, i8, [8 x x86_fp80], i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, [8 x i8], i16, i64, i16, i64, i16, i128, i128, i128, i128, i128, i128, i128, i128, i128, i128, i128, i128, i128, i128, i128, i128, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>

@stdin = external global [8 x i8]
@data_0x4009a0 = internal constant %0 <{ [656 x i8] c"\01\00\02\00\00\00\00\00Welcome. Please enter your base64 encoded input:\00\00\00\00\00\00\00\00Please send your solution to kirschju@sec.in.tum.de\00\00\00\00\00I know this is probably harder than what I could expect the average student to solve. Try the best you can and send me your write-up if time is tight.\00\00\1B[32mCongratz, you win!\1B[39m\00\1B[31mNope.\1B[39m\00Z3 SMT\00http://angr.io\00\00\00\00\00\00\00\00\00\00\00\00\00\00\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF>\FF\FF\FF?456789:;<=\FF\FF\FF\FF\FF\FF\FF\00\01\02\03\04\05\06\07\08\09\0A\0B\0C\0D\0E\0F\10\11\12\13\14\15\16\17\18\19\FF\FF\FF\FF\FF\FF\1A\1B\1C\1D\1E\1F !\22#$%&'()*+,-./0123\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\FF\A8;l\05\FC\DA\19\0A\5C\BF\1A #H4\9F\19\BCP\9D\1F\F4\ABM\8Fni<M\09\AF\C4\EF\BE\AD\DE\00\F07\13BBBB\EE\FF\C0\00" }>, align 64
@data_0x601010 = internal global %1 zeroinitializer, align 64
@data_0x601280 = internal global %2 zeroinitializer, align 64

; Function Attrs: noinline
define x86_64_sysvcc void @sub_40079f(%RegState*) #0 {
entry:
  %XAX = getelementptr %RegState* %0, i64 0, i32 1, !mcsema_real_eip !0
  %XCX = getelementptr %RegState* %0, i64 0, i32 3, !mcsema_real_eip !0
  %XDX = getelementptr %RegState* %0, i64 0, i32 4, !mcsema_real_eip !0
  %XSI = getelementptr %RegState* %0, i64 0, i32 5, !mcsema_real_eip !0
  %XDI = getelementptr %RegState* %0, i64 0, i32 6, !mcsema_real_eip !0
  %XSP = getelementptr %RegState* %0, i64 0, i32 7, !mcsema_real_eip !0
  %ZF_full = getelementptr %RegState* %0, i64 0, i32 12, !mcsema_real_eip !0
  %ZF = bitcast i8* %ZF_full to i1*, !mcsema_real_eip !0
  %PF_full = getelementptr %RegState* %0, i64 0, i32 10, !mcsema_real_eip !0
  %PF = bitcast i8* %PF_full to i1*, !mcsema_real_eip !0
  %AF_full = getelementptr %RegState* %0, i64 0, i32 11, !mcsema_real_eip !0
  %AF = bitcast i8* %AF_full to i1*, !mcsema_real_eip !0
  %CF_full = getelementptr %RegState* %0, i64 0, i32 9, !mcsema_real_eip !0
  %CF = bitcast i8* %CF_full to i1*, !mcsema_real_eip !0
  %SF_full = getelementptr %RegState* %0, i64 0, i32 13, !mcsema_real_eip !0
  %SF = bitcast i8* %SF_full to i1*, !mcsema_real_eip !0
  %OF_full = getelementptr %RegState* %0, i64 0, i32 14, !mcsema_real_eip !0
  %OF = bitcast i8* %OF_full to i1*, !mcsema_real_eip !0
  %DF_full = getelementptr %RegState* %0, i64 0, i32 15, !mcsema_real_eip !0
  %DF = bitcast i8* %DF_full to i1*, !mcsema_real_eip !0
  %R9 = getelementptr %RegState* %0, i64 0, i32 65, !mcsema_real_eip !0
  %RSP_val.0 = load i64* %XSP, align 8, !mcsema_real_eip !0
  %1 = add i64 %RSP_val.0, -56
  %2 = xor i64 %1, %RSP_val.0, !mcsema_real_eip !0
  %3 = and i64 %2, 16
  %4 = icmp eq i64 %3, 0
  store i1 %4, i1* %AF, align 1, !mcsema_real_eip !0
  %5 = trunc i64 %1 to i8, !mcsema_real_eip !0
  %6 = tail call i8 @llvm.ctpop.i8(i8 %5), !mcsema_real_eip !0
  %7 = and i8 %6, 1
  %8 = icmp eq i8 %7, 0
  store i1 %8, i1* %PF, align 1, !mcsema_real_eip !0
  %9 = icmp eq i64 %1, 0, !mcsema_real_eip !0
  store i1 %9, i1* %ZF, align 1, !mcsema_real_eip !0
  %10 = icmp slt i64 %1, 0
  store i1 %10, i1* %SF, align 1, !mcsema_real_eip !0
  %11 = icmp ult i64 %RSP_val.0, 56, !mcsema_real_eip !0
  store i1 %11, i1* %CF, align 1, !mcsema_real_eip !0
  %12 = and i64 %2, %RSP_val.0, !mcsema_real_eip !0
  %13 = icmp slt i64 %12, 0
  store i1 %13, i1* %OF, align 1, !mcsema_real_eip !0
  store i64 %1, i64* %XSP, align 8, !mcsema_real_eip !0
  %14 = inttoptr i64 %1 to i64*, !mcsema_real_eip !1
  store i64 0, i64* %14, align 8, !mcsema_real_eip !1
  %RSP_val.2 = load i64* %XSP, align 8, !mcsema_real_eip !2
  %15 = add i64 %RSP_val.2, 8, !mcsema_real_eip !2
  %16 = inttoptr i64 %15 to i64*, !mcsema_real_eip !2
  store i64 0, i64* %16, align 8, !mcsema_real_eip !2
  %RSP_val.3 = load i64* %XSP, align 8, !mcsema_real_eip !3
  %17 = add i64 %RSP_val.3, 16, !mcsema_real_eip !3
  %18 = inttoptr i64 %17 to i64*, !mcsema_real_eip !3
  store i64 0, i64* %18, align 8, !mcsema_real_eip !3
  %RSP_val.4 = load i64* %XSP, align 8, !mcsema_real_eip !4
  %19 = add i64 %RSP_val.4, 24, !mcsema_real_eip !4
  %20 = inttoptr i64 %19 to i64*, !mcsema_real_eip !4
  store i64 0, i64* %20, align 8, !mcsema_real_eip !4
  store i64 add (i64 ptrtoint (%0* @data_0x4009a0 to i64), i64 8), i64* %XDI, align 8, !mcsema_real_eip !5
  %RSP_val.6 = load i64* %XSP, align 8, !mcsema_real_eip !6
  %21 = add i64 %RSP_val.6, -8
  %22 = inttoptr i64 %21 to i64*, !mcsema_real_eip !6
  store i64 -2415393069852865332, i64* %22, align 8, !mcsema_real_eip !6
  store i64 %21, i64* %XSP, align 8, !mcsema_real_eip !6
  %23 = tail call x86_64_sysvcc i64 @_puts(i64 add (i64 ptrtoint (%0* @data_0x4009a0 to i64), i64 8)), !mcsema_real_eip !6
  store i64 %23, i64* %XAX, align 8, !mcsema_real_eip !6
  %24 = load i64* bitcast ([8 x i8]* @stdin to i64*), align 8, !mcsema_real_eip !7
  store i64 %24, i64* %XDX, align 8, !mcsema_real_eip !7
  store i64 256, i64* %XSI, align 8, !mcsema_real_eip !8
  store i64 add (i64 ptrtoint (%2* @data_0x601280 to i64), i64 32), i64* %XDI, align 8, !mcsema_real_eip !9
  %RSP_val.10 = load i64* %XSP, align 8, !mcsema_real_eip !10
  %25 = add i64 %RSP_val.10, -8
  %26 = inttoptr i64 %25 to i64*, !mcsema_real_eip !10
  store i64 -2415393069852865332, i64* %26, align 8, !mcsema_real_eip !10
  store i64 %25, i64* %XSP, align 8, !mcsema_real_eip !10
  %27 = tail call x86_64_sysvcc i64 @_fgets(i64 add (i64 ptrtoint (%2* @data_0x601280 to i64), i64 32), i64 256, i64 %24), !mcsema_real_eip !10
  store i64 add (i64 ptrtoint (%2* @data_0x601280 to i64), i64 32), i64* %XDI, align 8, !mcsema_real_eip !11
  store i64 0, i64* %XAX, align 8, !mcsema_real_eip !12
  store i64 -1, i64* %XCX, align 8, !mcsema_real_eip !13
  %.pre = load i1* %DF, align 1
  br label %46

block_0x400805:                                   ; preds = %65
  %28 = sub i64 add (i64 ptrtoint (%2* @data_0x601280 to i64), i64 30), %RCX_val.14.lcssa
  %29 = inttoptr i64 %28 to i8*, !mcsema_real_eip !14
  store i8 0, i8* %29, align 1, !mcsema_real_eip !14
  br label %block_0x40080c, !mcsema_real_eip !15

block_0x40080c:                                   ; preds = %65, %block_0x400805
  %RSP_val.17 = load i64* %XSP, align 8
  %30 = add i64 %RSP_val.17, 40, !mcsema_real_eip !16
  store i64 %30, i64* %XSI, align 8, !mcsema_real_eip !16
  store i64 add (i64 ptrtoint (%2* @data_0x601280 to i64), i64 32), i64* %XDI, align 8, !mcsema_real_eip !17
  %31 = add i64 %RSP_val.17, -8
  %32 = inttoptr i64 %31 to i64*, !mcsema_real_eip !18
  store i64 -4981261766360305936, i64* %32, align 8, !mcsema_real_eip !18
  store i64 %31, i64* %XSP, align 8, !mcsema_real_eip !18
  tail call x86_64_sysvcc void @b64d_fake(%RegState* %0), !mcsema_real_eip !18
  %RAX_val.19 = load i64* %XAX, align 8, !mcsema_real_eip !19
  %33 = add i64 %RAX_val.19, -16
  %34 = xor i64 %33, %RAX_val.19, !mcsema_real_eip !19
  %35 = and i64 %34, 16
  %36 = icmp eq i64 %35, 0
  store i1 %36, i1* %AF, align 1, !mcsema_real_eip !19
  %37 = trunc i64 %33 to i8, !mcsema_real_eip !19
  %38 = tail call i8 @llvm.ctpop.i8(i8 %37), !mcsema_real_eip !19
  %39 = and i8 %38, 1
  %40 = icmp eq i8 %39, 0
  store i1 %40, i1* %PF, align 1, !mcsema_real_eip !19
  %41 = icmp eq i64 %33, 0, !mcsema_real_eip !19
  store i1 %41, i1* %ZF, align 1, !mcsema_real_eip !19
  %42 = icmp slt i64 %33, 0
  store i1 %42, i1* %SF, align 1, !mcsema_real_eip !19
  %43 = icmp ult i64 %RAX_val.19, 16, !mcsema_real_eip !19
  store i1 %43, i1* %CF, align 1, !mcsema_real_eip !19
  %44 = and i64 %34, %RAX_val.19, !mcsema_real_eip !19
  %45 = icmp slt i64 %44, 0
  store i1 %45, i1* %OF, align 1, !mcsema_real_eip !19
  br i1 %41, label %block_0x400825, label %block_0x4008ea, !mcsema_real_eip !20

; <label>:46                                      ; preds = %46, %entry
  %RCX_val.14 = phi i64 [ -1, %entry ], [ %62, %46 ]
  %RDI_val.11 = phi i64 [ add (i64 ptrtoint (%2* @data_0x601280 to i64), i64 32), %entry ], [ %61, %46 ]
  %47 = inttoptr i64 %RDI_val.11 to i8*, !mcsema_real_eip !21
  %48 = load i8* %47, align 1, !mcsema_real_eip !21
  %49 = sub i8 0, %48, !mcsema_real_eip !21
  %50 = tail call i8 @llvm.ctpop.i8(i8 %49), !mcsema_real_eip !21
  %51 = and i8 %50, 1
  %52 = icmp eq i8 %51, 0
  store i1 %52, i1* %PF, align 1, !mcsema_real_eip !21
  %53 = icmp eq i8 %48, 0
  store i1 %53, i1* %ZF, align 1, !mcsema_real_eip !21
  %54 = icmp slt i8 %49, 0
  store i1 %54, i1* %SF, align 1, !mcsema_real_eip !21
  %55 = icmp ne i8 %48, 0
  store i1 %55, i1* %CF, align 1, !mcsema_real_eip !21
  %56 = xor i8 %48, %49, !mcsema_real_eip !21
  %57 = and i8 %56, 16, !mcsema_real_eip !21
  %58 = icmp ne i8 %57, 0, !mcsema_real_eip !21
  store i1 %58, i1* %AF, align 1, !mcsema_real_eip !21
  %59 = and i8 %48, %49, !mcsema_real_eip !21
  %60 = icmp slt i8 %59, 0
  store i1 %60, i1* %OF, align 1, !mcsema_real_eip !21
  %.v = select i1 %.pre, i64 -1, i64 1
  %61 = add i64 %.v, %RDI_val.11
  store i64 %61, i64* %XDI, align 8, !mcsema_real_eip !21
  %62 = add i64 %RCX_val.14, -1
  store i64 %62, i64* %XCX, align 8, !mcsema_real_eip !21
  %63 = icmp eq i64 %62, 0, !mcsema_real_eip !21
  %64 = or i1 %63, %53, !mcsema_real_eip !21
  br i1 %64, label %65, label %46, !mcsema_real_eip !21

; <label>:65                                      ; preds = %46
  %RCX_val.14.lcssa = phi i64 [ %RCX_val.14, %46 ]
  %XIP = getelementptr %RegState* %0, i64 0, i32 0, !mcsema_real_eip !0
  %R8 = getelementptr %RegState* %0, i64 0, i32 64, !mcsema_real_eip !0
  %R10 = getelementptr %RegState* %0, i64 0, i32 66, !mcsema_real_eip !0
  %66 = sub i64 0, %RCX_val.14.lcssa
  store i64 %66, i64* %XCX, align 8, !mcsema_real_eip !22
  %67 = sub i64 sub (i64 sub (i64 add (i64 ptrtoint (%2* @data_0x601280 to i64), i64 30), i64 1), i64 -1), %RCX_val.14.lcssa
  %68 = inttoptr i64 %67 to i8*, !mcsema_real_eip !23
  %69 = load i8* %68, align 1, !mcsema_real_eip !23
  %70 = add i8 %69, -10
  %71 = xor i8 %70, %69, !mcsema_real_eip !23
  %72 = and i8 %71, 16, !mcsema_real_eip !23
  %73 = icmp ne i8 %72, 0, !mcsema_real_eip !23
  store i1 %73, i1* %AF, align 1, !mcsema_real_eip !23
  %74 = tail call i8 @llvm.ctpop.i8(i8 %70), !mcsema_real_eip !23
  %75 = and i8 %74, 1
  %76 = icmp eq i8 %75, 0
  store i1 %76, i1* %PF, align 1, !mcsema_real_eip !23
  %77 = icmp eq i8 %70, 0, !mcsema_real_eip !23
  store i1 %77, i1* %ZF, align 1, !mcsema_real_eip !23
  %78 = icmp slt i8 %70, 0
  store i1 %78, i1* %SF, align 1, !mcsema_real_eip !23
  %79 = icmp ult i8 %69, 10, !mcsema_real_eip !23
  store i1 %79, i1* %CF, align 1, !mcsema_real_eip !23
  %80 = and i8 %71, %69, !mcsema_real_eip !23
  %81 = icmp slt i8 %80, 0
  store i1 %81, i1* %OF, align 1, !mcsema_real_eip !23
  br i1 %77, label %block_0x400805, label %block_0x40080c, !mcsema_real_eip !24

block_0x400825:                                   ; preds = %block_0x40080c
  %RSP_val.23 = load i64* %XSP, align 8
  %82 = inttoptr i64 %RSP_val.23 to i64*, !mcsema_real_eip !25
  %83 = load i64* %82, align 8, !mcsema_real_eip !25
  store i64 %83, i64* %XCX, align 8, !mcsema_real_eip !25
  %84 = add i64 %RSP_val.23, 8, !mcsema_real_eip !26
  %85 = inttoptr i64 %84 to i64*, !mcsema_real_eip !26
  %86 = load i64* %85, align 8, !mcsema_real_eip !26
  store i64 %86, i64* %XSI, align 8, !mcsema_real_eip !26
  %87 = add i64 %RSP_val.23, 16, !mcsema_real_eip !27
  %88 = inttoptr i64 %87 to i64*, !mcsema_real_eip !27
  %89 = load i64* %88, align 8, !mcsema_real_eip !27
  store i64 %89, i64* %XDI, align 8, !mcsema_real_eip !27
  %90 = add i64 %RSP_val.23, 24, !mcsema_real_eip !28
  %91 = inttoptr i64 %90 to i64*, !mcsema_real_eip !28
  %92 = load i64* %91, align 8, !mcsema_real_eip !28
  store i64 %92, i64* %R10, align 8, !mcsema_real_eip !28
  %93 = add i64 %RSP_val.23, 40, !mcsema_real_eip !29
  %94 = inttoptr i64 %93 to i64*, !mcsema_real_eip !29
  %95 = load i64* %94, align 8, !mcsema_real_eip !29
  store i64 %95, i64* %R9, align 8, !mcsema_real_eip !29
  store i64 0, i64* %R8, align 8, !mcsema_real_eip !30
  br label %block_0x400843, !mcsema_real_eip !31

block_0x4008ea:                                   ; preds = %block_0x4008c5, %block_0x4008b6, %block_0x4008a7, %block_0x400898, %block_0x40080c
  store i64 add (i64 ptrtoint (%0* @data_0x4009a0 to i64), i64 301), i64* %XDI, align 8, !mcsema_real_eip !15
  %RSP_val.22 = load i64* %XSP, align 8, !mcsema_real_eip !32
  %96 = add i64 %RSP_val.22, -8
  %97 = inttoptr i64 %96 to i64*, !mcsema_real_eip !32
  store i64 -2415393069852865332, i64* %97, align 8, !mcsema_real_eip !32
  store i64 %96, i64* %XSP, align 8, !mcsema_real_eip !32
  %98 = tail call x86_64_sysvcc i64 @_puts(i64 add (i64 ptrtoint (%0* @data_0x4009a0 to i64), i64 301)), !mcsema_real_eip !32
  br label %block_0x4008f4, !mcsema_real_eip !25

block_0x4008f4:                                   ; preds = %block_0x4008d4, %block_0x4008ea
  %storemerge = phi i64 [ %98, %block_0x4008ea ], [ %450, %block_0x4008d4 ]
  store i64 %storemerge, i64* %XAX, align 8
  %RSP_val.28 = load i64* %XSP, align 8
  %99 = add i64 %RSP_val.28, 40, !mcsema_real_eip !31
  %100 = inttoptr i64 %99 to i64*, !mcsema_real_eip !31
  %101 = load i64* %100, align 8, !mcsema_real_eip !31
  store i64 %101, i64* %XDI, align 8, !mcsema_real_eip !31
  %102 = add i64 %RSP_val.28, -8
  %103 = inttoptr i64 %102 to i64*, !mcsema_real_eip !33
  store i64 -2415393069852865332, i64* %103, align 8, !mcsema_real_eip !33
  store i64 %102, i64* %XSP, align 8, !mcsema_real_eip !33
  %104 = tail call x86_64_sysvcc i64 @_free(i64 %101), !mcsema_real_eip !33
  store i64 0, i64* %XAX, align 8, !mcsema_real_eip !34
  %RSP_val.31 = load i64* %XSP, align 8, !mcsema_real_eip !35
  %uadd3 = tail call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %RSP_val.31, i64 56)
  %105 = extractvalue { i64, i1 } %uadd3, 0
  %106 = xor i64 %105, %RSP_val.31, !mcsema_real_eip !35
  %107 = and i64 %106, 16
  %108 = icmp eq i64 %107, 0
  store i1 %108, i1* %AF, align 1, !mcsema_real_eip !35
  %109 = icmp slt i64 %105, 0
  store i1 %109, i1* %SF, align 1, !mcsema_real_eip !35
  %110 = icmp eq i64 %105, 0, !mcsema_real_eip !35
  store i1 %110, i1* %ZF, align 1, !mcsema_real_eip !35
  %111 = xor i64 %RSP_val.31, -9223372036854775808, !mcsema_real_eip !35
  %112 = and i64 %106, %111, !mcsema_real_eip !35
  %113 = icmp slt i64 %112, 0
  store i1 %113, i1* %OF, align 1, !mcsema_real_eip !35
  %114 = trunc i64 %105 to i8, !mcsema_real_eip !35
  %115 = tail call i8 @llvm.ctpop.i8(i8 %114), !mcsema_real_eip !35
  %116 = and i8 %115, 1
  %117 = icmp eq i8 %116, 0
  store i1 %117, i1* %PF, align 1, !mcsema_real_eip !35
  %118 = extractvalue { i64, i1 } %uadd3, 1
  store i1 %118, i1* %CF, align 1, !mcsema_real_eip !35
  store i64 %105, i64* %XSP, align 8, !mcsema_real_eip !35
  %119 = add i64 %105, 8, !mcsema_real_eip !36
  %120 = inttoptr i64 %105 to i64*, !mcsema_real_eip !36
  %121 = load i64* %120, align 8, !mcsema_real_eip !36
  store i64 %121, i64* %XIP, align 8, !mcsema_real_eip !36
  store i64 %119, i64* %XSP, align 8, !mcsema_real_eip !36
  ret void, !mcsema_real_eip !36

block_0x400843:                                   ; preds = %block_0x400843.block_0x400843_crit_edge, %block_0x400825
  %RCX_val.42 = phi i64 [ %RCX_val.42.pre, %block_0x400843.block_0x400843_crit_edge ], [ %83, %block_0x400825 ]
  %R9_val.36 = phi i64 [ %R9_val.36.pre, %block_0x400843.block_0x400843_crit_edge ], [ %95, %block_0x400825 ]
  %R8_val.38 = phi i64 [ %377, %block_0x400843.block_0x400843_crit_edge ], [ 0, %block_0x400825 ]
  %122 = shl i64 %R8_val.38, 2
  %trunc = trunc i64 %122 to i32
  %123 = and i32 %trunc, 12, !mcsema_real_eip !37
  store i1 false, i1* %SF, align 1, !mcsema_real_eip !37
  %124 = icmp eq i32 %123, 0, !mcsema_real_eip !37
  store i1 %124, i1* %ZF, align 1, !mcsema_real_eip !37
  %125 = trunc i32 %123 to i8, !mcsema_real_eip !37
  %126 = tail call i8 @llvm.ctpop.i8(i8 %125), !mcsema_real_eip !37
  %127 = and i8 %126, 1
  %128 = icmp eq i8 %127, 0
  store i1 %128, i1* %PF, align 1, !mcsema_real_eip !37
  store i1 false, i1* %OF, align 1, !mcsema_real_eip !37
  store i1 false, i1* %CF, align 1, !mcsema_real_eip !37
  %129 = zext i32 %123 to i64, !mcsema_real_eip !37
  store i64 %129, i64* %XAX, align 8, !mcsema_real_eip !37
  %130 = add i64 %R9_val.36, %129, !mcsema_real_eip !38
  %131 = inttoptr i64 %130 to i32*, !mcsema_real_eip !38
  %132 = load i32* %131, align 4, !mcsema_real_eip !38
  %133 = zext i32 %132 to i64, !mcsema_real_eip !38
  store i64 %133, i64* %XDX, align 8, !mcsema_real_eip !38
  %trunc36 = trunc i64 %R8_val.38 to i32
  %134 = and i32 %trunc36, 3, !mcsema_real_eip !39
  store i1 false, i1* %SF, align 1, !mcsema_real_eip !39
  %135 = icmp eq i32 %134, 0, !mcsema_real_eip !39
  store i1 %135, i1* %ZF, align 1, !mcsema_real_eip !39
  %136 = trunc i32 %134 to i8, !mcsema_real_eip !39
  %137 = tail call i8 @llvm.ctpop.i8(i8 %136), !mcsema_real_eip !39
  %138 = and i8 %137, 1
  %139 = icmp eq i8 %138, 0
  store i1 %139, i1* %PF, align 1, !mcsema_real_eip !39
  store i1 false, i1* %OF, align 1, !mcsema_real_eip !39
  store i1 false, i1* %CF, align 1, !mcsema_real_eip !39
  %140 = zext i32 %134 to i64, !mcsema_real_eip !39
  store i64 %140, i64* %XAX, align 8, !mcsema_real_eip !39
  %141 = shl nuw nsw i64 %140, 2
  %142 = or i64 %141, add (i64 ptrtoint (%0* @data_0x4009a0 to i64), i64 640)
  %143 = inttoptr i64 %142 to i32*, !mcsema_real_eip !40
  %144 = load i32* %143, align 4, !mcsema_real_eip !40
  %145 = zext i32 %144 to i64, !mcsema_real_eip !40
  store i64 %145, i64* %XAX, align 8, !mcsema_real_eip !40
  %146 = lshr i64 %RCX_val.42, 63, !mcsema_real_eip !41
  %147 = shl i64 %RCX_val.42, 1
  %148 = or i64 %147, %146
  %149 = lshr i64 %RCX_val.42, 62
  %150 = and i64 %149, 1
  %151 = shl i64 %148, 1
  %152 = or i64 %151, %150
  %153 = lshr i64 %RCX_val.42, 61
  %154 = and i64 %153, 1
  %155 = shl i64 %152, 1
  %156 = or i64 %155, %154
  %157 = lshr i64 %RCX_val.42, 60
  %158 = and i64 %157, 1
  %159 = shl i64 %156, 1
  %160 = or i64 %159, %158
  %161 = lshr i64 %RCX_val.42, 59
  %162 = and i64 %161, 1
  %163 = shl i64 %160, 1
  %164 = or i64 %163, %162
  %165 = lshr i64 %RCX_val.42, 58
  %166 = and i64 %165, 1
  %167 = shl i64 %164, 1
  %168 = or i64 %167, %166
  %169 = lshr i64 %RCX_val.42, 57
  %170 = and i64 %169, 1
  %171 = shl i64 %168, 1
  %172 = or i64 %171, %170
  %173 = lshr i64 %RCX_val.42, 56
  %174 = and i64 %173, 1
  %175 = shl i64 %172, 1
  %176 = or i64 %175, %174
  %177 = lshr i64 %RCX_val.42, 55
  %178 = and i64 %177, 1
  %179 = shl i64 %176, 1
  %180 = or i64 %179, %178
  %181 = lshr i64 %RCX_val.42, 54
  %182 = and i64 %181, 1
  %183 = shl i64 %180, 1
  %184 = or i64 %183, %182
  %185 = lshr i64 %RCX_val.42, 53
  %186 = and i64 %185, 1
  %187 = shl i64 %184, 1
  %188 = or i64 %187, %186
  %189 = lshr i64 %RCX_val.42, 52
  %190 = and i64 %189, 1
  %191 = shl i64 %188, 1
  %192 = or i64 %191, %190
  %193 = lshr i64 %RCX_val.42, 51
  %194 = and i64 %193, 1
  %195 = shl i64 %192, 1
  %196 = or i64 %195, %194
  %197 = xor i64 %133, %196, !mcsema_real_eip !42
  %198 = add i64 %145, %197
  store i64 %198, i64* %XCX, align 8, !mcsema_real_eip !43
  %RSI_val.47 = load i64* %XSI, align 8, !mcsema_real_eip !44
  %199 = lshr i64 %RSI_val.47, 1, !mcsema_real_eip !44
  %200 = shl i64 %RSI_val.47, 63, !mcsema_real_eip !44
  %201 = or i64 %199, %200
  %202 = lshr i64 %201, 1, !mcsema_real_eip !44
  %203 = shl i64 %199, 63, !mcsema_real_eip !44
  %204 = or i64 %202, %203
  %205 = lshr i64 %204, 1, !mcsema_real_eip !44
  %206 = shl i64 %202, 63, !mcsema_real_eip !44
  %207 = or i64 %205, %206
  %208 = lshr i64 %207, 1, !mcsema_real_eip !44
  %209 = shl i64 %205, 63, !mcsema_real_eip !44
  %210 = or i64 %208, %209
  %211 = lshr i64 %210, 1, !mcsema_real_eip !44
  %212 = shl i64 %208, 63, !mcsema_real_eip !44
  %213 = or i64 %211, %212
  %214 = lshr i64 %213, 1, !mcsema_real_eip !44
  %215 = shl i64 %211, 63, !mcsema_real_eip !44
  %216 = or i64 %214, %215
  %217 = lshr i64 %216, 1, !mcsema_real_eip !44
  %218 = shl i64 %214, 63, !mcsema_real_eip !44
  %219 = or i64 %217, %218
  %220 = lshr i64 %219, 1, !mcsema_real_eip !44
  %221 = shl i64 %217, 63, !mcsema_real_eip !44
  %222 = or i64 %220, %221
  %223 = lshr i64 %222, 1, !mcsema_real_eip !44
  %224 = shl i64 %220, 63, !mcsema_real_eip !44
  %225 = or i64 %223, %224
  %226 = lshr i64 %225, 1, !mcsema_real_eip !44
  %227 = shl i64 %223, 63, !mcsema_real_eip !44
  %228 = or i64 %226, %227
  %229 = lshr i64 %228, 1, !mcsema_real_eip !44
  %230 = shl i64 %226, 63, !mcsema_real_eip !44
  %231 = or i64 %229, %230
  %232 = lshr i64 %231, 1, !mcsema_real_eip !44
  %233 = shl i64 %229, 63, !mcsema_real_eip !44
  %234 = or i64 %232, %233
  %235 = lshr i64 %234, 1, !mcsema_real_eip !44
  %236 = shl i64 %232, 63, !mcsema_real_eip !44
  %237 = or i64 %235, %236
  %RDX_val.49 = load i64* %XDX, align 8, !mcsema_real_eip !45
  %238 = xor i64 %RDX_val.49, %237, !mcsema_real_eip !45
  %RAX_val.51 = load i64* %XAX, align 8
  %239 = sub i64 %238, %RAX_val.51, !mcsema_real_eip !46
  store i64 %239, i64* %XSI, align 8, !mcsema_real_eip !46
  %240 = shl i64 %RAX_val.51, 32
  store i64 %240, i64* %XAX, align 8, !mcsema_real_eip !47
  %RDI_val.53 = load i64* %XDI, align 8, !mcsema_real_eip !48
  %241 = lshr i64 %RDI_val.53, 1, !mcsema_real_eip !48
  %242 = shl i64 %RDI_val.53, 63, !mcsema_real_eip !48
  %243 = or i64 %241, %242
  %244 = lshr i64 %243, 1, !mcsema_real_eip !48
  %245 = shl i64 %241, 63, !mcsema_real_eip !48
  %246 = or i64 %244, %245
  %247 = lshr i64 %246, 1, !mcsema_real_eip !48
  %248 = shl i64 %244, 63, !mcsema_real_eip !48
  %249 = or i64 %247, %248
  %250 = lshr i64 %249, 1, !mcsema_real_eip !48
  %251 = shl i64 %247, 63, !mcsema_real_eip !48
  %252 = or i64 %250, %251
  %253 = lshr i64 %252, 1, !mcsema_real_eip !48
  %254 = shl i64 %250, 63, !mcsema_real_eip !48
  %255 = or i64 %253, %254
  %256 = lshr i64 %255, 1, !mcsema_real_eip !48
  %257 = shl i64 %253, 63, !mcsema_real_eip !48
  %258 = or i64 %256, %257
  %259 = lshr i64 %258, 1, !mcsema_real_eip !48
  %260 = shl i64 %256, 63, !mcsema_real_eip !48
  %261 = or i64 %259, %260
  %262 = lshr i64 %261, 1, !mcsema_real_eip !48
  %263 = shl i64 %259, 63, !mcsema_real_eip !48
  %264 = or i64 %262, %263
  %265 = lshr i64 %264, 1, !mcsema_real_eip !48
  %266 = shl i64 %262, 63, !mcsema_real_eip !48
  %267 = or i64 %265, %266
  %268 = lshr i64 %267, 1, !mcsema_real_eip !48
  %269 = shl i64 %265, 63, !mcsema_real_eip !48
  %270 = or i64 %268, %269
  %271 = lshr i64 %270, 1, !mcsema_real_eip !48
  %272 = shl i64 %268, 63, !mcsema_real_eip !48
  %273 = or i64 %271, %272
  %274 = lshr i64 %273, 1, !mcsema_real_eip !48
  %275 = shl i64 %271, 63, !mcsema_real_eip !48
  %276 = or i64 %274, %275
  %277 = lshr i64 %276, 1, !mcsema_real_eip !48
  %278 = shl i64 %274, 63, !mcsema_real_eip !48
  %279 = or i64 %277, %278
  %280 = lshr i64 %279, 1, !mcsema_real_eip !48
  %281 = shl i64 %277, 63, !mcsema_real_eip !48
  %282 = or i64 %280, %281
  %283 = lshr i64 %282, 1, !mcsema_real_eip !48
  %284 = shl i64 %280, 63, !mcsema_real_eip !48
  %285 = or i64 %283, %284
  %286 = lshr i64 %285, 1, !mcsema_real_eip !48
  %287 = shl i64 %283, 63, !mcsema_real_eip !48
  %288 = or i64 %286, %287
  %289 = lshr i64 %288, 1, !mcsema_real_eip !48
  %290 = shl i64 %286, 63, !mcsema_real_eip !48
  %291 = or i64 %289, %290
  %292 = lshr i64 %291, 1, !mcsema_real_eip !48
  %293 = shl i64 %289, 63, !mcsema_real_eip !48
  %294 = or i64 %292, %293
  %295 = lshr i64 %294, 1, !mcsema_real_eip !48
  %296 = shl i64 %292, 63, !mcsema_real_eip !48
  %297 = or i64 %295, %296
  %RDX_val.55 = load i64* %XDX, align 8, !mcsema_real_eip !49
  %298 = xor i64 %RDX_val.55, %297, !mcsema_real_eip !49
  %299 = add i64 %240, %298
  store i64 %299, i64* %XDI, align 8, !mcsema_real_eip !50
  %R10_val.58 = load i64* %R10, align 8, !mcsema_real_eip !51
  %300 = lshr i64 %R10_val.58, 63, !mcsema_real_eip !51
  %301 = shl i64 %R10_val.58, 1
  %302 = or i64 %301, %300
  %303 = lshr i64 %R10_val.58, 62
  %304 = and i64 %303, 1
  %305 = shl i64 %302, 1
  %306 = or i64 %305, %304
  %307 = lshr i64 %R10_val.58, 61
  %308 = and i64 %307, 1
  %309 = shl i64 %306, 1
  %310 = or i64 %309, %308
  %311 = lshr i64 %R10_val.58, 60
  %312 = and i64 %311, 1
  %313 = shl i64 %310, 1
  %314 = or i64 %313, %312
  %315 = lshr i64 %R10_val.58, 59
  %316 = and i64 %315, 1
  %317 = shl i64 %314, 1
  %318 = or i64 %317, %316
  %319 = lshr i64 %R10_val.58, 58
  %320 = and i64 %319, 1
  %321 = shl i64 %318, 1
  %322 = or i64 %321, %320
  %323 = lshr i64 %R10_val.58, 57
  %324 = and i64 %323, 1
  %325 = shl i64 %322, 1
  %326 = or i64 %325, %324
  %327 = lshr i64 %R10_val.58, 56
  %328 = and i64 %327, 1
  %329 = shl i64 %326, 1
  %330 = or i64 %329, %328
  %331 = lshr i64 %R10_val.58, 55
  %332 = and i64 %331, 1
  %333 = shl i64 %330, 1
  %334 = or i64 %333, %332
  %335 = lshr i64 %R10_val.58, 54
  %336 = and i64 %335, 1
  %337 = shl i64 %334, 1
  %338 = or i64 %337, %336
  %339 = lshr i64 %R10_val.58, 53
  %340 = and i64 %339, 1
  %341 = shl i64 %338, 1
  %342 = or i64 %341, %340
  %343 = lshr i64 %R10_val.58, 52
  %344 = and i64 %343, 1
  %345 = shl i64 %342, 1
  %346 = or i64 %345, %344
  %347 = lshr i64 %R10_val.58, 51
  %348 = and i64 %347, 1
  %349 = shl i64 %346, 1
  %350 = or i64 %349, %348
  %351 = lshr i64 %R10_val.58, 50
  %352 = and i64 %351, 1
  %353 = shl i64 %350, 1
  %354 = or i64 %353, %352
  %355 = lshr i64 %R10_val.58, 49
  %356 = and i64 %355, 1
  %357 = shl i64 %354, 1
  %358 = or i64 %357, %356
  %359 = lshr i64 %R10_val.58, 48
  %360 = and i64 %359, 1
  %361 = shl i64 %358, 1
  %362 = or i64 %361, %360
  %363 = lshr i64 %R10_val.58, 47
  %364 = and i64 %363, 1
  %365 = shl i64 %362, 1
  %366 = or i64 %365, %364
  %367 = lshr i64 %R10_val.58, 46
  %368 = and i64 %367, 1
  %369 = shl i64 %366, 1
  %370 = or i64 %369, %368
  %371 = lshr i64 %R10_val.58, 45
  %372 = and i64 %371, 1
  %373 = shl i64 %370, 1
  %374 = or i64 %373, %372
  %RDX_val.59 = load i64* %XDX, align 8, !mcsema_real_eip !52
  %375 = xor i64 %RDX_val.59, %374, !mcsema_real_eip !52
  %RAX_val.62 = load i64* %XAX, align 8, !mcsema_real_eip !53
  %376 = sub i64 %375, %RAX_val.62, !mcsema_real_eip !53
  store i64 %376, i64* %XDX, align 8, !mcsema_real_eip !53
  store i64 %376, i64* %R10, align 8, !mcsema_real_eip !54
  %R8_val.64 = load i64* %R8, align 8, !mcsema_real_eip !55
  %377 = add i64 %R8_val.64, 1
  store i64 %377, i64* %R8, align 8, !mcsema_real_eip !55
  %378 = add i64 %R8_val.64, -3
  %379 = xor i64 %378, %377, !mcsema_real_eip !56
  %380 = and i64 %379, 16, !mcsema_real_eip !56
  %381 = icmp ne i64 %380, 0, !mcsema_real_eip !56
  store i1 %381, i1* %AF, align 1, !mcsema_real_eip !56
  %382 = trunc i64 %378 to i8, !mcsema_real_eip !56
  %383 = tail call i8 @llvm.ctpop.i8(i8 %382), !mcsema_real_eip !56
  %384 = and i8 %383, 1
  %385 = icmp eq i8 %384, 0
  store i1 %385, i1* %PF, align 1, !mcsema_real_eip !56
  %386 = icmp eq i64 %378, 0, !mcsema_real_eip !56
  store i1 %386, i1* %ZF, align 1, !mcsema_real_eip !56
  %387 = icmp slt i64 %378, 0
  store i1 %387, i1* %SF, align 1, !mcsema_real_eip !56
  %388 = icmp ult i64 %377, 4, !mcsema_real_eip !56
  store i1 %388, i1* %CF, align 1, !mcsema_real_eip !56
  %389 = and i64 %379, %377, !mcsema_real_eip !56
  %390 = icmp slt i64 %389, 0
  store i1 %390, i1* %OF, align 1, !mcsema_real_eip !56
  br i1 %386, label %block_0x400898, label %block_0x400843.block_0x400843_crit_edge, !mcsema_real_eip !57

block_0x400843.block_0x400843_crit_edge:          ; preds = %block_0x400843
  %R9_val.36.pre = load i64* %R9, align 8
  %RCX_val.42.pre = load i64* %XCX, align 8
  br label %block_0x400843

block_0x400898:                                   ; preds = %block_0x400843
  %.lcssa = phi i64 [ %376, %block_0x400843 ]
  store i64 727853590754638760, i64* %XAX, align 8, !mcsema_real_eip !58
  %RCX_val.66 = load i64* %XCX, align 8, !mcsema_real_eip !59
  %391 = add i64 %RCX_val.66, -727853590754638760
  %392 = xor i64 %391, %RCX_val.66, !mcsema_real_eip !59
  %393 = and i64 %392, 16, !mcsema_real_eip !59
  %394 = icmp ne i64 %393, 0, !mcsema_real_eip !59
  store i1 %394, i1* %AF, align 1, !mcsema_real_eip !59
  %395 = trunc i64 %391 to i8, !mcsema_real_eip !59
  %396 = tail call i8 @llvm.ctpop.i8(i8 %395), !mcsema_real_eip !59
  %397 = and i8 %396, 1
  %398 = icmp eq i8 %397, 0
  store i1 %398, i1* %PF, align 1, !mcsema_real_eip !59
  %399 = icmp eq i64 %391, 0, !mcsema_real_eip !59
  store i1 %399, i1* %ZF, align 1, !mcsema_real_eip !59
  %400 = icmp slt i64 %391, 0
  store i1 %400, i1* %SF, align 1, !mcsema_real_eip !59
  %401 = icmp ult i64 %RCX_val.66, 727853590754638760, !mcsema_real_eip !59
  store i1 %401, i1* %CF, align 1, !mcsema_real_eip !59
  %402 = and i64 %392, %RCX_val.66, !mcsema_real_eip !59
  %403 = icmp slt i64 %402, 0
  store i1 %403, i1* %OF, align 1, !mcsema_real_eip !59
  br i1 %399, label %block_0x4008a7, label %block_0x4008ea, !mcsema_real_eip !60

block_0x4008a7:                                   ; preds = %block_0x400898
  store i64 -6974870607190376612, i64* %XAX, align 8, !mcsema_real_eip !61
  %RSI_val.68 = load i64* %XSI, align 8, !mcsema_real_eip !62
  %404 = add i64 %RSI_val.68, 6974870607190376612
  %405 = xor i64 %404, %RSI_val.68, !mcsema_real_eip !62
  %406 = and i64 %405, 16
  %407 = icmp eq i64 %406, 0
  store i1 %407, i1* %AF, align 1, !mcsema_real_eip !62
  %408 = trunc i64 %404 to i8, !mcsema_real_eip !62
  %409 = tail call i8 @llvm.ctpop.i8(i8 %408), !mcsema_real_eip !62
  %410 = and i8 %409, 1
  %411 = icmp eq i8 %410, 0
  store i1 %411, i1* %PF, align 1, !mcsema_real_eip !62
  %412 = icmp eq i64 %404, 0, !mcsema_real_eip !62
  store i1 %412, i1* %ZF, align 1, !mcsema_real_eip !62
  %413 = icmp slt i64 %404, 0
  store i1 %413, i1* %SF, align 1, !mcsema_real_eip !62
  %414 = icmp ult i64 %RSI_val.68, -6974870607190376612, !mcsema_real_eip !62
  store i1 %414, i1* %CF, align 1, !mcsema_real_eip !62
  %415 = xor i64 %RSI_val.68, -9223372036854775808, !mcsema_real_eip !62
  %416 = and i64 %405, %415, !mcsema_real_eip !62
  %417 = icmp slt i64 %416, 0
  store i1 %417, i1* %OF, align 1, !mcsema_real_eip !62
  br i1 %412, label %block_0x4008b6, label %block_0x4008ea, !mcsema_real_eip !63

block_0x4008b6:                                   ; preds = %block_0x4008a7
  store i64 5596835378558450713, i64* %XAX, align 8, !mcsema_real_eip !64
  %RDI_val.70 = load i64* %XDI, align 8, !mcsema_real_eip !65
  %418 = add i64 %RDI_val.70, -5596835378558450713
  %419 = xor i64 %418, %RDI_val.70, !mcsema_real_eip !65
  %420 = and i64 %419, 16
  %421 = icmp eq i64 %420, 0
  store i1 %421, i1* %AF, align 1, !mcsema_real_eip !65
  %422 = trunc i64 %418 to i8, !mcsema_real_eip !65
  %423 = tail call i8 @llvm.ctpop.i8(i8 %422), !mcsema_real_eip !65
  %424 = and i8 %423, 1
  %425 = icmp eq i8 %424, 0
  store i1 %425, i1* %PF, align 1, !mcsema_real_eip !65
  %426 = icmp eq i64 %418, 0, !mcsema_real_eip !65
  store i1 %426, i1* %ZF, align 1, !mcsema_real_eip !65
  %427 = icmp slt i64 %418, 0
  store i1 %427, i1* %SF, align 1, !mcsema_real_eip !65
  %428 = icmp ult i64 %RDI_val.70, 5596835378558450713, !mcsema_real_eip !65
  store i1 %428, i1* %CF, align 1, !mcsema_real_eip !65
  %429 = and i64 %419, %RDI_val.70, !mcsema_real_eip !65
  %430 = icmp slt i64 %429, 0
  store i1 %430, i1* %OF, align 1, !mcsema_real_eip !65
  br i1 %426, label %block_0x4008c5, label %block_0x4008ea, !mcsema_real_eip !66

block_0x4008c5:                                   ; preds = %block_0x4008b6
  store i64 -4274187294020637041, i64* %XAX, align 8, !mcsema_real_eip !67
  %431 = add i64 %.lcssa, 4274187294020637041
  %432 = xor i64 %431, %.lcssa, !mcsema_real_eip !68
  %433 = and i64 %432, 16, !mcsema_real_eip !68
  %434 = icmp ne i64 %433, 0, !mcsema_real_eip !68
  store i1 %434, i1* %AF, align 1, !mcsema_real_eip !68
  %435 = trunc i64 %431 to i8, !mcsema_real_eip !68
  %436 = tail call i8 @llvm.ctpop.i8(i8 %435), !mcsema_real_eip !68
  %437 = and i8 %436, 1
  %438 = icmp eq i8 %437, 0
  store i1 %438, i1* %PF, align 1, !mcsema_real_eip !68
  %439 = icmp eq i64 %431, 0, !mcsema_real_eip !68
  store i1 %439, i1* %ZF, align 1, !mcsema_real_eip !68
  %440 = icmp slt i64 %431, 0
  store i1 %440, i1* %SF, align 1, !mcsema_real_eip !68
  %441 = icmp ult i64 %.lcssa, -4274187294020637041, !mcsema_real_eip !68
  store i1 %441, i1* %CF, align 1, !mcsema_real_eip !68
  %442 = xor i64 %.lcssa, -9223372036854775808, !mcsema_real_eip !68
  %443 = and i64 %432, %442, !mcsema_real_eip !68
  %444 = icmp slt i64 %443, 0
  store i1 %444, i1* %OF, align 1, !mcsema_real_eip !68
  br i1 %439, label %block_0x4008d4, label %block_0x4008ea, !mcsema_real_eip !69

block_0x4008d4:                                   ; preds = %block_0x4008c5
  store i64 add (i64 ptrtoint (%0* @data_0x4009a0 to i64), i64 272), i64* %XDI, align 8, !mcsema_real_eip !70
  %RSP_val.75 = load i64* %XSP, align 8, !mcsema_real_eip !71
  %445 = add i64 %RSP_val.75, -8
  %446 = inttoptr i64 %445 to i64*, !mcsema_real_eip !71
  store i64 -2415393069852865332, i64* %446, align 8, !mcsema_real_eip !71
  store i64 %445, i64* %XSP, align 8, !mcsema_real_eip !71
  %447 = tail call x86_64_sysvcc i64 @_puts(i64 add (i64 ptrtoint (%0* @data_0x4009a0 to i64), i64 272)), !mcsema_real_eip !71
  store i64 %447, i64* %XAX, align 8, !mcsema_real_eip !71
  store i64 add (i64 ptrtoint (%0* @data_0x4009a0 to i64), i64 64), i64* %XDI, align 8, !mcsema_real_eip !72
  %RSP_val.77 = load i64* %XSP, align 8, !mcsema_real_eip !73
  %448 = add i64 %RSP_val.77, -8
  %449 = inttoptr i64 %448 to i64*, !mcsema_real_eip !73
  store i64 -2415393069852865332, i64* %449, align 8, !mcsema_real_eip !73
  store i64 %448, i64* %XSP, align 8, !mcsema_real_eip !73
  %450 = tail call x86_64_sysvcc i64 @_puts(i64 add (i64 ptrtoint (%0* @data_0x4009a0 to i64), i64 64)), !mcsema_real_eip !73
  br label %block_0x4008f4, !mcsema_real_eip !74
}

; Function Attrs: noinline
define x86_64_sysvcc void @sub_400680(%RegState* nocapture) #0 {
entry:
  %XIP = getelementptr %RegState* %0, i64 0, i32 0, !mcsema_real_eip !75
  %XAX = getelementptr %RegState* %0, i64 0, i32 1, !mcsema_real_eip !75
  %XSI = getelementptr %RegState* %0, i64 0, i32 5, !mcsema_real_eip !75
  %XDI = getelementptr %RegState* %0, i64 0, i32 6, !mcsema_real_eip !75
  %XBP = getelementptr %RegState* %0, i64 0, i32 8, !mcsema_real_eip !75
  %XSP = getelementptr %RegState* %0, i64 0, i32 7, !mcsema_real_eip !75
  %ZF_full = getelementptr %RegState* %0, i64 0, i32 12, !mcsema_real_eip !75
  %ZF = bitcast i8* %ZF_full to i1*, !mcsema_real_eip !75
  %PF_full = getelementptr %RegState* %0, i64 0, i32 10, !mcsema_real_eip !75
  %PF = bitcast i8* %PF_full to i1*, !mcsema_real_eip !75
  %AF_full = getelementptr %RegState* %0, i64 0, i32 11, !mcsema_real_eip !75
  %AF = bitcast i8* %AF_full to i1*, !mcsema_real_eip !75
  %CF_full = getelementptr %RegState* %0, i64 0, i32 9, !mcsema_real_eip !75
  %CF = bitcast i8* %CF_full to i1*, !mcsema_real_eip !75
  %SF_full = getelementptr %RegState* %0, i64 0, i32 13, !mcsema_real_eip !75
  %SF = bitcast i8* %SF_full to i1*, !mcsema_real_eip !75
  %OF_full = getelementptr %RegState* %0, i64 0, i32 14, !mcsema_real_eip !75
  %OF = bitcast i8* %OF_full to i1*, !mcsema_real_eip !75
  store i64 ptrtoint (%1* @data_0x601010 to i64), i64* %XDI, align 8, !mcsema_real_eip !75
  %1 = load i64* bitcast (%1* @data_0x601010 to i64*), align 64, !mcsema_real_eip !76
  store i1 false, i1* %AF, align 1, !mcsema_real_eip !76
  %2 = trunc i64 %1 to i8, !mcsema_real_eip !76
  %3 = tail call i8 @llvm.ctpop.i8(i8 %2), !mcsema_real_eip !76
  %4 = and i8 %3, 1
  %5 = icmp eq i8 %4, 0
  store i1 %5, i1* %PF, align 1, !mcsema_real_eip !76
  %6 = icmp eq i64 %1, 0, !mcsema_real_eip !76
  store i1 %6, i1* %ZF, align 1, !mcsema_real_eip !76
  %7 = icmp slt i64 %1, 0
  store i1 %7, i1* %SF, align 1, !mcsema_real_eip !76
  store i1 false, i1* %CF, align 1, !mcsema_real_eip !76
  store i1 false, i1* %OF, align 1, !mcsema_real_eip !76
  br i1 %6, label %block_0x400620, label %block_0x400690, !mcsema_real_eip !77

block_0x400690:                                   ; preds = %entry
  store i64 0, i64* %XAX, align 8, !mcsema_real_eip !78
  store i1 true, i1* %ZF, align 1, !mcsema_real_eip !79
  store i1 false, i1* %SF, align 1, !mcsema_real_eip !79
  store i1 true, i1* %PF, align 1, !mcsema_real_eip !79
  store i1 false, i1* %CF, align 1, !mcsema_real_eip !79
  store i1 false, i1* %OF, align 1, !mcsema_real_eip !79
  br label %block_0x400620

block_0x400620:                                   ; preds = %block_0x400690, %entry
  store i64 6296176, i64* %XSI, align 8, !mcsema_real_eip !80
  %RBP_val.87 = load i64* %XBP, align 8, !mcsema_real_eip !81
  %RSP_val.88 = load i64* %XSP, align 8, !mcsema_real_eip !81
  %8 = add i64 %RSP_val.88, -8
  %9 = inttoptr i64 %8 to i64*
  store i64 %RBP_val.87, i64* %9, align 8, !mcsema_real_eip !81
  store i64 %8, i64* %XSP, align 8, !mcsema_real_eip !81
  %RSI_val.89 = load i64* %XSI, align 8, !mcsema_real_eip !82
  %10 = add i64 %RSI_val.89, -6296176
  %11 = ashr i64 %10, 3
  store i64 %8, i64* %XBP, align 8, !mcsema_real_eip !83
  %12 = lshr i64 %11, 63
  store i64 %12, i64* %XAX, align 8, !mcsema_real_eip !84
  %13 = add nsw i64 %12, %11
  %14 = xor i64 %13, %11, !mcsema_real_eip !85
  %15 = and i64 %14, 16, !mcsema_real_eip !85
  %16 = icmp ne i64 %15, 0, !mcsema_real_eip !85
  store i1 %16, i1* %AF, align 1, !mcsema_real_eip !85
  %17 = and i64 %13, 1, !mcsema_real_eip !86
  %18 = icmp ne i64 %17, 0, !mcsema_real_eip !86
  %19 = ashr i64 %13, 1, !mcsema_real_eip !86
  store i1 false, i1* %OF, align 1, !mcsema_real_eip !86
  store i1 %18, i1* %CF, align 1, !mcsema_real_eip !86
  %20 = icmp eq i64 %19, 0, !mcsema_real_eip !86
  store i1 %20, i1* %ZF, align 1, !mcsema_real_eip !86
  %21 = icmp slt i64 %19, 0, !mcsema_real_eip !86
  store i1 %21, i1* %SF, align 1, !mcsema_real_eip !86
  %22 = trunc i64 %19 to i8, !mcsema_real_eip !86
  %23 = tail call i8 @llvm.ctpop.i8(i8 %22), !mcsema_real_eip !86
  %24 = and i8 %23, 1
  %25 = icmp eq i8 %24, 0
  store i1 %25, i1* %PF, align 1, !mcsema_real_eip !86
  store i64 %19, i64* %XSI, align 8, !mcsema_real_eip !86
  br i1 %20, label %block_0x400658, label %block_0x400643, !mcsema_real_eip !87

block_0x400643:                                   ; preds = %block_0x400620
  store i64 0, i64* %XAX, align 8, !mcsema_real_eip !88
  store i1 true, i1* %ZF, align 1, !mcsema_real_eip !89
  store i1 false, i1* %SF, align 1, !mcsema_real_eip !89
  store i1 true, i1* %PF, align 1, !mcsema_real_eip !89
  store i1 false, i1* %CF, align 1, !mcsema_real_eip !89
  store i1 false, i1* %OF, align 1, !mcsema_real_eip !89
  br label %block_0x400658

block_0x400658:                                   ; preds = %block_0x400643, %block_0x400620
  %26 = load i64* %9, align 8, !mcsema_real_eip !90
  store i64 %26, i64* %XBP, align 8, !mcsema_real_eip !90
  store i64 %RSP_val.88, i64* %XSP, align 8, !mcsema_real_eip !90
  %27 = add i64 %RSP_val.88, 8, !mcsema_real_eip !91
  %28 = inttoptr i64 %RSP_val.88 to i64*, !mcsema_real_eip !91
  %29 = load i64* %28, align 8, !mcsema_real_eip !91
  store i64 %29, i64* %XIP, align 8, !mcsema_real_eip !91
  store i64 %27, i64* %XSP, align 8, !mcsema_real_eip !91
  ret void, !mcsema_real_eip !91
}

; Function Attrs: noinline
define x86_64_sysvcc void @sub_400660(%RegState* nocapture) #0 {
entry:
  %XIP = getelementptr %RegState* %0, i64 0, i32 0, !mcsema_real_eip !92
  %XBP = getelementptr %RegState* %0, i64 0, i32 8, !mcsema_real_eip !92
  %XSP = getelementptr %RegState* %0, i64 0, i32 7, !mcsema_real_eip !92
  %ZF_full = getelementptr %RegState* %0, i64 0, i32 12, !mcsema_real_eip !92
  %ZF = bitcast i8* %ZF_full to i1*, !mcsema_real_eip !92
  %PF_full = getelementptr %RegState* %0, i64 0, i32 10, !mcsema_real_eip !92
  %PF = bitcast i8* %PF_full to i1*, !mcsema_real_eip !92
  %AF_full = getelementptr %RegState* %0, i64 0, i32 11, !mcsema_real_eip !92
  %AF = bitcast i8* %AF_full to i1*, !mcsema_real_eip !92
  %CF_full = getelementptr %RegState* %0, i64 0, i32 9, !mcsema_real_eip !92
  %CF = bitcast i8* %CF_full to i1*, !mcsema_real_eip !92
  %SF_full = getelementptr %RegState* %0, i64 0, i32 13, !mcsema_real_eip !92
  %SF = bitcast i8* %SF_full to i1*, !mcsema_real_eip !92
  %OF_full = getelementptr %RegState* %0, i64 0, i32 14, !mcsema_real_eip !92
  %OF = bitcast i8* %OF_full to i1*, !mcsema_real_eip !92
  %1 = load i8* inttoptr (i64 add (i64 ptrtoint (%2* @data_0x601280 to i64), i64 8) to i8*), align 8, !mcsema_real_eip !92
  store i1 false, i1* %AF, align 1, !mcsema_real_eip !92
  %2 = tail call i8 @llvm.ctpop.i8(i8 %1), !mcsema_real_eip !92
  %3 = and i8 %2, 1
  %4 = icmp eq i8 %3, 0
  store i1 %4, i1* %PF, align 1, !mcsema_real_eip !92
  %5 = icmp eq i8 %1, 0, !mcsema_real_eip !92
  store i1 %5, i1* %ZF, align 1, !mcsema_real_eip !92
  %6 = icmp slt i8 %1, 0
  store i1 %6, i1* %SF, align 1, !mcsema_real_eip !92
  store i1 false, i1* %CF, align 1, !mcsema_real_eip !92
  store i1 false, i1* %OF, align 1, !mcsema_real_eip !92
  br i1 %5, label %block_0x400669, label %block_0x40067a, !mcsema_real_eip !93

block_0x400669:                                   ; preds = %entry
  %RBP_val.104 = load i64* %XBP, align 8, !mcsema_real_eip !94
  %RSP_val.105 = load i64* %XSP, align 8, !mcsema_real_eip !94
  %7 = add i64 %RSP_val.105, -8
  %8 = inttoptr i64 %7 to i64*, !mcsema_real_eip !94
  store i64 %RBP_val.104, i64* %8, align 8, !mcsema_real_eip !94
  store i64 %7, i64* %XBP, align 8, !mcsema_real_eip !95
  %9 = add i64 %RSP_val.105, -16
  %10 = inttoptr i64 %9 to i64*, !mcsema_real_eip !96
  store i64 -4981261766360305936, i64* %10, align 8, !mcsema_real_eip !96
  store i64 %9, i64* %XSP, align 8, !mcsema_real_eip !96
  tail call x86_64_sysvcc void @deregister_tm_clones(%RegState* %0), !mcsema_real_eip !96
  %RSP_val.108 = load i64* %XSP, align 8, !mcsema_real_eip !97
  %11 = inttoptr i64 %RSP_val.108 to i64*, !mcsema_real_eip !97
  %12 = load i64* %11, align 8, !mcsema_real_eip !97
  store i64 %12, i64* %XBP, align 8, !mcsema_real_eip !97
  %13 = add i64 %RSP_val.108, 8, !mcsema_real_eip !97
  store i64 %13, i64* %XSP, align 8, !mcsema_real_eip !97
  store i8 1, i8* inttoptr (i64 add (i64 ptrtoint (%2* @data_0x601280 to i64), i64 8) to i8*), align 8, !mcsema_real_eip !98
  br label %block_0x40067a

block_0x40067a:                                   ; preds = %block_0x400669, %entry
  %RSP_val.103 = load i64* %XSP, align 8, !mcsema_real_eip !99
  %14 = add i64 %RSP_val.103, 8, !mcsema_real_eip !99
  %15 = inttoptr i64 %RSP_val.103 to i64*, !mcsema_real_eip !99
  %16 = load i64* %15, align 8, !mcsema_real_eip !99
  store i64 %16, i64* %XIP, align 8, !mcsema_real_eip !99
  store i64 %14, i64* %XSP, align 8, !mcsema_real_eip !99
  ret void, !mcsema_real_eip !99
}

; Function Attrs: noinline
define internal x86_64_sysvcc void @deregister_tm_clones(%RegState* nocapture) #0 {
entry:
  %XIP = getelementptr %RegState* %0, i64 0, i32 0, !mcsema_real_eip !100
  %XAX = getelementptr %RegState* %0, i64 0, i32 1, !mcsema_real_eip !100
  %XBP = getelementptr %RegState* %0, i64 0, i32 8, !mcsema_real_eip !100
  %XSP = getelementptr %RegState* %0, i64 0, i32 7, !mcsema_real_eip !100
  %ZF_full = getelementptr %RegState* %0, i64 0, i32 12, !mcsema_real_eip !100
  %ZF = bitcast i8* %ZF_full to i1*, !mcsema_real_eip !100
  %PF_full = getelementptr %RegState* %0, i64 0, i32 10, !mcsema_real_eip !100
  %PF = bitcast i8* %PF_full to i1*, !mcsema_real_eip !100
  %AF_full = getelementptr %RegState* %0, i64 0, i32 11, !mcsema_real_eip !100
  %AF = bitcast i8* %AF_full to i1*, !mcsema_real_eip !100
  %CF_full = getelementptr %RegState* %0, i64 0, i32 9, !mcsema_real_eip !100
  %CF = bitcast i8* %CF_full to i1*, !mcsema_real_eip !100
  %SF_full = getelementptr %RegState* %0, i64 0, i32 13, !mcsema_real_eip !100
  %SF = bitcast i8* %SF_full to i1*, !mcsema_real_eip !100
  %OF_full = getelementptr %RegState* %0, i64 0, i32 14, !mcsema_real_eip !100
  %OF = bitcast i8* %OF_full to i1*, !mcsema_real_eip !100
  store i64 6296183, i64* %XAX, align 8, !mcsema_real_eip !100
  %RBP_val.109 = load i64* %XBP, align 8, !mcsema_real_eip !101
  %RSP_val.110 = load i64* %XSP, align 8, !mcsema_real_eip !101
  %1 = add i64 %RSP_val.110, -8
  %2 = inttoptr i64 %1 to i64*
  store i64 %RBP_val.109, i64* %2, align 8, !mcsema_real_eip !101
  store i64 %1, i64* %XSP, align 8, !mcsema_real_eip !101
  %RAX_val.111 = load i64* %XAX, align 8, !mcsema_real_eip !102
  %3 = add i64 %RAX_val.111, -6296176
  store i64 %3, i64* %XAX, align 8, !mcsema_real_eip !102
  %4 = add i64 %RAX_val.111, -6296190
  %5 = xor i64 %4, %3, !mcsema_real_eip !103
  %6 = and i64 %5, 16, !mcsema_real_eip !103
  %7 = icmp ne i64 %6, 0, !mcsema_real_eip !103
  store i1 %7, i1* %AF, align 1, !mcsema_real_eip !103
  %8 = trunc i64 %4 to i8, !mcsema_real_eip !103
  %9 = tail call i8 @llvm.ctpop.i8(i8 %8), !mcsema_real_eip !103
  %10 = and i8 %9, 1
  %11 = icmp eq i8 %10, 0
  store i1 %11, i1* %PF, align 1, !mcsema_real_eip !103
  %12 = icmp eq i64 %4, 0, !mcsema_real_eip !103
  store i1 %12, i1* %ZF, align 1, !mcsema_real_eip !103
  %13 = icmp slt i64 %4, 0
  store i1 %13, i1* %SF, align 1, !mcsema_real_eip !103
  %14 = icmp ult i64 %3, 14, !mcsema_real_eip !103
  store i1 %14, i1* %CF, align 1, !mcsema_real_eip !103
  %15 = and i64 %5, %3, !mcsema_real_eip !103
  %16 = icmp slt i64 %15, 0
  store i1 %16, i1* %OF, align 1, !mcsema_real_eip !103
  store i64 %1, i64* %XBP, align 8, !mcsema_real_eip !104
  %17 = or i1 %14, %12, !mcsema_real_eip !105
  br i1 %17, label %block_0x400610, label %block_0x4005f5, !mcsema_real_eip !105

block_0x4005f5:                                   ; preds = %entry
  store i64 0, i64* %XAX, align 8, !mcsema_real_eip !106
  store i1 true, i1* %ZF, align 1, !mcsema_real_eip !107
  store i1 false, i1* %SF, align 1, !mcsema_real_eip !107
  store i1 true, i1* %PF, align 1, !mcsema_real_eip !107
  store i1 false, i1* %CF, align 1, !mcsema_real_eip !107
  store i1 false, i1* %OF, align 1, !mcsema_real_eip !107
  br label %block_0x400610

block_0x400610:                                   ; preds = %block_0x4005f5, %entry
  %18 = load i64* %2, align 8, !mcsema_real_eip !108
  store i64 %18, i64* %XBP, align 8, !mcsema_real_eip !108
  store i64 %RSP_val.110, i64* %XSP, align 8, !mcsema_real_eip !108
  %19 = add i64 %RSP_val.110, 8, !mcsema_real_eip !109
  %20 = inttoptr i64 %RSP_val.110 to i64*, !mcsema_real_eip !109
  %21 = load i64* %20, align 8, !mcsema_real_eip !109
  store i64 %21, i64* %XIP, align 8, !mcsema_real_eip !109
  store i64 %19, i64* %XSP, align 8, !mcsema_real_eip !109
  ret void, !mcsema_real_eip !109
}


; Function Attrs: noinline
define x86_64_sysvcc void @b64d(%RegState*) #0 {
.preheader:
  %XIP = getelementptr %RegState* %0, i64 0, i32 0, !mcsema_real_eip !110
  %XAX = getelementptr %RegState* %0, i64 0, i32 1, !mcsema_real_eip !110
  %XBX = getelementptr %RegState* %0, i64 0, i32 2, !mcsema_real_eip !110
  %XCX = getelementptr %RegState* %0, i64 0, i32 3, !mcsema_real_eip !110
  %XDX = getelementptr %RegState* %0, i64 0, i32 4, !mcsema_real_eip !110
  %XSI = getelementptr %RegState* %0, i64 0, i32 5, !mcsema_real_eip !110
  %XDI = getelementptr %RegState* %0, i64 0, i32 6, !mcsema_real_eip !110
  %XBP = getelementptr %RegState* %0, i64 0, i32 8, !mcsema_real_eip !110
  %XSP = getelementptr %RegState* %0, i64 0, i32 7, !mcsema_real_eip !110
  %ZF_full = getelementptr %RegState* %0, i64 0, i32 12, !mcsema_real_eip !110
  %ZF = bitcast i8* %ZF_full to i1*, !mcsema_real_eip !110
  %PF_full = getelementptr %RegState* %0, i64 0, i32 10, !mcsema_real_eip !110
  %PF = bitcast i8* %PF_full to i1*, !mcsema_real_eip !110
  %AF_full = getelementptr %RegState* %0, i64 0, i32 11, !mcsema_real_eip !110
  %AF = bitcast i8* %AF_full to i1*, !mcsema_real_eip !110
  %CF_full = getelementptr %RegState* %0, i64 0, i32 9, !mcsema_real_eip !110
  %CF = bitcast i8* %CF_full to i1*, !mcsema_real_eip !110
  %SF_full = getelementptr %RegState* %0, i64 0, i32 13, !mcsema_real_eip !110
  %SF = bitcast i8* %SF_full to i1*, !mcsema_real_eip !110
  %OF_full = getelementptr %RegState* %0, i64 0, i32 14, !mcsema_real_eip !110
  %OF = bitcast i8* %OF_full to i1*, !mcsema_real_eip !110
  %DF_full = getelementptr %RegState* %0, i64 0, i32 15, !mcsema_real_eip !110
  %DF = bitcast i8* %DF_full to i1*, !mcsema_real_eip !110
  %R8 = getelementptr %RegState* %0, i64 0, i32 64, !mcsema_real_eip !110
  %RBP_val.120 = load i64* %XBP, align 8, !mcsema_real_eip !110
  %RSP_val.121 = load i64* %XSP, align 8, !mcsema_real_eip !110
  %1 = add i64 %RSP_val.121, -8
  %2 = inttoptr i64 %1 to i64*, !mcsema_real_eip !110
  store i64 %RBP_val.120, i64* %2, align 8, !mcsema_real_eip !110
  %RBX_val.122 = load i64* %XBX, align 8, !mcsema_real_eip !111
  %3 = add i64 %RSP_val.121, -16
  %4 = inttoptr i64 %3 to i64*, !mcsema_real_eip !111
  store i64 %RBX_val.122, i64* %4, align 8, !mcsema_real_eip !111
  %5 = add i64 %RSP_val.121, -216
  %6 = xor i64 %5, %3, !mcsema_real_eip !112
  %7 = and i64 %6, 16, !mcsema_real_eip !112
  %8 = icmp ne i64 %7, 0, !mcsema_real_eip !112
  store i1 %8, i1* %AF, align 1, !mcsema_real_eip !112
  %9 = trunc i64 %5 to i8, !mcsema_real_eip !112
  %10 = tail call i8 @llvm.ctpop.i8(i8 %9), !mcsema_real_eip !112
  %11 = and i8 %10, 1
  %12 = icmp eq i8 %11, 0
  store i1 %12, i1* %PF, align 1, !mcsema_real_eip !112
  %13 = icmp eq i64 %5, 0, !mcsema_real_eip !112
  store i1 %13, i1* %ZF, align 1, !mcsema_real_eip !112
  %14 = icmp slt i64 %5, 0
  store i1 %14, i1* %SF, align 1, !mcsema_real_eip !112
  %15 = icmp ult i64 %3, 200, !mcsema_real_eip !112
  store i1 %15, i1* %CF, align 1, !mcsema_real_eip !112
  %16 = and i64 %6, %3, !mcsema_real_eip !112
  %17 = icmp slt i64 %16, 0
  store i1 %17, i1* %OF, align 1, !mcsema_real_eip !112
  store i64 %5, i64* %XSP, align 8, !mcsema_real_eip !112
  %RDI_val.125 = load i64* %XDI, align 8, !mcsema_real_eip !113
  store i64 %RDI_val.125, i64* %R8, align 8, !mcsema_real_eip !113
  %RSI_val.126 = load i64* %XSI, align 8, !mcsema_real_eip !114
  store i64 %RSI_val.126, i64* %XBP, align 8, !mcsema_real_eip !114
  store i64 %5, i64* %XDI, align 8, !mcsema_real_eip !115
  store i64 24, i64* %XCX, align 8, !mcsema_real_eip !116
  store i64 0, i64* %XAX, align 8, !mcsema_real_eip !117
  br label %55

block_0x400712:                                   ; preds = %block_0x4006df, %block_0x400712.outer
  %RCX_val.132 = phi i64 [ %18, %block_0x4006df ], [ %RCX_val.132.ph, %block_0x400712.outer ]
  %RSI_val.190 = phi i64 [ %125, %block_0x4006df ], [ 0, %block_0x400712.outer ]
  store i64 %RSI_val.190, i64* %XSI, align 8
  %uadd = tail call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %RCX_val.132, i64 1)
  %18 = extractvalue { i64, i1 } %uadd, 0
  %19 = xor i64 %18, %RCX_val.132, !mcsema_real_eip !118
  %20 = and i64 %19, 16, !mcsema_real_eip !118
  %21 = icmp ne i64 %20, 0, !mcsema_real_eip !118
  store i1 %21, i1* %AF, align 1, !mcsema_real_eip !118
  %22 = icmp slt i64 %18, 0
  store i1 %22, i1* %SF, align 1, !mcsema_real_eip !118
  %23 = icmp eq i64 %18, 0, !mcsema_real_eip !118
  store i1 %23, i1* %ZF, align 1, !mcsema_real_eip !118
  %24 = xor i64 %RCX_val.132, -9223372036854775808, !mcsema_real_eip !118
  %25 = and i64 %19, %24, !mcsema_real_eip !118
  %26 = icmp slt i64 %25, 0
  store i1 %26, i1* %OF, align 1, !mcsema_real_eip !118
  %27 = trunc i64 %18 to i8, !mcsema_real_eip !118
  %28 = tail call i8 @llvm.ctpop.i8(i8 %27), !mcsema_real_eip !118
  %29 = and i8 %28, 1
  %30 = icmp eq i8 %29, 0
  store i1 %30, i1* %PF, align 1, !mcsema_real_eip !118
  %31 = extractvalue { i64, i1 } %uadd, 1
  store i1 %31, i1* %CF, align 1, !mcsema_real_eip !118
  store i64 %18, i64* %XCX, align 8, !mcsema_real_eip !118
  %R8_val.133 = load i64* %R8, align 8, !mcsema_real_eip !119
  %32 = add i64 %18, -1, !mcsema_real_eip !119
  %33 = add i64 %32, %R8_val.133, !mcsema_real_eip !119
  %34 = inttoptr i64 %33 to i8*, !mcsema_real_eip !119
  %35 = load i8* %34, align 1, !mcsema_real_eip !119
  %36 = zext i8 %35 to i64
  store i64 %36, i64* %XDI, align 8, !mcsema_real_eip !119
  %37 = zext i8 %35 to i64
  store i64 %37, i64* %XDX, align 8, !mcsema_real_eip !120
  %38 = add i64 %37, add (i64 ptrtoint (%0* @data_0x4009a0 to i64), i64 352), !mcsema_real_eip !121
  %39 = inttoptr i64 %38 to i8*, !mcsema_real_eip !121
  %40 = load i8* %39, align 1, !mcsema_real_eip !121
  %41 = zext i8 %40 to i64
  store i64 %41, i64* %XDX, align 8, !mcsema_real_eip !121
  %42 = add i8 %40, 1
  %43 = xor i8 %42, %40, !mcsema_real_eip !122
  %44 = and i8 %43, 16
  %45 = icmp eq i8 %44, 0
  store i1 %45, i1* %AF, align 1, !mcsema_real_eip !122
  %46 = tail call i8 @llvm.ctpop.i8(i8 %42), !mcsema_real_eip !122
  %47 = and i8 %46, 1
  %48 = icmp eq i8 %47, 0
  store i1 %48, i1* %PF, align 1, !mcsema_real_eip !122
  %49 = icmp eq i8 %42, 0, !mcsema_real_eip !122
  store i1 %49, i1* %ZF, align 1, !mcsema_real_eip !122
  %50 = icmp slt i8 %42, 0
  store i1 %50, i1* %SF, align 1, !mcsema_real_eip !122
  %51 = icmp ne i8 %40, -1
  store i1 %51, i1* %CF, align 1, !mcsema_real_eip !122
  %52 = xor i8 %40, -128, !mcsema_real_eip !122
  %53 = and i8 %43, %52, !mcsema_real_eip !122
  %54 = icmp slt i8 %53, 0
  store i1 %54, i1* %OF, align 1, !mcsema_real_eip !122
  br i1 %49, label %block_0x40072c, label %block_0x4006d1, !mcsema_real_eip !123

; <label>:55                                      ; preds = %._crit_edge, %.preheader
  %RAX_val.129 = phi i64 [ 0, %.preheader ], [ %RAX_val.129.pre, %._crit_edge ]
  %RDI_val.128 = phi i64 [ %5, %.preheader ], [ %58, %._crit_edge ]
  %56 = inttoptr i64 %RDI_val.128 to i64*, !mcsema_real_eip !124
  store i64 %RAX_val.129, i64* %56, align 8, !mcsema_real_eip !124
  %57 = load i1* %DF, align 1, !mcsema_real_eip !124
  %.v = select i1 %57, i64 -8, i64 8
  %58 = add i64 %.v, %RDI_val.128
  store i64 %58, i64* %XDI, align 8, !mcsema_real_eip !124
  %RCX_val.131 = load i64* %XCX, align 8, !mcsema_real_eip !124
  %59 = add i64 %RCX_val.131, -1
  store i64 %59, i64* %XCX, align 8, !mcsema_real_eip !124
  %60 = icmp eq i64 %59, 0, !mcsema_real_eip !124
  br i1 %60, label %.loopexit, label %._crit_edge, !mcsema_real_eip !124

._crit_edge:                                      ; preds = %55
  %RAX_val.129.pre = load i64* %XAX, align 8
  br label %55

.loopexit:                                        ; preds = %55
  store i64 0, i64* %XBX, align 8, !mcsema_real_eip !125
  %EAX.142 = bitcast i64* %XAX to i32*
  br label %block_0x400712.outer, !mcsema_real_eip !126

block_0x400712.outer:                             ; preds = %block_0x4006e5, %.loopexit
  %RBX_val.186.ph = phi i64 [ %150, %block_0x4006e5 ], [ 0, %.loopexit ]
  %RCX_val.132.ph = phi i64 [ %RCX_val.132.pre.pre, %block_0x4006e5 ], [ 0, %.loopexit ]
  br label %block_0x400712

block_0x40072c:                                   ; preds = %block_0x400712
  %RBX_val.186.ph.lcssa = phi i64 [ %RBX_val.186.ph, %block_0x400712 ]
  %.lcssa68 = phi i8 [ %35, %block_0x400712 ]
  %R8_val.133.lcssa = phi i64 [ %R8_val.133, %block_0x400712 ]
  %.lcssa = phi i64 [ %18, %block_0x400712 ]
  %61 = add i8 %.lcssa68, -61
  %62 = xor i8 %61, %.lcssa68, !mcsema_real_eip !127
  %63 = and i8 %62, 16
  %64 = icmp eq i8 %63, 0
  store i1 %64, i1* %AF, align 1, !mcsema_real_eip !127
  %65 = tail call i8 @llvm.ctpop.i8(i8 %61), !mcsema_real_eip !127
  %66 = and i8 %65, 1
  %67 = icmp eq i8 %66, 0
  store i1 %67, i1* %PF, align 1, !mcsema_real_eip !127
  %68 = icmp eq i8 %61, 0, !mcsema_real_eip !127
  store i1 %68, i1* %ZF, align 1, !mcsema_real_eip !127
  %69 = icmp slt i8 %61, 0
  store i1 %69, i1* %SF, align 1, !mcsema_real_eip !127
  %70 = icmp ult i8 %.lcssa68, 61, !mcsema_real_eip !127
  store i1 %70, i1* %CF, align 1, !mcsema_real_eip !127
  %71 = and i8 %62, %.lcssa68, !mcsema_real_eip !127
  %72 = icmp slt i8 %71, 0
  store i1 %72, i1* %OF, align 1, !mcsema_real_eip !127
  br i1 %68, label %block_0x400732, label %block_0x400769, !mcsema_real_eip !128

block_0x4006d1:                                   ; preds = %block_0x400712
  %EAX_val.143 = load i32* %EAX.142, align 4, !mcsema_real_eip !129
  %73 = shl i32 %EAX_val.143, 6
  %74 = zext i8 %40 to i64
  store i64 %74, i64* %XDX, align 8, !mcsema_real_eip !130
  %trunc47 = zext i8 %40 to i32
  %75 = or i32 %trunc47, %73, !mcsema_real_eip !131
  %76 = zext i32 %75 to i64, !mcsema_real_eip !131
  store i64 %76, i64* %XAX, align 8, !mcsema_real_eip !131
  %77 = add i64 %RSI_val.190, -2
  %78 = xor i64 %77, %RSI_val.190, !mcsema_real_eip !132
  %79 = and i64 %78, 16, !mcsema_real_eip !132
  %80 = icmp ne i64 %79, 0, !mcsema_real_eip !132
  store i1 %80, i1* %AF, align 1, !mcsema_real_eip !132
  %81 = trunc i64 %77 to i8, !mcsema_real_eip !132
  %82 = tail call i8 @llvm.ctpop.i8(i8 %81), !mcsema_real_eip !132
  %83 = and i8 %82, 1
  %84 = icmp eq i8 %83, 0
  store i1 %84, i1* %PF, align 1, !mcsema_real_eip !132
  %85 = icmp eq i64 %77, 0, !mcsema_real_eip !132
  store i1 %85, i1* %ZF, align 1, !mcsema_real_eip !132
  %86 = icmp slt i64 %77, 0
  store i1 %86, i1* %SF, align 1, !mcsema_real_eip !132
  %87 = icmp ult i64 %RSI_val.190, 2, !mcsema_real_eip !132
  store i1 %87, i1* %CF, align 1, !mcsema_real_eip !132
  %88 = and i64 %78, %RSI_val.190, !mcsema_real_eip !132
  %89 = icmp slt i64 %88, 0
  store i1 %89, i1* %OF, align 1, !mcsema_real_eip !132
  %.demorgan = or i1 %87, %85
  br i1 %.demorgan, label %block_0x4006df, label %block_0x4006e5, !mcsema_real_eip !133

block_0x400732:                                   ; preds = %block_0x40072c
  %EAX_val.159 = load i32* %EAX.142, align 4, !mcsema_real_eip !134
  %.mask19 = and i32 %EAX_val.159, 67108864
  %90 = icmp ne i32 %.mask19, 0
  %91 = shl i32 %EAX_val.159, 6
  store i1 %72, i1* %OF, align 1, !mcsema_real_eip !134
  store i1 %90, i1* %CF, align 1, !mcsema_real_eip !134
  %92 = icmp eq i32 %91, 0, !mcsema_real_eip !134
  store i1 %92, i1* %ZF, align 1, !mcsema_real_eip !134
  %93 = icmp slt i32 %91, 0, !mcsema_real_eip !134
  store i1 %93, i1* %SF, align 1, !mcsema_real_eip !134
  %94 = trunc i32 %91 to i8, !mcsema_real_eip !134
  %95 = tail call i8 @llvm.ctpop.i8(i8 %94), !mcsema_real_eip !134
  %96 = and i8 %95, 1
  %97 = icmp eq i8 %96, 0
  store i1 %97, i1* %PF, align 1, !mcsema_real_eip !134
  %98 = zext i32 %91 to i64, !mcsema_real_eip !134
  store i64 %98, i64* %XAX, align 8, !mcsema_real_eip !134
  %99 = add i64 %RBX_val.186.ph.lcssa, 2, !mcsema_real_eip !135
  store i64 %99, i64* %XSI, align 8, !mcsema_real_eip !135
  %100 = add i64 %.lcssa, %R8_val.133.lcssa, !mcsema_real_eip !136
  %101 = inttoptr i64 %100 to i8*, !mcsema_real_eip !136
  %102 = load i8* %101, align 1, !mcsema_real_eip !136
  %103 = add i8 %102, -61
  %104 = xor i8 %103, %102, !mcsema_real_eip !136
  %105 = and i8 %104, 16
  %106 = icmp eq i8 %105, 0
  store i1 %106, i1* %AF, align 1, !mcsema_real_eip !136
  %107 = tail call i8 @llvm.ctpop.i8(i8 %103), !mcsema_real_eip !136
  %108 = and i8 %107, 1
  %109 = icmp eq i8 %108, 0
  store i1 %109, i1* %PF, align 1, !mcsema_real_eip !136
  %110 = icmp eq i8 %103, 0, !mcsema_real_eip !136
  store i1 %110, i1* %ZF, align 1, !mcsema_real_eip !136
  %111 = icmp slt i8 %103, 0
  store i1 %111, i1* %SF, align 1, !mcsema_real_eip !136
  %112 = icmp ult i8 %102, 61, !mcsema_real_eip !136
  store i1 %112, i1* %CF, align 1, !mcsema_real_eip !136
  %113 = and i8 %104, %102, !mcsema_real_eip !136
  %114 = icmp slt i8 %113, 0
  store i1 %114, i1* %OF, align 1, !mcsema_real_eip !136
  br i1 %110, label %block_0x400740, label %block_0x400747, !mcsema_real_eip !137

block_0x400769:                                   ; preds = %block_0x400747, %block_0x40072c
  %RBX_val.151 = phi i64 [ %RBX_val.186.ph.lcssa, %block_0x40072c ], [ %RSI_val.231, %block_0x400747 ]
  store i64 %RBX_val.151, i64* %XDI, align 8, !mcsema_real_eip !138
  %RSP_val.153 = load i64* %XSP, align 8, !mcsema_real_eip !139
  %115 = add i64 %RSP_val.153, -8
  %116 = inttoptr i64 %115 to i64*, !mcsema_real_eip !139
  store i64 -2415393069852865332, i64* %116, align 8, !mcsema_real_eip !139
  store i64 %115, i64* %XSP, align 8, !mcsema_real_eip !139
  %117 = tail call x86_64_sysvcc i64 @_malloc(i64 %RBX_val.151), !mcsema_real_eip !139
  store i64 %117, i64* %XAX, align 8, !mcsema_real_eip !139
  %RBP_val.154 = load i64* %XBP, align 8, !mcsema_real_eip !140
  %118 = inttoptr i64 %RBP_val.154 to i64*, !mcsema_real_eip !140
  store i64 %117, i64* %118, align 8, !mcsema_real_eip !140
  %RAX_val.156 = load i64* %XAX, align 8, !mcsema_real_eip !141
  %119 = icmp eq i64 %RAX_val.156, 0, !mcsema_real_eip !141
  store i1 %119, i1* %ZF, align 1, !mcsema_real_eip !141
  %120 = icmp slt i64 %RAX_val.156, 0
  store i1 %120, i1* %SF, align 1, !mcsema_real_eip !141
  %121 = trunc i64 %RAX_val.156 to i8, !mcsema_real_eip !141
  %122 = tail call i8 @llvm.ctpop.i8(i8 %121), !mcsema_real_eip !141
  %123 = and i8 %122, 1
  %124 = icmp eq i8 %123, 0
  store i1 %124, i1* %PF, align 1, !mcsema_real_eip !141
  store i1 false, i1* %CF, align 1, !mcsema_real_eip !141
  store i1 false, i1* %OF, align 1, !mcsema_real_eip !141
  br i1 %119, label %block_0x40077a, label %block_0x400784, !mcsema_real_eip !142

block_0x4006df:                                   ; preds = %block_0x4006d1
  %uadd2 = tail call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %RSI_val.190, i64 1)
  %125 = extractvalue { i64, i1 } %uadd2, 0
  %126 = xor i64 %125, %RSI_val.190, !mcsema_real_eip !143
  %127 = and i64 %126, 16, !mcsema_real_eip !143
  %128 = icmp ne i64 %127, 0, !mcsema_real_eip !143
  store i1 %128, i1* %AF, align 1, !mcsema_real_eip !143
  %129 = icmp slt i64 %125, 0
  store i1 %129, i1* %SF, align 1, !mcsema_real_eip !143
  %130 = icmp eq i64 %125, 0, !mcsema_real_eip !143
  store i1 %130, i1* %ZF, align 1, !mcsema_real_eip !143
  %131 = xor i64 %RSI_val.190, -9223372036854775808, !mcsema_real_eip !143
  %132 = and i64 %126, %131, !mcsema_real_eip !143
  %133 = icmp slt i64 %132, 0
  store i1 %133, i1* %OF, align 1, !mcsema_real_eip !143
  %134 = trunc i64 %125 to i8, !mcsema_real_eip !143
  %135 = tail call i8 @llvm.ctpop.i8(i8 %134), !mcsema_real_eip !143
  %136 = and i8 %135, 1
  %137 = icmp eq i8 %136, 0
  store i1 %137, i1* %PF, align 1, !mcsema_real_eip !143
  %138 = extractvalue { i64, i1 } %uadd2, 1
  store i1 %138, i1* %CF, align 1, !mcsema_real_eip !143
  br label %block_0x400712, !mcsema_real_eip !144

block_0x4006e5:                                   ; preds = %block_0x4006d1
  %.lcssa71 = phi i32 [ %75, %block_0x4006d1 ]
  %.lcssa70 = phi i32 [ %73, %block_0x4006d1 ]
  %EAX_val.143.lcssa = phi i32 [ %EAX_val.143, %block_0x4006d1 ]
  %139 = lshr i32 %EAX_val.143.lcssa, 10
  %140 = and i32 %139, 255
  %141 = zext i32 %140 to i64, !mcsema_real_eip !145
  store i64 %141, i64* %XSI, align 8, !mcsema_real_eip !145
  %142 = shl i32 %.lcssa71, 16
  %143 = and i32 %142, 16711680
  %144 = or i32 %140, %143, !mcsema_real_eip !146
  %145 = zext i32 %144 to i64, !mcsema_real_eip !146
  store i64 %145, i64* %XDX, align 8, !mcsema_real_eip !146
  %146 = and i32 %.lcssa70, 65280, !mcsema_real_eip !147
  %147 = or i32 %144, %146, !mcsema_real_eip !148
  %RSP_val.185 = load i64* %XSP, align 8, !mcsema_real_eip !149
  %148 = add i64 %RBX_val.186.ph, %RSP_val.185, !mcsema_real_eip !149
  %149 = inttoptr i64 %148 to i32*, !mcsema_real_eip !149
  store i32 %147, i32* %149, align 4, !mcsema_real_eip !149
  %RBX_val.189 = load i64* %XBX, align 8, !mcsema_real_eip !150
  %uadd3 = tail call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %RBX_val.189, i64 3)
  %150 = extractvalue { i64, i1 } %uadd3, 0
  %151 = xor i64 %150, %RBX_val.189, !mcsema_real_eip !150
  %152 = and i64 %151, 16, !mcsema_real_eip !150
  %153 = icmp ne i64 %152, 0, !mcsema_real_eip !150
  store i1 %153, i1* %AF, align 1, !mcsema_real_eip !150
  %154 = icmp slt i64 %150, 0
  store i1 %154, i1* %SF, align 1, !mcsema_real_eip !150
  %155 = icmp eq i64 %150, 0, !mcsema_real_eip !150
  store i1 %155, i1* %ZF, align 1, !mcsema_real_eip !150
  %156 = xor i64 %RBX_val.189, -9223372036854775808, !mcsema_real_eip !150
  %157 = and i64 %151, %156, !mcsema_real_eip !150
  %158 = icmp slt i64 %157, 0
  store i1 %158, i1* %OF, align 1, !mcsema_real_eip !150
  %159 = trunc i64 %150 to i8, !mcsema_real_eip !150
  %160 = tail call i8 @llvm.ctpop.i8(i8 %159), !mcsema_real_eip !150
  %161 = and i8 %160, 1
  %162 = icmp eq i8 %161, 0
  store i1 %162, i1* %PF, align 1, !mcsema_real_eip !150
  %163 = extractvalue { i64, i1 } %uadd3, 1
  store i1 %163, i1* %CF, align 1, !mcsema_real_eip !150
  store i64 %150, i64* %XBX, align 8, !mcsema_real_eip !150
  store i64 0, i64* %XAX, align 8, !mcsema_real_eip !151
  %RCX_val.132.pre.pre = load i64* %XCX, align 8
  br label %block_0x400712.outer, !mcsema_real_eip !143

block_0x40077a:                                   ; preds = %block_0x400769
  store i64 4294967295, i64* %XDI, align 8, !mcsema_real_eip !152
  %RSP_val.204 = load i64* %XSP, align 8, !mcsema_real_eip !153
  %164 = add i64 %RSP_val.204, -8
  %165 = inttoptr i64 %164 to i64*, !mcsema_real_eip !153
  store i64 -2415393069852865332, i64* %165, align 8, !mcsema_real_eip !153
  store i64 %164, i64* %XSP, align 8, !mcsema_real_eip !153
  %166 = tail call x86_64_sysvcc i64 @_exit(i64 4294967295), !mcsema_real_eip !153
  store i64 %166, i64* %XAX, align 8, !mcsema_real_eip !153
  br label %block_0x400784, !mcsema_real_eip !154

block_0x400784:                                   ; preds = %block_0x40077a, %block_0x400769
  %RAX_val.193 = phi i64 [ %RAX_val.156, %block_0x400769 ], [ %166, %block_0x40077a ]
  %RBX_val.191 = load i64* %XBX, align 8, !mcsema_real_eip !155
  store i64 %RBX_val.191, i64* %XDX, align 8, !mcsema_real_eip !155
  %RSP_val.192 = load i64* %XSP, align 8
  store i64 %RSP_val.192, i64* %XSI, align 8, !mcsema_real_eip !156
  store i64 %RAX_val.193, i64* %XDI, align 8, !mcsema_real_eip !157
  %167 = add i64 %RSP_val.192, -8
  %168 = inttoptr i64 %167 to i64*, !mcsema_real_eip !158
  store i64 -2415393069852865332, i64* %168, align 8, !mcsema_real_eip !158
  store i64 %167, i64* %XSP, align 8, !mcsema_real_eip !158
  %169 = tail call x86_64_sysvcc i64 @_memcpy(i64 %RAX_val.193, i64 %RSP_val.192, i64 %RBX_val.191), !mcsema_real_eip !158
  %RBX_val.198 = load i64* %XBX, align 8, !mcsema_real_eip !159
  store i64 %RBX_val.198, i64* %XAX, align 8, !mcsema_real_eip !159
  %RSP_val.199 = load i64* %XSP, align 8, !mcsema_real_eip !160
  %uadd1 = tail call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %RSP_val.199, i64 200)
  %170 = extractvalue { i64, i1 } %uadd1, 0
  %171 = xor i64 %170, %RSP_val.199, !mcsema_real_eip !160
  %172 = and i64 %171, 16, !mcsema_real_eip !160
  %173 = icmp ne i64 %172, 0, !mcsema_real_eip !160
  store i1 %173, i1* %AF, align 1, !mcsema_real_eip !160
  %174 = icmp slt i64 %170, 0
  store i1 %174, i1* %SF, align 1, !mcsema_real_eip !160
  %175 = icmp eq i64 %170, 0, !mcsema_real_eip !160
  store i1 %175, i1* %ZF, align 1, !mcsema_real_eip !160
  %176 = xor i64 %RSP_val.199, -9223372036854775808, !mcsema_real_eip !160
  %177 = and i64 %171, %176, !mcsema_real_eip !160
  %178 = icmp slt i64 %177, 0
  store i1 %178, i1* %OF, align 1, !mcsema_real_eip !160
  %179 = trunc i64 %170 to i8, !mcsema_real_eip !160
  %180 = tail call i8 @llvm.ctpop.i8(i8 %179), !mcsema_real_eip !160
  %181 = and i8 %180, 1
  %182 = icmp eq i8 %181, 0
  store i1 %182, i1* %PF, align 1, !mcsema_real_eip !160
  %183 = extractvalue { i64, i1 } %uadd1, 1
  store i1 %183, i1* %CF, align 1, !mcsema_real_eip !160
  store i64 %170, i64* %XSP, align 8, !mcsema_real_eip !160
  %184 = inttoptr i64 %170 to i64*, !mcsema_real_eip !161
  %185 = load i64* %184, align 8, !mcsema_real_eip !161
  store i64 %185, i64* %XBX, align 8, !mcsema_real_eip !161
  %186 = add i64 %170, 8, !mcsema_real_eip !161
  store i64 %186, i64* %XSP, align 8, !mcsema_real_eip !161
  %187 = inttoptr i64 %186 to i64*, !mcsema_real_eip !162
  %188 = load i64* %187, align 8, !mcsema_real_eip !162
  store i64 %188, i64* %XBP, align 8, !mcsema_real_eip !162
  %189 = add i64 %170, 16, !mcsema_real_eip !162
  store i64 %189, i64* %XSP, align 8, !mcsema_real_eip !162
  %190 = add i64 %170, 24, !mcsema_real_eip !163
  %191 = inttoptr i64 %189 to i64*, !mcsema_real_eip !163
  %192 = load i64* %191, align 8, !mcsema_real_eip !163
  store i64 %192, i64* %XIP, align 8, !mcsema_real_eip !163
  store i64 %190, i64* %XSP, align 8, !mcsema_real_eip !163
  ret void, !mcsema_real_eip !163

block_0x400740:                                   ; preds = %block_0x400732
  %.mask25 = and i32 %91, 67108864
  %193 = icmp ne i32 %.mask25, 0
  %194 = shl i32 %EAX_val.159, 12
  store i1 %114, i1* %OF, align 1, !mcsema_real_eip !164
  store i1 %193, i1* %CF, align 1, !mcsema_real_eip !164
  %195 = icmp eq i32 %194, 0, !mcsema_real_eip !164
  store i1 %195, i1* %ZF, align 1, !mcsema_real_eip !164
  %196 = icmp slt i32 %194, 0, !mcsema_real_eip !164
  store i1 %196, i1* %SF, align 1, !mcsema_real_eip !164
  store i1 true, i1* %PF, align 1, !mcsema_real_eip !164
  %197 = zext i32 %194 to i64, !mcsema_real_eip !164
  store i64 %197, i64* %XAX, align 8, !mcsema_real_eip !164
  %198 = add i64 %RBX_val.186.ph.lcssa, 1, !mcsema_real_eip !165
  store i64 %198, i64* %XSI, align 8, !mcsema_real_eip !165
  br label %block_0x400747

block_0x400747:                                   ; preds = %block_0x400740, %block_0x400732
  %EAX_val.222 = phi i32 [ %91, %block_0x400732 ], [ %194, %block_0x400740 ]
  %199 = lshr i32 %EAX_val.222, 16
  %200 = and i32 %199, 255
  %201 = zext i32 %200 to i64, !mcsema_real_eip !166
  store i64 %201, i64* %XCX, align 8, !mcsema_real_eip !166
  %202 = shl i32 %EAX_val.222, 16
  %203 = and i32 %202, 12582912
  %204 = or i32 %200, %203, !mcsema_real_eip !167
  %205 = zext i32 %204 to i64, !mcsema_real_eip !167
  store i64 %205, i64* %XDX, align 8, !mcsema_real_eip !167
  %206 = and i32 %EAX_val.222, 65280, !mcsema_real_eip !168
  %207 = or i32 %204, %206, !mcsema_real_eip !169
  store i1 false, i1* %OF, align 1, !mcsema_real_eip !169
  store i1 false, i1* %CF, align 1, !mcsema_real_eip !169
  store i1 false, i1* %SF, align 1, !mcsema_real_eip !169
  %208 = icmp eq i32 %207, 0, !mcsema_real_eip !169
  store i1 %208, i1* %ZF, align 1, !mcsema_real_eip !169
  %209 = trunc i32 %199 to i8, !mcsema_real_eip !169
  %210 = tail call i8 @llvm.ctpop.i8(i8 %209), !mcsema_real_eip !169
  %211 = and i8 %210, 1
  %212 = icmp eq i8 %211, 0
  store i1 %212, i1* %PF, align 1, !mcsema_real_eip !169
  %213 = zext i32 %207 to i64, !mcsema_real_eip !169
  store i64 %213, i64* %XAX, align 8, !mcsema_real_eip !169
  %RSP_val.227 = load i64* %XSP, align 8, !mcsema_real_eip !170
  %214 = add i64 %RBX_val.186.ph.lcssa, %RSP_val.227, !mcsema_real_eip !170
  %215 = inttoptr i64 %214 to i32*, !mcsema_real_eip !170
  store i32 %207, i32* %215, align 4, !mcsema_real_eip !170
  %RSI_val.231 = load i64* %XSI, align 8, !mcsema_real_eip !171
  store i64 %RSI_val.231, i64* %XBX, align 8, !mcsema_real_eip !171
  br label %block_0x400769, !mcsema_real_eip !164
}



declare x86_64_sysvcc void @b64d_fake(%RegState*) #0

; Function Attrs: nounwind readnone
declare i8 @llvm.ctpop.i8(i8) #1

; Function Attrs: naked noinline
declare x86_64_sysvcc i64 @_puts(i64) #2

; Function Attrs: naked noinline
declare x86_64_sysvcc i64 @_fgets(i64, i64, i64) #2

; Function Attrs: naked noinline
declare x86_64_sysvcc i64 @_free(i64) #2

; Function Attrs: naked noinline
declare x86_64_sysvcc i64 @_malloc(i64) #2

; Function Attrs: naked noinline
declare x86_64_sysvcc i64 @_memcpy(i64, i64, i64) #2

; Function Attrs: naked noinline
declare x86_64_sysvcc i64 @_exit(i64) #2

; Function Attrs: nounwind readnone
declare { i64, i1 } @llvm.uadd.with.overflow.i64(i64, i64) #1

attributes #0 = { noinline }
attributes #1 = { nounwind readnone }
attributes #2 = { naked noinline }

!0 = metadata !{i64 4196255}
!1 = metadata !{i64 4196259}
!2 = metadata !{i64 4196267}
!3 = metadata !{i64 4196276}
!4 = metadata !{i64 4196285}
!5 = metadata !{i64 4196294}
!6 = metadata !{i64 4196299}
!7 = metadata !{i64 4196304}
!8 = metadata !{i64 4196311}
!9 = metadata !{i64 4196316}
!10 = metadata !{i64 4196321}
!11 = metadata !{i64 4196326}
!12 = metadata !{i64 4196331}
!13 = metadata !{i64 4196336}
!14 = metadata !{i64 4196357}
!15 = metadata !{i64 4196586}
!16 = metadata !{i64 4196364}
!17 = metadata !{i64 4196369}
!18 = metadata !{i64 4196374}
!19 = metadata !{i64 4196379}
!20 = metadata !{i64 4196383}
!21 = metadata !{i64 4196343}
!22 = metadata !{i64 4196345}
!23 = metadata !{i64 4196348}
!24 = metadata !{i64 4196355}
!25 = metadata !{i64 4196389}
!26 = metadata !{i64 4196393}
!27 = metadata !{i64 4196398}
!28 = metadata !{i64 4196403}
!29 = metadata !{i64 4196408}
!30 = metadata !{i64 4196413}
!31 = metadata !{i64 4196596}
!32 = metadata !{i64 4196591}
!33 = metadata !{i64 4196601}
!34 = metadata !{i64 4196606}
!35 = metadata !{i64 4196611}
!36 = metadata !{i64 4196615}
!37 = metadata !{i64 4196427}
!38 = metadata !{i64 4196430}
!39 = metadata !{i64 4196437}
!40 = metadata !{i64 4196440}
!41 = metadata !{i64 4196447}
!42 = metadata !{i64 4196451}
!43 = metadata !{i64 4196454}
!44 = metadata !{i64 4196457}
!45 = metadata !{i64 4196461}
!46 = metadata !{i64 4196464}
!47 = metadata !{i64 4196467}
!48 = metadata !{i64 4196471}
!49 = metadata !{i64 4196475}
!50 = metadata !{i64 4196478}
!51 = metadata !{i64 4196481}
!52 = metadata !{i64 4196485}
!53 = metadata !{i64 4196488}
!54 = metadata !{i64 4196491}
!55 = metadata !{i64 4196494}
!56 = metadata !{i64 4196498}
!57 = metadata !{i64 4196502}
!58 = metadata !{i64 4196504}
!59 = metadata !{i64 4196514}
!60 = metadata !{i64 4196517}
!61 = metadata !{i64 4196519}
!62 = metadata !{i64 4196529}
!63 = metadata !{i64 4196532}
!64 = metadata !{i64 4196534}
!65 = metadata !{i64 4196544}
!66 = metadata !{i64 4196547}
!67 = metadata !{i64 4196549}
!68 = metadata !{i64 4196559}
!69 = metadata !{i64 4196562}
!70 = metadata !{i64 4196564}
!71 = metadata !{i64 4196569}
!72 = metadata !{i64 4196574}
!73 = metadata !{i64 4196579}
!74 = metadata !{i64 4196584}
!75 = metadata !{i64 4195968}
!76 = metadata !{i64 4195973}
!77 = metadata !{i64 4195977}
!78 = metadata !{i64 4195984}
!79 = metadata !{i64 4195989}
!80 = metadata !{i64 4195872}
!81 = metadata !{i64 4195877}
!82 = metadata !{i64 4195878}
!83 = metadata !{i64 4195889}
!84 = metadata !{i64 4195895}
!85 = metadata !{i64 4195899}
!86 = metadata !{i64 4195902}
!87 = metadata !{i64 4195905}
!88 = metadata !{i64 4195907}
!89 = metadata !{i64 4195912}
!90 = metadata !{i64 4195928}
!91 = metadata !{i64 4195929}
!92 = metadata !{i64 4195936}
!93 = metadata !{i64 4195943}
!94 = metadata !{i64 4195945}
!95 = metadata !{i64 4195946}
!96 = metadata !{i64 4195949}
!97 = metadata !{i64 4195954}
!98 = metadata !{i64 4195955}
!99 = metadata !{i64 4195963}
!100 = metadata !{i64 4195808}
!101 = metadata !{i64 4195813}
!102 = metadata !{i64 4195814}
!103 = metadata !{i64 4195820}
!104 = metadata !{i64 4195824}
!105 = metadata !{i64 4195827}
!106 = metadata !{i64 4195829}
!107 = metadata !{i64 4195834}
!108 = metadata !{i64 4195856}
!109 = metadata !{i64 4195857}
!110 = metadata !{i64 4196006}
!111 = metadata !{i64 4196007}
!112 = metadata !{i64 4196008}
!113 = metadata !{i64 4196015}
!114 = metadata !{i64 4196018}
!115 = metadata !{i64 4196021}
!116 = metadata !{i64 4196024}
!117 = metadata !{i64 4196029}
!118 = metadata !{i64 4196114}
!119 = metadata !{i64 4196118}
!120 = metadata !{i64 4196124}
!121 = metadata !{i64 4196128}
!122 = metadata !{i64 4196135}
!123 = metadata !{i64 4196138}
!124 = metadata !{i64 4196034}
!125 = metadata !{i64 4196037}
!126 = metadata !{i64 4196047}
!127 = metadata !{i64 4196140}
!128 = metadata !{i64 4196144}
!129 = metadata !{i64 4196049}
!130 = metadata !{i64 4196052}
!131 = metadata !{i64 4196055}
!132 = metadata !{i64 4196057}
!133 = metadata !{i64 4196061}
!134 = metadata !{i64 4196146}
!135 = metadata !{i64 4196149}
!136 = metadata !{i64 4196153}
!137 = metadata !{i64 4196158}
!138 = metadata !{i64 4196201}
!139 = metadata !{i64 4196204}
!140 = metadata !{i64 4196209}
!141 = metadata !{i64 4196213}
!142 = metadata !{i64 4196216}
!143 = metadata !{i64 4196063}
!144 = metadata !{i64 4196067}
!145 = metadata !{i64 4196079}
!146 = metadata !{i64 4196088}
!147 = metadata !{i64 4196090}
!148 = metadata !{i64 4196095}
!149 = metadata !{i64 4196097}
!150 = metadata !{i64 4196100}
!151 = metadata !{i64 4196104}
!152 = metadata !{i64 4196218}
!153 = metadata !{i64 4196223}
!154 = metadata !{i64 4196167}
!155 = metadata !{i64 4196228}
!156 = metadata !{i64 4196231}
!157 = metadata !{i64 4196234}
!158 = metadata !{i64 4196237}
!159 = metadata !{i64 4196242}
!160 = metadata !{i64 4196245}
!161 = metadata !{i64 4196252}
!162 = metadata !{i64 4196253}
!163 = metadata !{i64 4196254}
!164 = metadata !{i64 4196160}
!165 = metadata !{i64 4196163}
!166 = metadata !{i64 4196177}
!167 = metadata !{i64 4196186}
!168 = metadata !{i64 4196188}
!169 = metadata !{i64 4196193}
!170 = metadata !{i64 4196195}
!171 = metadata !{i64 4196198}
