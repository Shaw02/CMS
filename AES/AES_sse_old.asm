;===============================================================|
;								|
;		AES for SSE (SIMD)				|
;								|
;				Programmed by			|
;					(S.W.)	( A.Watanabe )	|
;								|
;===============================================================|
;void	__fastcall	AES_SSE_Cipher(char Nr, unsigned char Ks);
;---------------------------------------------------------------|
;*Input								|
;	Nr	Round				(ecx)		|
;	Ks	Pointer of Key schedule		(edx)		|
;	xmm0	Plain text					|
;*Output							|
;	xmm0	Cipher text					|
;*Break								|
;	eax, ecx, edx						|
;	xmm1�`7   (all SIMD Register)				|
;===============================================================|
;void	__fastcall	AES_SSE_InvCipher(char Nr, unsigned char Ks);
;---------------------------------------------------------------|
;*Input								|
;	Nr	Round				(ecx)		|
;	Ks	Pointer of Key schedule		(edx)		|
;	xmm0	Cipher text					|
;*Output							|
;	xmm0	Plain text					|
;*Break								|
;	eax, ecx, edx						|
;	xmm1�`7   (all SIMD Register)				|
;===============================================================|

.586p
.xmm
.model	flat, stdcall

;****************************************************************
;*		proto type					*
;****************************************************************
;���O���錾
;printf			proto	near	C	_Format:ptr byte, var:VARARG 

;����́A�b���ꑤ�ɂ���B



;���v���g�^�C�v�錾
AES_SSE_mul		proto	near			;4.2	Multiplication

@SubWord@4		proto	near	syscall
@SubWord2@4		proto	near	syscall
@SubWord3@4		proto	near	syscall
@InvSubWord@4		proto	near	syscall

@AES_SSE_Cipher@8	proto	near	syscall		;5.1	Cipher	(__fastcall)
AES_SSE_SubBytes	proto	near	stdcall		;5.1.1	SubBytes
AES_SSE_SubBytes2	proto	near	stdcall		;5.1.1	SubBytes
AES_SSE_SubBytes3	proto	near	stdcall		;5.1.1	SubBytes
AES_SSE_ShiftRows	proto	near	stdcall		;5.1.2	ShiftRows
AES_SSE_MixColumns	proto	near	stdcall		;5.1.3	MixColumns
;AES_SSE_AddRoundKey	proto	near	stdcall		;5.1.4	AddRoundKey

@AES_SSE_InvCipher@8	proto	near	syscall		;5.2	InvCipher	(__fastcall)
AES_SSE_InvShiftRows	proto	near	stdcall		;5.2.1	InvShiftRows
AES_SSE_InvSubBytes	proto	near	stdcall		;5.2.2	InvSubBytes
AES_SSE_InvMixColumns	proto	near	stdcall		;5.2.3	InvMixColumns
;AES_SSE_InvAddRoundKey	proto	near	stdcall		;5.2.4	InvAddRoundKey



;****************************************************************
;*		variable					*
;****************************************************************
;�Ƃ������A��������ɍ��萔�BSSE ���ߗp�B
.const
	align(16)

AES_SSE_Mask0		db	255,  0,  0,  0, 255,  0,  0,  0, 255,  0,  0,  0, 255,  0,  0,  0
AES_SSE_Mask1		db	  0,255,  0,  0,   0,255,  0,  0,   0,255,  0,  0,   0,255,  0,  0
AES_SSE_Mask2		db	  0,  0,255,  0,   0,  0,255,  0,   0,  0,255,  0,   0,  0,255,  0
AES_SSE_Mask3		db	  0,  0,  0,255,   0,  0,  0,255,   0,  0,  0,255,   0,  0,  0,255

AES_SSE_Mul_Mask1	equ	AES_SSE_Mask1
AES_SSE_Mul_Mask2	equ	AES_SSE_Mask0

;AES_SSE_00FF		dw	00FFh,00FFh,00FFh,00FFh, 00FFh,00FFh,00FFh,00FFh
AES_SSE_011B		dw	011Bh,011Bh,011Bh,011Bh, 011Bh,011Bh,011Bh,011Bh
AES_SSE_00FF		equ	AES_SSE_Mask1


;===============================================================|
;	fips-197		SBox				|
;---------------------------------------------------------------|
;	������							|
;		ecx		Input				|
;	���Ԓl							|
;		eax		Output				|
;===============================================================|
.const
SBox	db	063h,07ch,077h,07bh,0f2h,06bh,06fh,0c5h,030h,001h,067h,02bh,0feh,0d7h,0abh,076h
	db	0cah,082h,0c9h,07dh,0fah,059h,047h,0f0h,0adh,0d4h,0a2h,0afh,09ch,0a4h,072h,0c0h
	db	0b7h,0fdh,093h,026h,036h,03fh,0f7h,0cch,034h,0a5h,0e5h,0f1h,071h,0d8h,031h,015h
	db	004h,0c7h,023h,0c3h,018h,096h,005h,09ah,007h,012h,080h,0e2h,0ebh,027h,0b2h,075h
	db	009h,083h,02ch,01ah,01bh,06eh,05ah,0a0h,052h,03bh,0d6h,0b3h,029h,0e3h,02fh,084h
	db	053h,0d1h,000h,0edh,020h,0fch,0b1h,05bh,06ah,0cbh,0beh,039h,04ah,04ch,058h,0cfh
	db	0d0h,0efh,0aah,0fbh,043h,04dh,033h,085h,045h,0f9h,002h,07fh,050h,03ch,09fh,0a8h
	db	051h,0a3h,040h,08fh,092h,09dh,038h,0f5h,0bch,0b6h,0dah,021h,010h,0ffh,0f3h,0d2h
	db	0cdh,00ch,013h,0ech,05fh,097h,044h,017h,0c4h,0a7h,07eh,03dh,064h,05dh,019h,073h
	db	060h,081h,04fh,0dch,022h,02ah,090h,088h,046h,0eeh,0b8h,014h,0deh,05eh,00bh,0dbh
	db	0e0h,032h,03ah,00ah,049h,006h,024h,05ch,0c2h,0d3h,0ach,062h,091h,095h,0e4h,079h
	db	0e7h,0c8h,037h,06dh,08dh,0d5h,04eh,0a9h,06ch,056h,0f4h,0eah,065h,07ah,0aeh,008h
	db	0bah,078h,025h,02eh,01ch,0a6h,0b4h,0c6h,0e8h,0ddh,074h,01fh,04bh,0bdh,08bh,08ah
	db	070h,03eh,0b5h,066h,048h,003h,0f6h,00eh,061h,035h,057h,0b9h,086h,0c1h,01dh,09eh
	db	0e1h,0f8h,098h,011h,069h,0d9h,08eh,094h,09bh,01eh,087h,0e9h,0ceh,055h,028h,0dfh
	db	08ch,0a1h,089h,00dh,0bfh,0e6h,042h,068h,041h,099h,02dh,00fh,0b0h,054h,0bbh,016h
.code
	align(16)
@SubWord@4	proc	SYSCALL	uses	ebx
;	ecx	data

	mov	ebx, ecx
	mov	eax, ecx
	shr	ebx, 24
	shr	eax, 16
	movzx	edx, [SBox + ebx]	;[3]
	and	eax, 0FFh
	shl	edx, 8
	movzx	eax, [SBox + eax]	;[2]
	movzx	ebx, ch
	or	eax, edx
	shl	eax, 8
	movzx	edx, [SBox + ebx]	;[1]
	and	ecx, 0FFh
	or	eax, edx
	shl	eax, 8
	movzx	ebx, [SBox + ecx]	;[0]
	or	eax, ebx

	ret
@SubWord@4	endp
;===============================================================|
;	fips-197		SBox				|
;---------------------------------------------------------------|
;	������							|
;		ecx		Input				|
;	���Ԓl							|
;		eax		Output				|
;===============================================================|
.const
SBox2	db	0c6h,0f8h,0eeh,0f6h,0ffh,0d6h,0deh,091h,060h,002h,0ceh,056h,0e7h,0b5h,04dh,0ech
	db	08fh,01fh,089h,0fah,0efh,0b2h,08eh,0fbh,041h,0b3h,05fh,045h,023h,053h,0e4h,09bh
	db	075h,0e1h,03dh,04ch,06ch,07eh,0f5h,083h,068h,051h,0d1h,0f9h,0e2h,0abh,062h,02ah
	db	008h,095h,046h,09dh,030h,037h,00ah,02fh,00eh,024h,01bh,0dfh,0cdh,04eh,07fh,0eah
	db	012h,01dh,058h,034h,036h,0dch,0b4h,05bh,0a4h,076h,0b7h,07dh,052h,0ddh,05eh,013h
	db	0a6h,0b9h,000h,0c1h,040h,0e3h,079h,0b6h,0d4h,08dh,067h,072h,094h,098h,0b0h,085h
	db	0bbh,0c5h,04fh,0edh,086h,09ah,066h,011h,08ah,0e9h,004h,0feh,0a0h,078h,025h,04bh
	db	0a2h,05dh,080h,005h,03fh,021h,070h,0f1h,063h,077h,0afh,042h,020h,0e5h,0fdh,0bfh
	db	081h,018h,026h,0c3h,0beh,035h,088h,02eh,093h,055h,0fch,07ah,0c8h,0bah,032h,0e6h
	db	0c0h,019h,09eh,0a3h,044h,054h,03bh,00bh,08ch,0c7h,06bh,028h,0a7h,0bch,016h,0adh
	db	0dbh,064h,074h,014h,092h,00ch,048h,0b8h,09fh,0bdh,043h,0c4h,039h,031h,0d3h,0f2h
	db	0d5h,08bh,06eh,0dah,001h,0b1h,09ch,049h,0d8h,0ach,0f3h,0cfh,0cah,0f4h,047h,010h
	db	06fh,0f0h,04ah,05ch,038h,057h,073h,097h,0cbh,0a1h,0e8h,03eh,096h,061h,00dh,00fh
	db	0e0h,07ch,071h,0cch,090h,006h,0f7h,01ch,0c2h,06ah,0aeh,069h,017h,099h,03ah,027h
	db	0d9h,0ebh,02bh,022h,0d2h,0a9h,007h,033h,02dh,03ch,015h,0c9h,087h,0aah,050h,0a5h
	db	003h,059h,009h,01ah,065h,0d7h,084h,0d0h,082h,029h,05ah,01eh,07bh,0a8h,06dh,02ch
.code
	align(16)
@SubWord2@4	proc	SYSCALL	uses	ebx
;	ecx	data

	mov	ebx, ecx
	mov	eax, ecx
	shr	ebx, 24
	shr	eax, 16
	movzx	edx, [SBox2 + ebx]	;[3]
	and	eax, 0FFh
	shl	edx, 8
	movzx	eax, [SBox2 + eax]	;[2]
	movzx	ebx, ch
	or	eax, edx
	shl	eax, 8
	movzx	edx, [SBox2 + ebx]	;[1]
	and	ecx, 0FFh
	or	eax, edx
	shl	eax, 8
	movzx	ebx, [SBox2 + ecx]	;[0]
	or	eax, ebx

	ret
@SubWord2@4	endp
;===============================================================|
;	fips-197		SBox				|
;---------------------------------------------------------------|
;	������							|
;		ecx		Input				|
;	���Ԓl							|
;		eax		Output				|
;===============================================================|
.const
SBox3	db	0a5h,084h,099h,08dh,00dh,0bdh,0b1h,054h,050h,003h,0a9h,07dh,019h,062h,0e6h,09ah
	db	045h,09dh,040h,087h,015h,0ebh,0c9h,00bh,0ech,067h,0fdh,0eah,0bfh,0f7h,096h,05bh
	db	0c2h,01ch,0aeh,06ah,05ah,041h,002h,04fh,05ch,0f4h,034h,008h,093h,073h,053h,03fh
	db	00ch,052h,065h,05eh,028h,0a1h,00fh,0b5h,009h,036h,09bh,03dh,026h,069h,0cdh,09fh
	db	01bh,09eh,074h,02eh,02dh,0b2h,0eeh,0fbh,0f6h,04dh,061h,0ceh,07bh,03eh,071h,097h
	db	0f5h,068h,000h,02ch,060h,01fh,0c8h,0edh,0beh,046h,0d9h,04bh,0deh,0d4h,0e8h,04ah
	db	06bh,02ah,0e5h,016h,0c5h,0d7h,055h,094h,0cfh,010h,006h,081h,0f0h,044h,0bah,0e3h
	db	0f3h,0feh,0c0h,08ah,0adh,0bch,048h,004h,0dfh,0c1h,075h,063h,030h,01ah,00eh,06dh
	db	04ch,014h,035h,02fh,0e1h,0a2h,0cch,039h,057h,0f2h,082h,047h,0ach,0e7h,02bh,095h
	db	0a0h,098h,0d1h,07fh,066h,07eh,0abh,083h,0cah,029h,0d3h,03ch,079h,0e2h,01dh,076h
	db	03bh,056h,04eh,01eh,0dbh,00ah,06ch,0e4h,05dh,06eh,0efh,0a6h,0a8h,0a4h,037h,08bh
	db	032h,043h,059h,0b7h,08ch,064h,0d2h,0e0h,0b4h,0fah,007h,025h,0afh,08eh,0e9h,018h
	db	0d5h,088h,06fh,072h,024h,0f1h,0c7h,051h,023h,07ch,09ch,021h,0ddh,0dch,086h,085h
	db	090h,042h,0c4h,0aah,0d8h,005h,001h,012h,0a3h,05fh,0f9h,0d0h,091h,058h,027h,0b9h
	db	038h,013h,0b3h,033h,0bbh,070h,089h,0a7h,0b6h,022h,092h,020h,049h,0ffh,078h,07ah
	db	08fh,0f8h,080h,017h,0dah,031h,0c6h,0b8h,0c3h,0b0h,077h,011h,0cbh,0fch,0d6h,03ah
.code
	align(16)
@SubWord3@4	proc	SYSCALL	uses	ebx
;	ecx	data

	mov	ebx, ecx
	mov	eax, ecx
	shr	ebx, 24
	shr	eax, 16
	movzx	edx, [SBox3 + ebx]	;[3]
	and	eax, 0FFh
	shl	edx, 8
	movzx	eax, [SBox3 + eax]	;[2]
	movzx	ebx, ch
	or	eax, edx
	shl	eax, 8
	movzx	edx, [SBox3 + ebx]	;[1]
	and	ecx, 0FFh
	or	eax, edx
	shl	eax, 8
	movzx	ebx, [SBox3 + ecx]	;[0]
	or	eax, ebx

	ret
@SubWord3@4	endp
;===============================================================|
;	fips-197		SBox				|
;---------------------------------------------------------------|
;	������							|
;		ecx		Input				|
;	���Ԓl							|
;		eax		Output				|
;===============================================================|
.const
InvSBox	db	052h,009h,06ah,0d5h,030h,036h,0a5h,038h,0bfh,040h,0a3h,09eh,081h,0f3h,0d7h,0fbh
	db	07ch,0e3h,039h,082h,09bh,02fh,0ffh,087h,034h,08eh,043h,044h,0c4h,0deh,0e9h,0cbh
	db	054h,07bh,094h,032h,0a6h,0c2h,023h,03dh,0eeh,04ch,095h,00bh,042h,0fah,0c3h,04eh
	db	008h,02eh,0a1h,066h,028h,0d9h,024h,0b2h,076h,05bh,0a2h,049h,06dh,08bh,0d1h,025h
	db	072h,0f8h,0f6h,064h,086h,068h,098h,016h,0d4h,0a4h,05ch,0cch,05dh,065h,0b6h,092h
	db	06ch,070h,048h,050h,0fdh,0edh,0b9h,0dah,05eh,015h,046h,057h,0a7h,08dh,09dh,084h
	db	090h,0d8h,0abh,000h,08ch,0bch,0d3h,00ah,0f7h,0e4h,058h,005h,0b8h,0b3h,045h,006h
	db	0d0h,02ch,01eh,08fh,0cah,03fh,00fh,002h,0c1h,0afh,0bdh,003h,001h,013h,08ah,06bh
	db	03ah,091h,011h,041h,04fh,067h,0dch,0eah,097h,0f2h,0cfh,0ceh,0f0h,0b4h,0e6h,073h
	db	096h,0ach,074h,022h,0e7h,0adh,035h,085h,0e2h,0f9h,037h,0e8h,01ch,075h,0dfh,06eh
	db	047h,0f1h,01ah,071h,01dh,029h,0c5h,089h,06fh,0b7h,062h,00eh,0aah,018h,0beh,01bh
	db	0fch,056h,03eh,04bh,0c6h,0d2h,079h,020h,09ah,0dbh,0c0h,0feh,078h,0cdh,05ah,0f4h
	db	01fh,0ddh,0a8h,033h,088h,007h,0c7h,031h,0b1h,012h,010h,059h,027h,080h,0ech,05fh
	db	060h,051h,07fh,0a9h,019h,0b5h,04ah,00dh,02dh,0e5h,07ah,09fh,093h,0c9h,09ch,0efh
	db	0a0h,0e0h,03bh,04dh,0aeh,02ah,0f5h,0b0h,0c8h,0ebh,0bbh,03ch,083h,053h,099h,061h
	db	017h,02bh,004h,07eh,0bah,077h,0d6h,026h,0e1h,069h,014h,063h,055h,021h,00ch,07dh
.code
	align(16)
@InvSubWord@4	proc	SYSCALL	uses	ebx
;	ecx	data

	mov	ebx, ecx
	mov	eax, ecx
	shr	ebx, 24
	shr	eax, 16
	movzx	edx, [InvSBox + ebx]	;[3]
	and	eax, 0FFh
	shl	edx, 8
	movzx	eax, [InvSBox + eax]	;[2]
	movzx	ebx, ch
	or	eax, edx
	shl	eax, 8
	movzx	edx, [InvSBox + ebx]	;[1]
	and	ecx, 0FFh
	or	eax, edx
	shl	eax, 8
	movzx	ebx, [InvSBox + ecx]	;[0]
	or	eax, ebx

	ret
@InvSubWord@4	endp
;===============================================================|
;	fips-197	4.2	Multiplication			|
;---------------------------------------------------------------|
;	������							|
;		xmm0		�v�Z�O	�i�j�󂹂��j		|
;		al		�����鐔�i0�`15�j		|
;	������							|
;		xmm1		�v�Z��				|
;	���g�p���郌�W�X�^	xmm4�`xmm7			|
;		ecx		��Z�p				|
;		xmm1		�v�Z���ʁi�Bytes�j		|
;		xmm5		�v�Z���ʁi����Bytes�j		|
;		xmm4		���Z�l				|
;		xmm6		���Z�l				|
;		xmm7		��r�p				|
;===============================================================|
.code
	align(16)
AES_SSE_mul	proc

	movdqa	xmm6, xmm0
	pxor	xmm1, xmm1
	pand	xmm6, XMMWORD PTR [AES_SSE_Mul_Mask1]
	psrlw	xmm6, 8

	movdqa	xmm4, xmm0
	pxor	xmm5, xmm5
	pand	xmm4, XMMWORD PTR [AES_SSE_Mul_Mask2]

	xor	ecx, ecx
	mov	cl, 008h		;000h �` 00Fh �͈̔͂ł����g��Ȃ��B

	align(16)
	.repeat
		psllw	xmm1, 1			;result <<= 1;
		movdqa	xmm7, xmm1
		pcmpgtw	xmm7, XMMWORD PTR [AES_SSE_00FF]
		pand	xmm7, XMMWORD PTR [AES_SSE_011B]
		pxor	xmm1, xmm7		;result ^= ((result & 0x100)?	0x11B	: 0);

		psllw	xmm5, 1			;result <<= 1;
		movdqa	xmm7, xmm5
		pcmpgtw	xmm7, XMMWORD PTR [AES_SSE_00FF]
		pand	xmm7, XMMWORD PTR [AES_SSE_011B]
		pxor	xmm5, xmm7		;result ^= ((result & 0x100)?	0x11B	: 0);
		.if	(al & cl)
			pxor	xmm1,	xmm6
			pxor	xmm5,	xmm4
		.endif
		shr	cl, 1
	.until	(!cl)

	psllw	xmm1, 8
	por	xmm1, xmm5

	ret

AES_SSE_mul	endp
;===============================================================|
;	fips-197	5.1	Cipher				|
;---------------------------------------------------------------|
;	������							|
;		xmm0		Plain Text			|
;		ecx	Nr	Round				|
;		edx	ptrKS	Pointer of Key stream		|
;	���Ԓl							|
;		xmm0		Cipher Text			|
;===============================================================|
.code
	align(16)
@AES_SSE_Cipher@8	proc	SYSCALL	uses	ebx edi esi
	push	ebp
	mov	ebp, esp
	and	esp, -16
	sub	esp, 16

	movzx	edi, cl
	mov	esi, edx
	xor	ebx, ebx
	shl	edi, 4

	;=======================
	;��Round (0)
	;---------------
	;AddRoundKey()
	pxor	xmm0, XMMWORD PTR [esi + ebx]
	add	ebx, 16

	;=======================
	;��Round (1) �` (Nr-1)
	align(16)
	.repeat
;		invoke	AES_SSE_SubBytes	;MixColumns()�ł��

;		invoke	AES_SSE_ShiftRows	;[0] 0,1,2,3
		pshufd	xmm1, xmm0, 00111001b	;[1] 1,2,3,0
		pshufd	xmm2, xmm0, 01001110b	;[2] 2,3,0,1
		pand	xmm1, XMMWORD PTR [AES_SSE_Mask1]
		pand	xmm2, XMMWORD PTR [AES_SSE_Mask2]
		pshufd	xmm3, xmm0, 10010011b	;[3] 3,0,1,2
		pand	xmm0, XMMWORD PTR [AES_SSE_Mask0]
		pand	xmm3, XMMWORD PTR [AES_SSE_Mask3]
		por	xmm2, xmm3
		por	xmm0, xmm1
		por	xmm0, xmm2

;		invoke	AES_SSE_MixColumns
		movdqa	XMMWORD PTR [esp], xmm0
		mov	ecx, DWORD PTR [esp + 0]
		invoke	@SubWord2@4
		mov	ecx, DWORD PTR [esp + 4]
		mov	DWORD PTR [esp + 0], eax
		invoke	@SubWord2@4
		mov	ecx, DWORD PTR [esp + 8]
		mov	DWORD PTR [esp + 4], eax
		invoke	@SubWord2@4
		mov	ecx, DWORD PTR [esp + 12]
		mov	DWORD PTR [esp + 8], eax
		invoke	@SubWord2@4
		mov	DWORD PTR [esp + 12], eax
		movdqa	xmm1, XMMWORD PTR [esp]

		movdqa	XMMWORD PTR [esp], xmm0
		mov	ecx, DWORD PTR [esp + 0]
		invoke	@SubWord3@4
		mov	ecx, DWORD PTR [esp + 4]
		mov	DWORD PTR [esp + 0], eax
		invoke	@SubWord3@4
		mov	ecx, DWORD PTR [esp + 8]
		mov	DWORD PTR [esp + 4], eax
		invoke	@SubWord3@4
		mov	ecx, DWORD PTR [esp + 12]
		mov	DWORD PTR [esp + 8], eax
		invoke	@SubWord3@4
		mov	DWORD PTR [esp + 12], eax
		movdqa	xmm2, XMMWORD PTR [esp]

		movdqa	XMMWORD PTR [esp], xmm0
		mov	ecx, DWORD PTR [esp + 0]
		invoke	@SubWord@4
		mov	ecx, DWORD PTR [esp + 4]
		mov	DWORD PTR [esp + 0], eax
		invoke	@SubWord@4
		mov	ecx, DWORD PTR [esp + 8]
		mov	DWORD PTR [esp + 4], eax
		invoke	@SubWord@4
		mov	ecx, DWORD PTR [esp + 12]
		mov	DWORD PTR [esp + 8], eax
		invoke	@SubWord@4
		mov	DWORD PTR [esp + 12], eax
		movdqa	xmm0, XMMWORD PTR [esp]

		movdqa	xmm3, xmm2
		movdqa	xmm5, xmm0
		psrld	xmm2, 8
		movdqa	xmm6, xmm0
		pslld	xmm3, 24
		movdqa	xmm7, xmm0
		pslld	xmm5, 16
		por	xmm2, xmm3
		psrld	xmm6, 16
		pxor	xmm1, xmm2	;xmm1 = [0] ^ [1]
		psrld	xmm0, 24
		por	xmm5, xmm6	;xmm5 = [2]
		pslld	xmm7, 8
		pxor	xmm1, xmm5	;xmm1 = [0] ^ [1] ^ [2]
		por	xmm0, xmm7	;xmm0 = [3]
		pxor	xmm0, xmm1



		pxor	xmm0, XMMWORD PTR [esi + ebx]
		add	ebx, 16
	.until	(edi <= ebx)

	;=======================
	;��Last Round (Nr)
;	invoke	AES_SSE_SubBytes
	movdqa	XMMWORD PTR [esp], xmm0
	mov	ecx, DWORD PTR [esp + 0]
	invoke	@SubWord@4
	mov	DWORD PTR [esp + 0], eax
	mov	ecx, DWORD PTR [esp + 4]
	invoke	@SubWord@4
	mov	DWORD PTR [esp + 4], eax
	mov	ecx, DWORD PTR [esp + 8]
	invoke	@SubWord@4
	mov	DWORD PTR [esp + 8], eax
	mov	ecx, DWORD PTR [esp + 12]
	invoke	@SubWord@4
	mov	DWORD PTR [esp + 12], eax
	movdqa	xmm0, XMMWORD PTR [esp]

;	invoke	AES_SSE_ShiftRows	;[0] 0,1,2,3
	pshufd	xmm1, xmm0, 00111001b	;[1] 1,2,3,0
	pshufd	xmm2, xmm0, 01001110b	;[2] 2,3,0,1
	pand	xmm1, XMMWORD PTR [AES_SSE_Mask1]
	pand	xmm2, XMMWORD PTR [AES_SSE_Mask2]
	pshufd	xmm3, xmm0, 10010011b	;[3] 3,0,1,2
	pand	xmm0, XMMWORD PTR [AES_SSE_Mask0]
	pand	xmm3, XMMWORD PTR [AES_SSE_Mask3]
	por	xmm2, xmm3
	por	xmm0, xmm1
	por	xmm0, xmm2

	pxor	xmm0, XMMWORD PTR [esi + ebx]

	mov	esp, ebp
	pop	ebp
	ret
@AES_SSE_Cipher@8	endp
;===============================================================|
;	fips-197	5.1.1	SubBytes			|
;---------------------------------------------------------------|
;	������							|
;		xmm0	input					|
;	���Ԓl							|
;		xmm0	output					|
;===============================================================|
	align(16)
AES_SSE_SubBytes	proc

	push	ebx
	lea	ebx, [esp - 16]
	sub	esp, 32
	and	ebx, -16	;align(16)

	movdqa	XMMWORD PTR [ebx], xmm0
	mov	ecx, DWORD PTR [ebx + 0]
	invoke	@SubWord@4
	mov	DWORD PTR [ebx + 0], eax
	mov	ecx, DWORD PTR [ebx + 4]
	invoke	@SubWord@4
	mov	DWORD PTR [ebx + 4], eax
	mov	ecx, DWORD PTR [ebx + 8]
	invoke	@SubWord@4
	mov	DWORD PTR [ebx + 8], eax
	mov	ecx, DWORD PTR [ebx + 12]
	invoke	@SubWord@4
	mov	DWORD PTR [ebx + 12], eax
	movdqa	xmm0, XMMWORD PTR [ebx]

	add	esp, 32
	pop	ebx
	ret
AES_SSE_SubBytes	endp
;===============================================================|
;	fips-197	5.1.2	ShiftRows			|
;---------------------------------------------------------------|
;	������							|
;		xmm0	input					|
;	���Ԓl							|
;		xmm0	output					|
;===============================================================|
	align(16)
AES_SSE_ShiftRows	proc

					;[0] 0,1,2,3
	pshufd	xmm1, xmm0, 00111001b	;[1] 1,2,3,0
	pshufd	xmm2, xmm0, 01001110b	;[2] 2,3,0,1
	pand	xmm1, XMMWORD PTR [AES_SSE_Mask1]
	pand	xmm2, XMMWORD PTR [AES_SSE_Mask2]
	pshufd	xmm3, xmm0, 10010011b	;[3] 3,0,1,2
	pand	xmm0, XMMWORD PTR [AES_SSE_Mask0]
	pand	xmm3, XMMWORD PTR [AES_SSE_Mask3]
	por	xmm2, xmm3
	por	xmm0, xmm1
	por	xmm0, xmm2

	ret
AES_SSE_ShiftRows	endp
;===============================================================|
;	fips-197	5.1.3	MixColumns			|
;---------------------------------------------------------------|
;	������							|
;		xmm0	input					|
;	���Ԓl							|
;		xmm0	output					|
;===============================================================|
	align(16)
AES_SSE_MixColumns	proc
	push	ebp
	mov	ebp, esp
	and	esp, -16
	sub	esp, 16

	;---------------
	;����Z	
	;�����������āAXOR����B
	;   |	2S0	2S1	2S2	2S3	|
	;   |	 S3	 S0	 S1	 S2	|
	;   |	 S2	 S3	 S0	 S1	|
	;   |	3S1	3S2	3S3	3S0	|

;	mov	al, 2
;	invoke	AES_SSE_mul		;//�N���X�̃����o�[�֐��Ȃ̂ŁA �֐��K��thiscall
;	movdqa	xmm2, xmm1		;//�ꎞ�ۑ�

	movdqa	XMMWORD PTR [esp], xmm0
	mov	ecx, DWORD PTR [esp + 0]
	invoke	@SubWord2@4
	mov	ecx, DWORD PTR [esp + 4]
	mov	DWORD PTR [esp + 0], eax
	invoke	@SubWord2@4
	mov	ecx, DWORD PTR [esp + 8]
	mov	DWORD PTR [esp + 4], eax
	invoke	@SubWord2@4
	mov	ecx, DWORD PTR [esp + 12]
	mov	DWORD PTR [esp + 8], eax
	invoke	@SubWord2@4
	mov	DWORD PTR [esp + 12], eax
	movdqa	xmm1, XMMWORD PTR [esp]

;	mov	al, 3
;	invoke	AES_SSE_mul		;//�N���X�̃����o�[�֐��Ȃ̂ŁA �֐��K��thiscall
;	movdqa	xmm3, xmm1

	movdqa	XMMWORD PTR [esp], xmm0
	mov	ecx, DWORD PTR [esp + 0]
	invoke	@SubWord3@4
	mov	ecx, DWORD PTR [esp + 4]
	mov	DWORD PTR [esp + 0], eax
	invoke	@SubWord3@4
	mov	ecx, DWORD PTR [esp + 8]
	mov	DWORD PTR [esp + 4], eax
	invoke	@SubWord3@4
	mov	ecx, DWORD PTR [esp + 12]
	mov	DWORD PTR [esp + 8], eax
	invoke	@SubWord3@4
	mov	DWORD PTR [esp + 12], eax
	movdqa	xmm2, XMMWORD PTR [esp]

	movdqa	XMMWORD PTR [esp], xmm0
	mov	ecx, DWORD PTR [esp + 0]
	invoke	@SubWord@4
	mov	ecx, DWORD PTR [esp + 4]
	mov	DWORD PTR [esp + 0], eax
	invoke	@SubWord@4
	mov	ecx, DWORD PTR [esp + 8]
	mov	DWORD PTR [esp + 4], eax
	invoke	@SubWord@4
	mov	ecx, DWORD PTR [esp + 12]
	mov	DWORD PTR [esp + 8], eax
	invoke	@SubWord@4
	mov	DWORD PTR [esp + 12], eax
	movdqa	xmm0, XMMWORD PTR [esp]

	movdqa	xmm3, xmm2
	movdqa	xmm5, xmm0
	psrld	xmm2, 8
	movdqa	xmm6, xmm0
	pslld	xmm3, 24
	movdqa	xmm7, xmm0
	pslld	xmm5, 16
	por	xmm2, xmm3
	psrld	xmm6, 16
	pxor	xmm1, xmm2	;xmm1 = [0] ^ [1]
	psrld	xmm0, 24
	por	xmm5, xmm6	;xmm5 = [2]
	pslld	xmm7, 8
	pxor	xmm1, xmm5	;xmm1 = [0] ^ [1] ^ [2]
	por	xmm0, xmm7	;xmm0 = [3]
	mov	esp, ebp
	pxor	xmm0, xmm1

	pop	ebp
	ret
AES_SSE_MixColumns	endp
;===============================================================|
;	fips-197	5.2	InvCipher			|
;---------------------------------------------------------------|
;	������							|
;		xmm0		Cipher Text			|
;		ecx	Nr	Round				|
;		edx	ptrKS	Pointer of Key stream		|
;	���Ԓl							|
;		xmm0		Plain Text			|
;===============================================================|
.code
	align(16)
@AES_SSE_InvCipher@8	proc	SYSCALL	uses	ebx edi esi

	movzx	ebx, cl
	shl	ebx, 4
	mov	esi, edx

	;=======================
	;��Round (Nr)
	pxor	xmm0, XMMWORD PTR [esi + ebx]
	sub	ebx, 16

	;=======================
	;��Round (Nr-1) �` (1)
	align(16)
	.repeat
		invoke	AES_SSE_InvShiftRows
		invoke	AES_SSE_InvSubBytes
		pxor	xmm0, XMMWORD PTR [esi + ebx]
		invoke	AES_SSE_InvMixColumns
		sub	ebx, 16
	.until(zero?)

	;=======================
	;��Round (0)
	invoke	AES_SSE_InvShiftRows
	invoke	AES_SSE_InvSubBytes
	pxor	xmm0, XMMWORD PTR [esi + ebx]

	ret
@AES_SSE_InvCipher@8	endp
;===============================================================|
;	fips-197	5.2.1	ShiftRows			|
;---------------------------------------------------------------|
;	������							|
;		xmm0	input					|
;	���Ԓl							|
;		xmm0	output					|
;===============================================================|
	align(16)
AES_SSE_InvShiftRows	proc

					;[0] 0,1,2,3
	pshufd	xmm1, xmm0, 00111001b	;[1] 1,2,3,0
	pshufd	xmm2, xmm0, 01001110b	;[2] 2,3,0,1
	pand	xmm1, XMMWORD PTR [AES_SSE_Mask3]
	pand	xmm2, XMMWORD PTR [AES_SSE_Mask2]
	pshufd	xmm3, xmm0, 10010011b	;[3] 3,0,1,2
	pand	xmm0, XMMWORD PTR [AES_SSE_Mask0]
	pand	xmm3, XMMWORD PTR [AES_SSE_Mask1]
	por	xmm2, xmm3
	por	xmm0, xmm1
	por	xmm0, xmm2

	ret
AES_SSE_InvShiftRows	endp
;===============================================================|
;	fips-197	5.2.2	InvSubBytes			|
;---------------------------------------------------------------|
;	������							|
;		xmm0	input					|
;	���Ԓl							|
;		xmm0	output					|
;===============================================================|
	align(16)
AES_SSE_InvSubBytes	proc

	push	ebx

	lea	ebx, [esp - 16]
	sub	esp, 32
	and	ebx, -16	;align(16)

	movdqa	XMMWORD PTR [ebx], xmm0
	mov	ecx, DWORD PTR [ebx + 0]
	invoke	@InvSubWord@4
	mov	DWORD PTR [ebx + 0], eax
	mov	ecx, DWORD PTR [ebx + 4]
	invoke	@InvSubWord@4
	mov	DWORD PTR [ebx + 4], eax
	mov	ecx, DWORD PTR [ebx + 8]
	invoke	@InvSubWord@4
	mov	DWORD PTR [ebx + 8], eax
	mov	ecx, DWORD PTR [ebx + 12]
	invoke	@InvSubWord@4
	mov	DWORD PTR [ebx + 12], eax
	movdqa	xmm0, XMMWORD PTR [ebx]

	add	esp, 32

	pop	ebx
	ret
AES_SSE_InvSubBytes	endp
;===============================================================|
;	fips-197	5.1.3	MixColumns			|
;---------------------------------------------------------------|
;	������							|
;		xmm0	input					|
;	���Ԓl							|
;		xmm0	output					|
;===============================================================|
	align(16)
AES_SSE_InvMixColumns	proc

	;---------------
	;����Z	
	;�����������āAXOR����B
	;  = |	e.S0	e.S1	e.S2	e.S3	|
	;  = |	9.S3	9.S0	9.S1	9.S2	|
	;  = |	d.S2	d.S3	d.S0	d.S1	|
	;  = |	b.S1	b.S2	b.S3	b.S0	|

	;��AES_SSE_mul
	;	xmm2,3,4 �͔j�󂹂��B

	mov	al, 00Eh
	invoke	AES_SSE_mul		;//�N���X�̃����o�[�֐��Ȃ̂ŁA �֐��K��thiscall
	movdqa	xmm2, xmm1		;//[0]

	mov	al, 009h
	invoke	AES_SSE_mul		;//�N���X�̃����o�[�֐��Ȃ̂ŁA �֐��K��thiscall
	movdqa	xmm3, xmm1
	pslld	xmm1, 8
	psrld	xmm3, 24		;//[1]
	por	xmm3, xmm1
	pxor	xmm2, xmm3

	mov	al, 00Dh
	invoke	AES_SSE_mul		;//�N���X�̃����o�[�֐��Ȃ̂ŁA �֐��K��thiscall
	movdqa	xmm3, xmm1
	pslld	xmm1, 16
	psrld	xmm3, 16		;//[2]
	por	xmm3, xmm1

	mov	al, 00Bh
	invoke	AES_SSE_mul		;//�N���X�̃����o�[�֐��Ȃ̂ŁA �֐��K��thiscall
	movdqa	xmm0, xmm1
	pslld	xmm1, 24
	psrld	xmm0, 8
	por	xmm0, xmm1		;//[3]
	pxor	xmm0, xmm3
	pxor	xmm0, xmm2

	ret
AES_SSE_InvMixColumns	endp
;****************************************************************
	end
