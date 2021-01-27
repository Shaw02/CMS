;=======================================================================|
;									|
;		High speed AES encipher / decipher			|
;			with the SSE2 and AES-NI (SIMD) code		|
;									|
;				Programmed by				|
;					S.W.	( A.Watanabe )		|
;									|
;=======================================================================|

;=======================================================================|
;__m128i  __fastcall	AES_NI_KeyExpansion128(unsigned int *ptrKs, unsigned char *key);
;__m128i  __fastcall	AES_NI_KeyExpansion192(unsigned int *ptrKs, unsigned char *key);
;__m128i  __fastcall	AES_NI_KeyExpansion256(unsigned int *ptrKs, unsigned char *key);
;-----------------------------------------------------------------------|
;*Contents								|
;	Key Expansion							|
;*Input									|
;	ecx	unsigned int	*ptrKs	Pointer of Key schedule		|
;*Output								|
;	none								|
;*Break									|
;	eax, ecx, edx							|
;	xmm0～7   (all SIMD Register)					|
;=======================================================================|
;__m128i  __fastcall	AES_SSE_Cipher(unsigned char cNr,unsigned int *ptrKs, __m128i data);
;__m128i  __fastcall	AES_NI_Cipher( unsigned char cNr,unsigned int *ptrKs, __m128i data);
;-----------------------------------------------------------------------|
;*Contents								|
;	This function encrypt the Plain text of one block(16byte).	|
;*Input									|
;	ecx	unsigned char	cNr	Round (times)			|
;	edx	unsigned int	*ptrKs	Pointer of Key schedule		|
;	xmm0		__m128i	data	Plain text			|
;*Output								|
;	xmm0		__m128i		Cipher text			|
;*Break									|
;	eax, ecx, edx							|
;	xmm1～7   (all SIMD Register)					|
;=======================================================================|
;__m128i  __fastcall	AES_SSE_InvCipher(unsigned char cNr,unsigned int *ptrKs, __m128i data);
;__m128i  __fastcall	AES_NI_InvCipher( unsigned char cNr,unsigned int *ptrKs, __m128i data);
;-----------------------------------------------------------------------|
;*Contents								|
;	This function decrypt the Cipher text of one block(16byte).	|
;*Input									|
;	ecx	unsigned char	cNr	Round (times)			|
;	edx	unsigned int	*ptrKs	Pointer of Key schedule		|
;	xmm0		__m128i	data	Cipher text			|
;*Output								|
;	xmm0		__m128i		Plain text			|
;*Break									|
;	eax, ecx, edx							|
;	xmm1～7   (all SIMD Register)					|
;=======================================================================|

.586p
.xmm
.model	flat, stdcall

;****************************************************************
;*		proto type					*
;****************************************************************
;●外部宣言
;printf			proto	near	C	_Format:ptr byte, var:VARARG 
;dataPrint		proto	near	C	i:DWORD, n:PTR XMMWORD

;これは、Ｃ言語側にある。



;●プロトタイプ宣言
;@AES_SSE_mul@4		proto	near	syscall		;4.2	Multiplication	(__fastcall)

@SubWord@4		proto	near	syscall		;(__fastcall)
@SubWord2@4		proto	near	syscall		;(__fastcall)
@SubWord3@4		proto	near	syscall		;(__fastcall)
@InvSubWord@4		proto	near	syscall		;(__fastcall)

@AES_SSE_Cipher@24	proto	near	syscall		;5.1	Cipher		(__fastcall)
;AES_SSE_SubBytes	proto	near	stdcall		;5.1.1	SubBytes
;AES_SSE_ShiftRows	proto	near	stdcall		;5.1.2	ShiftRows
;AES_SSE_MixColumns	proto	near	stdcall		;5.1.3	MixColumns
;AES_SSE_AddRoundKey	proto	near	stdcall		;5.1.4	AddRoundKey

@AES_SSE_InvCipher@24	proto	near	syscall		;5.3	InvCipher	(__fastcall)
;AES_SSE_InvShiftRows	proto	near	stdcall		;5.3.1	InvShiftRows
;AES_SSE_InvSubBytes	proto	near	stdcall		;5.3.2	InvSubBytes
;AES_SSE_InvMixColumns	proto	near	stdcall		;5.3.3	InvMixColumns
;AES_SSE_InvAddRoundKey	proto	near	stdcall		;5.3.4	InvAddRoundKey

@AES_NI_Cipher@24	proto	near	syscall		;5.1	Cipher		(__fastcall)
@AES_NI_InvCipher@24	proto	near	syscall		;5.3	InvCipher	(__fastcall)

@AES_NI_KeyExpansion128@8	proto	near	syscall	;5.2	Key Expansion	(__fastcall)
@AES_NI_KeyExpansion192@8	proto	near	syscall	;5.2	Key Expansion	(__fastcall)
@AES_NI_KeyExpansion256@8	proto	near	syscall	;5.2	Key Expansion	(__fastcall)

;****************************************************************
;*		variable					*
;****************************************************************
;というか、メモリ上に作る定数。SSE 命令用。
.const
	align(16)
AES_SSE_Mask0		db	255,  0,  0,  0, 255,  0,  0,  0, 255,  0,  0,  0, 255,  0,  0,  0
AES_SSE_Mask1		db	  0,255,  0,  0,   0,255,  0,  0,   0,255,  0,  0,   0,255,  0,  0
AES_SSE_Mask2		db	  0,  0,255,  0,   0,  0,255,  0,   0,  0,255,  0,   0,  0,255,  0
AES_SSE_Mask3		db	  0,  0,  0,255,   0,  0,  0,255,   0,  0,  0,255,   0,  0,  0,255

AES_KEY_Mask0		db	255,255,255,255, 255,255,255,255,   0,  0,  0,  0,   0,  0,  0,  0
AES_KEY_Mask1		db	255,255,255,255,   0,  0,  0,  0, 255,255,255,255,   0,  0,  0,  0

AES_SSE_00FF		dw	000FFh,000FFh,000FFh,000FFh, 000FFh,000FFh,000FFh,000FFh
AES_SSE_011B		dw	0011Bh,0011Bh,0011Bh,0011Bh, 0011Bh,0011Bh,0011Bh,0011Bh
AES_SSE_FF00		dw	0FF00h,0FF00h,0FF00h,0FF00h, 0FF00h,0FF00h,0FF00h,0FF00h

;===============================================================|
;	fips-197	4.2	Multiplication			|
;---------------------------------------------------------------|
;	●引数							|
;		_out		計算結果を格納するxmmレジスタ	|
;		_in		かける数のxmmレジスタ		|
;		_n		かける数（0～15）		|
;	●引数							|
;		_out		計算結果			|
;	●使用するレジスタ	xmm4～xmm7			|
;		eax		ポインタ			|
;		ebx		ポインタ			|
;		ecx		ポインタ			|
;		xmm5		計算結果（偶数Bytes）		|
;		xmm4		加算値				|
;		xmm6		加算値				|
;		xmm7		比較用				|
;===============================================================|
GF2Mul	macro	_out, _in, _n

	lea	eax, XMMWORD PTR [AES_SSE_FF00]
	lea	ebx, XMMWORD PTR [AES_SSE_00FF]
	lea	ecx, XMMWORD PTR [AES_SSE_011B]

	;-------
	;x1
	movdqa	xmm6, _in
	movdqa	xmm4, _in
	pand	xmm6, XMMWORD PTR [eax]
	pand	xmm4, XMMWORD PTR [ebx]
	psrlw	xmm6, 8

if (_n AND 01h)
	movdqa	xmm5, xmm4
	movdqa	_out, xmm6
else
	pxor	_out, _out
	pxor	xmm5, xmm5
endif
	;-------
	;x2
	psllw	xmm6, 1			;result <<= 1;
	movdqa	xmm7, xmm6
	pcmpgtw	xmm7, XMMWORD PTR [ebx]
	pand	xmm7, XMMWORD PTR [ecx]
	pxor	xmm6, xmm7		;result ^= ((result & 0x100)?	0x11B	: 0);

	psllw	xmm4, 1			;result <<= 1;
	movdqa	xmm7, xmm4
	pcmpgtw	xmm7, XMMWORD PTR [ebx]
	pand	xmm7, XMMWORD PTR [ecx]
	pxor	xmm4, xmm7		;result ^= ((result & 0x100)?	0x11B	: 0);

if (_n AND 02h)
	pxor	_out, xmm6
	pxor	xmm5, xmm4
endif

	;-------
	;x4
	psllw	xmm6, 1			;result <<= 1;
	movdqa	xmm7, xmm6
	pcmpgtw	xmm7, XMMWORD PTR [ebx]
	pand	xmm7, XMMWORD PTR [ecx]
	pxor	xmm6, xmm7		;result ^= ((result & 0x100)?	0x11B	: 0);

	psllw	xmm4, 1			;result <<= 1;
	movdqa	xmm7, xmm4
	pcmpgtw	xmm7, XMMWORD PTR [ebx]
	pand	xmm7, XMMWORD PTR [ecx]
	pxor	xmm4, xmm7		;result ^= ((result & 0x100)?	0x11B	: 0);

if (_n AND 04h)
	pxor	_out, xmm6
	pxor	xmm5, xmm4
endif
	;-------
	;x8
if (_n AND 08h)
	psllw	xmm6, 1			;result <<= 1;
	movdqa	xmm7, xmm6
	pcmpgtw	xmm7, XMMWORD PTR [ebx]
	pand	xmm7, XMMWORD PTR [ecx]
	pxor	xmm6, xmm7		;result ^= ((result & 0x100)?	0x11B	: 0);

	psllw	xmm4, 1			;result <<= 1;
	movdqa	xmm7, xmm4
	pcmpgtw	xmm7, XMMWORD PTR [ebx]
	pand	xmm7, XMMWORD PTR [ecx]
	pxor	xmm4, xmm7		;result ^= ((result & 0x100)?	0x11B	: 0);

	pxor	_out, xmm6
	pxor	xmm5, xmm4
endif
	psllw	_out, 8
	por	_out, xmm5

	endm
;===============================================================|
;	fips-197		SBox				|
;---------------------------------------------------------------|
;	●引数							|
;		ecx		Input				|
;	●返値							|
;		eax		Output				|
;	●使用するレジスタ					|
;		eax, ebx, ecx, edx				|
;		(*) ecx, edxレジスタは、破壊			|
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
;	●引数							|
;		ecx		Input				|
;	●返値							|
;		eax		Output				|
;	●使用するレジスタ					|
;		eax, ebx, ecx, edx				|
;		(*) ecx, edxレジスタは、破壊			|
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
;	●引数							|
;		ecx		Input				|
;	●返値							|
;		eax		Output				|
;	●使用するレジスタ					|
;		eax, ebx, ecx, edx				|
;		(*) ecx, edxレジスタは、破壊			|
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
;	●引数							|
;		ecx		Input				|
;	●返値							|
;		eax		Output				|
;	●使用するレジスタ					|
;		eax, ebx, ecx, edx				|
;		(*) ecx, edxレジスタは、破壊			|
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
;	fips-197	5.1	Cipher (SSE2)			|
;---------------------------------------------------------------|
;	●引数							|
;		cl	Nr	Round				|
;		edx	ptrKS	Pointer of Key stream		|
;		xmm0		Plain Text			|
;	●返値							|
;		xmm0		Cipher Text			|
;	●使用するレジスタ					|
;		ebp		スタックフレーム		|
;		eax		関数からの返り値		|
;		ecx		関数への引数			|
;		ebx	=  1<<4	Key Stream読み込み用のカウンタ	|
;		edi	= cl<<4	Key Streamの最終カウンタ値	|
;		esi	= edx	Key Streamのポインタ		|
;		edx		関数呼び出しで破壊されるので注意|
;===============================================================|
.code
	align(16)
@AES_SSE_Cipher@24	proc	SYSCALL	uses	edi esi
	movzx	edi, cl
	movdqa	xmm4, XMMWORD PTR [AES_SSE_Mask0]
	lea	esi, [edx + 16]			;esi = Pointer of Key stream
	movdqa	xmm5, XMMWORD PTR [AES_SSE_Mask1]
	add	edi, edi
	movdqa	xmm6, XMMWORD PTR [AES_SSE_Mask2]
	lea	edi, [edx + edi * 8]		;edi = Last Round's Pointer of Key stream
	movdqa	xmm7, XMMWORD PTR [AES_SSE_Mask3]

	;=======================
	;◆Round (0)
	;---------------
	;AddRoundKey()
	movdqa	xmm2, XMMWORD PTR [edx]

	;=======================
	;◆Round (1) ～ (Nr-1)
	align(16)
	.repeat
		pxor	xmm0, xmm2
;		invoke	AES_SSE_SubBytes	;MixColumns()でやる

	;	invoke	AES_SSE_ShiftRows	;[0] 0,1,2,3
		pshufd	xmm1, xmm0, 00111001b	;[1] 1,2,3,0
		pshufd	xmm2, xmm0, 01001110b	;[2] 2,3,0,1
		pand	xmm1, xmm5
		pand	xmm2, xmm6
		pshufd	xmm3, xmm0, 10010011b	;[3] 3,0,1,2
		pand	xmm0, xmm4
		pand	xmm3, xmm7
		por	xmm1, xmm2
		por	xmm0, xmm3
		por	xmm0, xmm1

;		invoke	AES_SSE_MixColumns	;(+ SubBytesを同時に。)
		movdqa	xmm1,xmm0
		movd	ecx, xmm1
		invoke	@SubWord3@4
		movd	xmm2, eax
		psrldq	xmm1, 4
		pslldq	xmm2, 12
		movd	ecx, xmm1
		por	xmm1, xmm2
		invoke	@SubWord3@4
		movd	xmm2, eax
		psrldq	xmm1, 4
		pslldq	xmm2, 12
		movd	ecx, xmm1
		por	xmm1, xmm2
		invoke	@SubWord3@4
		movd	xmm2, eax
		psrldq	xmm1, 4
		pslldq	xmm2, 12
		movd	ecx, xmm1
		por	xmm1, xmm2
		invoke	@SubWord3@4
		movd	xmm2, eax
		psrldq	xmm1, 4
		pslldq	xmm2, 12
		por	xmm1, xmm2

		movdqa	xmm3, xmm1
		psrld	xmm1, 8
		pslld	xmm3, 24
		por	xmm3, xmm1		;xmm3 = [3]

		movdqa	xmm1,xmm0
		movd	ecx, xmm1
		invoke	@SubWord@4
		movd	xmm2, eax
		psrldq	xmm1, 4
		pslldq	xmm2, 12
		movd	ecx, xmm1
		por	xmm1, xmm2
		invoke	@SubWord@4
		movd	xmm2, eax
		psrldq	xmm1, 4
		pslldq	xmm2, 12
		movd	ecx, xmm1
		por	xmm1, xmm2
		invoke	@SubWord@4
		movd	xmm2, eax
		psrldq	xmm1, 4
		pslldq	xmm2, 12
		movd	ecx, xmm1
		por	xmm1, xmm2
		invoke	@SubWord@4
		movd	xmm2, eax
		psrldq	xmm1, 4
		pslldq	xmm2, 12
		por	xmm1, xmm2

		movdqa	xmm2, xmm1
		pslld	xmm1, 16
		psrld	xmm2, 16
		por	xmm1, xmm2		;xmm2 = [2]
		pxor	xmm3, xmm1		;xmm3 = [2] ^ [3]

		movdqa	xmm2, xmm1
		psrld	xmm1, 8
		pslld	xmm2, 24
		por	xmm1, xmm2		;xmm1 = [1]
		pxor	xmm3, xmm1		;xmm1 = [1] ^ [2] ^ [3]

		movd	ecx, xmm0
		invoke	@SubWord2@4
		movd	xmm1, eax
		psrldq	xmm0, 4
		pslldq	xmm1, 12
		movd	ecx, xmm0
		por	xmm0, xmm1
		invoke	@SubWord2@4
		movd	xmm1, eax
		psrldq	xmm0, 4
		pslldq	xmm1, 12
		movd	ecx, xmm0
		por	xmm0, xmm1
		invoke	@SubWord2@4
		movd	xmm1, eax
		psrldq	xmm0, 4
		pslldq	xmm1, 12
		movd	ecx, xmm0
		por	xmm0, xmm1
		invoke	@SubWord2@4
		movd	xmm1, eax
		psrldq	xmm0, 4
		pslldq	xmm1, 12
		por	xmm0, xmm1

		movdqa	xmm2, XMMWORD PTR [esi]
		pxor	xmm0, xmm3
		add	esi, 16

		;AddRoundKey()
	.until	(edi <= esi)

	;=======================
	;◆Last Round (Nr)
	pxor	xmm0, xmm2

;	invoke	AES_SSE_SubBytes
	movd	ecx, xmm0
	invoke	@SubWord@4
	movd	xmm2, eax
	psrldq	xmm0, 4
	pslldq	xmm2, 12
	movd	ecx, xmm0
	por	xmm0, xmm2
	invoke	@SubWord@4
	movd	xmm2, eax
	psrldq	xmm0, 4
	pslldq	xmm2, 12
	movd	ecx, xmm0
	por	xmm0, xmm2
	invoke	@SubWord@4
	movd	xmm2, eax
	psrldq	xmm0, 4
	pslldq	xmm2, 12
	movd	ecx, xmm0
	por	xmm0, xmm2
	invoke	@SubWord@4
	movd	xmm2, eax
	psrldq	xmm0, 4
	pslldq	xmm2, 12
	por	xmm0, xmm2

;	invoke	AES_SSE_ShiftRows	;[0] 0,1,2,3
	pshufd	xmm1, xmm0, 00111001b	;[1] 1,2,3,0
	pshufd	xmm2, xmm0, 01001110b	;[2] 2,3,0,1
	pand	xmm1, xmm5
	pand	xmm2, xmm6
	pshufd	xmm3, xmm0, 10010011b	;[3] 3,0,1,2
	pand	xmm0, xmm4
	pand	xmm3, xmm7
	por	xmm1, xmm2
	por	xmm0, xmm3
	movdqa	xmm2, XMMWORD PTR [esi]
	por	xmm0, xmm1

	;AddRoundKey()
	pxor	xmm0, xmm2

	ret
@AES_SSE_Cipher@24	endp
;===============================================================|
;	fips-197	5.3	InvCipher (SSE2)		|
;---------------------------------------------------------------|
;	●引数							|
;		cl	Nr	Round				|
;		edx	ptrKS	Pointer of Key stream		|
;		xmm0		Cipher Text			|
;	●返値							|
;		xmm0		Plain Text			|
;	●使用するレジスタ					|
;		ebp		スタックフレーム		|
;		eax		関数からの返り値		|
;		ecx		関数への引数			|
;		ebx	= cl<<4	Key Stream読み込み用のカウンタ	|
;		esi	= edx	Key Streamのポインタ		|
;		edx		関数呼び出しで破壊されるので注意|
;===============================================================|
.code
	align(16)
@AES_SSE_InvCipher@24	proc	SYSCALL	uses	ebx edi esi
	movzx	ebx, cl
	mov	edi, edx			;esi = Last
	add	ebx, ebx
	lea	eax, XMMWORD PTR [AES_SSE_Mask0]
	lea	esi, [edx + ebx * 8]		;esi = Pointer of Key stream
	lea	ecx, XMMWORD PTR [AES_SSE_Mask2]
	movdqa	xmm2, XMMWORD PTR [esi]
	lea	ebx, XMMWORD PTR [AES_SSE_Mask1]


	;=======================
	;◆Round (Nr)
	;AddRoundKey()

	pxor	xmm0, xmm2
	lea	edx, XMMWORD PTR [AES_SSE_Mask3]

;	invoke	AES_SSE_InvShiftRows	;[0] 0,1,2,3
	pshufd	xmm1, xmm0, 00111001b	;[1] 1,2,3,0
	pshufd	xmm2, xmm0, 01001110b	;[2] 2,3,0,1
	pand	xmm1, XMMWORD PTR [edx]
	pand	xmm2, XMMWORD PTR [ecx]
	pshufd	xmm3, xmm0, 10010011b	;[3] 3,0,1,2
	pand	xmm0, XMMWORD PTR [eax]
	pand	xmm3, XMMWORD PTR [ebx]
	por	xmm1, xmm2
	por	xmm0, xmm3
	por	xmm0, xmm1

	sub	esi, 16

;	invoke	AES_SSE_InvSubBytes
	movd	ecx, xmm0
	invoke	@InvSubWord@4
	movd	xmm1, eax
	psrldq	xmm0, 4
	pslldq	xmm1, 12
	movd	ecx, xmm0
	por	xmm0, xmm1
	invoke	@InvSubWord@4
	movd	xmm1, eax
	psrldq	xmm0, 4
	pslldq	xmm1, 12
	movd	ecx, xmm0
	por	xmm0, xmm1
	invoke	@InvSubWord@4
	movd	xmm1, eax
	psrldq	xmm0, 4
	pslldq	xmm1, 12
	movd	ecx, xmm0
	por	xmm0, xmm1
	invoke	@InvSubWord@4
	movd	xmm1, eax
	psrldq	xmm0, 4
	pslldq	xmm1, 12
	movdqa	xmm2, XMMWORD PTR [esi]
	por	xmm0, xmm1


	;=======================
	;◆Round (Nr-1) ～ (1)
	align(16)
	.repeat
		;AddRoundKey()
		pxor	xmm0, xmm2

	;	invoke	AES_SSE_InvMixColumns
		GF2Mul	xmm2, xmm0, 09h
		movdqa	xmm3, xmm2
		pslld	xmm2, 8
		psrld	xmm3, 24		;//[1]
		GF2Mul	xmm1, xmm0, 0Eh
		por	xmm2, xmm3
		GF2Mul	xmm3, xmm0, 0Dh
		pxor	xmm1, xmm2
		GF2Mul	xmm0, xmm0, 0Bh
		movdqa	xmm2, xmm3
		movdqa	xmm4, xmm0
		pslld	xmm2, 16
		psrld	xmm3, 16		;//[2]
		pslld	xmm0, 24
		psrld	xmm4, 8
		por	xmm2, xmm3
		por	xmm0, xmm4		;//[3]
		pxor	xmm1, xmm2
		pxor	xmm0, xmm1

	;	invoke	AES_SSE_InvShiftRows	;[0] 0,1,2,3
		lea	edx, XMMWORD PTR [AES_SSE_Mask3]
		pshufd	xmm1, xmm0, 00111001b	;[1] 1,2,3,0
		lea	ecx, XMMWORD PTR [AES_SSE_Mask2]
		pshufd	xmm2, xmm0, 01001110b	;[2] 2,3,0,1
		lea	eax, XMMWORD PTR [AES_SSE_Mask0]
		pand	xmm1, XMMWORD PTR [edx]
		pand	xmm2, XMMWORD PTR [ecx]
		pshufd	xmm3, xmm0, 10010011b	;[3] 3,0,1,2
		lea	ebx, XMMWORD PTR [AES_SSE_Mask1]
		pand	xmm0, XMMWORD PTR [eax]
		pand	xmm3, XMMWORD PTR [ebx]
		por	xmm1, xmm2
		por	xmm0, xmm3
		por	xmm0, xmm1

		sub	esi, 16

	;	invoke	AES_SSE_InvSubBytes
		movd	ecx, xmm0
		invoke	@InvSubWord@4
		movd	xmm1, eax
		psrldq	xmm0, 4
		pslldq	xmm1, 12
		movd	ecx, xmm0
		por	xmm0, xmm1
		invoke	@InvSubWord@4
		movd	xmm1, eax
		psrldq	xmm0, 4
		pslldq	xmm1, 12
		movd	ecx, xmm0
		por	xmm0, xmm1
		invoke	@InvSubWord@4
		movd	xmm1, eax
		psrldq	xmm0, 4
		pslldq	xmm1, 12
		movd	ecx, xmm0
		por	xmm0, xmm1
		invoke	@InvSubWord@4
		movd	xmm1, eax
		psrldq	xmm0, 4
		pslldq	xmm1, 12
		movdqa	xmm2, XMMWORD PTR [esi]
		por	xmm0, xmm1

	.until(edi >= esi)

	;=======================
	;◆Round (0)

	;AddRoundKey()
	pxor	xmm0, xmm2

	ret
@AES_SSE_InvCipher@24	endp

;===============================================================|
;	fips-197	5.1	Cipher (AES-NI)			|
;---------------------------------------------------------------|
;	●引数							|
;		cl	Nr	Round				|
;		edx	ptrKS	Pointer of Key stream		|
;		xmm0		Plain Text			|
;	●返値							|
;		xmm0		Cipher Text			|
;	●使用するレジスタ					|
;		eax		関数からの返り値		|
;		ecx		関数への引数			|
;		ebx	=  1<<4	Key Stream読み込み用のカウンタ	|
;		edi	= cl<<4	Key Streamの最終カウンタ値	|
;		esi	= edx	Key Streamのポインタ		|
;===============================================================|
.code
	align(16)
@AES_NI_Cipher@24	proc	SYSCALL	uses	ebx edi esi
	lea	esi, [edx + 16]			;esi = Pointer of Key stream

	pxor	xmm0, XMMWORD PTR [edx]		;w0
	aesenc	xmm0, XMMWORD PTR [esi]		;w1
	movzx	edi, cl

	lea	eax, [esi + 16]			;前もって、アドレスを計算しておく。
	lea	ebx, [esi + 32]			;（Core DUO, Core iシリーズの最適化）
	lea	ecx, [esi + 48]
	add	edi, edi
	add	esi, 64
	aesenc	xmm0, XMMWORD PTR [eax]		;w2
	aesenc	xmm0, XMMWORD PTR [ebx]		;w3
	aesenc	xmm0, XMMWORD PTR [ecx]		;w4
	lea	edi, [edx + edi * 8]		;edi = Last Round's Pointer of Key stream

	lea	eax, [esi + 16]			;前もって、アドレスを計算しておく。
	lea	ebx, [esi + 32]			;（Core DUO, Core iシリーズの最適化）
	lea	ecx, [esi + 48]
	lea	edx, [esi + 64]

	aesenc	xmm0, XMMWORD PTR [esi]		;w5
	aesenc	xmm0, XMMWORD PTR [eax]		;w6
	aesenc	xmm0, XMMWORD PTR [ebx]		;w7
	aesenc	xmm0, XMMWORD PTR [ecx]		;w8
	add	esi, 80
	aesenc	xmm0, XMMWORD PTR [edx]		;w9

	;=======================
	;◆Round (10) ～ (Nr-1)
	align(16)
	.while	(edi > esi)
		lea	eax, [esi + 16]			;前もって、アドレスを計算しておく。
		aesenc	xmm0, XMMWORD PTR [esi]		;
		aesenc	xmm0, XMMWORD PTR [eax]		;
		add	esi, 32
	.endw

	;=======================
	;◆Last Round (Nr)
	aesenclast	xmm0, XMMWORD PTR [esi]

	ret
@AES_NI_Cipher@24	endp

;===============================================================|
;	fips-197	5.3	InvCipher (AES-NI)		|
;---------------------------------------------------------------|
;	●引数							|
;		cl	Nr	Round				|
;		edx	ptrKS	Pointer of Key stream		|
;		xmm0		Cipher Text			|
;	●返値							|
;		xmm0		Plain Text			|
;	●使用するレジスタ					|
;		eax		関数からの返り値		|
;		ecx		関数への引数			|
;		ebx	= cl<<4	Key Stream読み込み用のカウンタ	|
;		esi	= edx	Key Streamのポインタ		|
;===============================================================|
.code
	align(16)
@AES_NI_InvCipher@24	proc	SYSCALL	uses	ebx edi esi
	movzx	ebx, cl
	add	ebx, ebx
	lea	esi, [edx + ebx * 8]		;esi = Pointer of Key stream

	;=======================
	;◆Round (Nr)
	lea	eax, [esi - 16]			;前もって、アドレスを計算しておく。
	lea	ebx, [esi - 32]			;（Core DUO, Core iシリーズの最適化）
	lea	ecx, [esi - 48]
	lea	edi, [esi - 64]
	pxor	xmm0, XMMWORD PTR [esi]
	aesimc	xmm5, XMMWORD PTR [eax]
	sub	esi, 80
	aesimc	xmm4, XMMWORD PTR [ebx]
	aesdec	xmm0, xmm5
	aesimc	xmm3, XMMWORD PTR [ecx]
	aesdec	xmm0, xmm4
	aesimc	xmm2, XMMWORD PTR [edi]
	aesdec	xmm0, xmm3

	lea	eax, [esi - 16]			;前もって、アドレスを計算しておく。
	lea	ebx, [esi - 32]			;（Core DUO, Core iシリーズの最適化）
	lea	ecx, [esi - 48]
	lea	edi, [esi - 64]

	aesimc	xmm5, XMMWORD PTR [esi]
	aesdec	xmm0, xmm2
	aesimc	xmm4, XMMWORD PTR [eax]
	aesdec	xmm0, xmm5
	aesimc	xmm3, XMMWORD PTR [ebx]
	aesdec	xmm0, xmm4
	aesimc	xmm2, XMMWORD PTR [ecx]
	aesdec	xmm0, xmm3
	aesimc	xmm1, XMMWORD PTR [edi]
	aesdec	xmm0, xmm2
	sub	esi, 80
	aesdec	xmm0, xmm1

	;=======================
	;◆Round (10) ～ (Nr-1)
	align(16)
	.while	(edx < esi)
		lea	eax, [esi - 16]		;前もって、アドレスを計算しておく。
		aesimc	xmm2, XMMWORD PTR [esi]
		aesimc	xmm1, XMMWORD PTR [eax]
		aesdec	xmm0, xmm2
		sub	esi, 32
		aesdec	xmm0, xmm1
	.endw
	;=======================
	;◆Last Round (Nr)
	aesdeclast	xmm0, XMMWORD PTR [esi]

	ret
@AES_NI_InvCipher@24	endp

;===============================================================|
;	fips-197	5.2	Key Expansion (AES-NI)		|
;---------------------------------------------------------------|
;	●引数							|
;		ecx	ptrKS	Pointer of Key stream		|
;		edx	key	Pointer of Key			|
;	●返値							|
;		none						|
;	●使用するレジスタ					|
;		eax, ecx, edx	ポインタ計算用			|
;		xmm0-7		鍵計算用			|
;===============================================================|
.code
@AES_NI_KeyExpansion128@8	proc	SYSCALL

	movdqu		xmm1, XMMWORD PTR [edx]
	movdqa		XMMWORD PTR [ecx],xmm1

	aeskeygenassist	xmm2, xmm1, 01h
	call		AES_NI_KeyExpansion128_Sub

	aeskeygenassist	xmm2, xmm1, 02h
	call		AES_NI_KeyExpansion128_Sub

	aeskeygenassist	xmm2, xmm1, 04h
	call		AES_NI_KeyExpansion128_Sub

	aeskeygenassist	xmm2, xmm1, 08h
	call		AES_NI_KeyExpansion128_Sub

	aeskeygenassist	xmm2, xmm1, 10h
	call		AES_NI_KeyExpansion128_Sub

	aeskeygenassist	xmm2, xmm1, 20h
	call		AES_NI_KeyExpansion128_Sub

	aeskeygenassist	xmm2, xmm1, 40h
	call		AES_NI_KeyExpansion128_Sub

	aeskeygenassist	xmm2, xmm1, 80h
	call		AES_NI_KeyExpansion128_Sub

	aeskeygenassist	xmm2, xmm1, 1bh
	call		AES_NI_KeyExpansion128_Sub

	aeskeygenassist	xmm2, xmm1, 36h
;	call		AES_NI_KeyExpansion128_Sub
;
;	ret
@AES_NI_KeyExpansion128@8	endp

AES_NI_KeyExpansion128_Sub	proc
	movdqa		xmm3, xmm1
	lea		ecx,  XMMWORD PTR [ecx + 16]
	pslldq		xmm3, 4
	pshufd		xmm2, xmm2, 11111111b	;3,3,3,3
	pxor		xmm1, xmm3
	pslldq		xmm3, 4
	pxor		xmm1, xmm3
	pslldq		xmm3, 4
	pxor		xmm1, xmm2
	pxor		xmm1, xmm3
	movdqa		XMMWORD PTR [ecx], xmm1

	ret
AES_NI_KeyExpansion128_Sub	endp

;---------------------------------------------------------------|
@AES_NI_KeyExpansion192@8	proc	SYSCALL

;	xmm0	読み込み
;	xmm1	読み込み
;	xmm2	シフト用＆合成
;	xmm3	シフト用
;	xmm4	aeskeygenassist
;	xmm5	一時
;	xmm6	AES_KEY_Mask0
;	xmm7	AES_KEY_Mask1

	movdqa		xmm6, XMMWORD PTR [AES_KEY_Mask0]
	movdqa		xmm7, XMMWORD PTR [AES_KEY_Mask1]

;	;[0]
	lea		eax, XMMWORD PTR [edx + 16]
	movdqu		xmm0, XMMWORD PTR [edx]	;[0][1][2][3]
	movdqu		xmm1, XMMWORD PTR [eax]	;[4][5][6][7]
	movdqa		XMMWORD PTR [ecx], xmm0
	pand		xmm1, xmm6		;[4][5][-][-]

;	;[1]
	movdqa		xmm2, xmm0
	aeskeygenassist	xmm4, xmm1, 01h
	lea		eax, XMMWORD PTR [ecx + 16]
	pshufd		xmm4, xmm4, 01010101b	;1,1,1,1
	pslldq		xmm2, 8			;  = [-][-][1][0]
	pxor		xmm1, xmm2		; += [-][-][1][0]
	pslldq		xmm4, 8			;  = [-][-][s][s]
	pxor		xmm1, xmm4		; += [-][-][s][s]
	pslldq		xmm2, 4
	pxor		xmm1, xmm2		; += [-][-][1][1]
	movdqa		XMMWORD PTR [eax], xmm1	;[4][5][6][7]

;	;[2]
	movdqa		xmm2, xmm0
	lea		eax, XMMWORD PTR [ecx + 32]
	psrldq		xmm2, 8
	movdqa		xmm3, xmm1
	pslldq		xmm3, 8
	pshufd		xmm0, xmm1, 11111111b	;3,3,3,3
	pxor		xmm2, xmm3
	pxor		xmm0, xmm2
	pslldq		xmm2, 4
	pxor		xmm0, xmm2
	pslldq		xmm2, 4
	pxor		xmm0, xmm2
	pslldq		xmm2, 4
	pxor		xmm0, xmm2
	movdqa		XMMWORD PTR [eax], xmm0	;[8][9][10][11]

;	;[3]
	movdqa		xmm2, xmm1
	lea		eax, XMMWORD PTR [ecx + 48]
	psrldq		xmm2, 8
	movdqa		xmm3, xmm0
	aeskeygenassist	xmm1, xmm0, 02h
	pslldq		xmm3, 8
	pshufd		xmm1, xmm1, 11111111b	;3,3,3,3
	pxor		xmm2, xmm3		;[6][7][8][9]
	pxor		xmm1, xmm2
	pslldq		xmm2, 4
	pxor		xmm1, xmm2
	pslldq		xmm2, 4
	pxor		xmm1, xmm2
	pslldq		xmm2, 4
	pxor		xmm1, xmm2
	movdqa		XMMWORD PTR [eax], xmm1	;[12][13][14][15]

;	;[4]
	movdqa		xmm2, xmm0
	lea		eax, XMMWORD PTR [ecx + 64]
	psrldq		xmm2, 8
	movdqa		xmm3, xmm1
	pslldq		xmm3, 8
	pshufd		xmm4, xmm1, 11111111b	;[15][15][15][15]
	pxor		xmm2, xmm3		;[10][11][12][13]
	pand		xmm4, xmm6		;[15][15][- ][- ]
	movdqa		xmm5, xmm2		
	pand		xmm5, xmm7		;[10][- ][12][-]
	pslldq		xmm5, 4
	pxor		xmm5, xmm2
	pxor		xmm5, xmm4
	aeskeygenassist	xmm0, xmm5, 04h
	pshufd		xmm0, xmm0, 01010101b	;3,3,3,3
	pslldq		xmm0, 8
	pxor		xmm0, xmm5
	movdqa		XMMWORD PTR [eax], xmm0	;[16][17][18][19]

;	;[5]
	movdqa		xmm2, xmm1
	lea		ecx, XMMWORD PTR [eax + 16]
	psrldq		xmm2, 8
	movdqa		xmm3, xmm0
	pslldq		xmm3, 8
	pshufd		xmm1, xmm0, 11111111b	;3,3,3,3
	pxor		xmm2, xmm3
	pxor		xmm1, xmm2
	pslldq		xmm2, 4
	pxor		xmm1, xmm2
	pslldq		xmm2, 4
	pxor		xmm1, xmm2
	pslldq		xmm2, 4
	pxor		xmm1, xmm2
	movdqa		XMMWORD PTR [ecx], xmm1	;[20][21][22][23]

;	;[6]
	movdqa		xmm2, xmm0
	lea		ecx, XMMWORD PTR [eax + 32]
	psrldq		xmm2, 8
	movdqa		xmm3, xmm1
	aeskeygenassist	xmm0, xmm1, 08h
	pslldq		xmm3, 8
	pshufd		xmm0, xmm0, 11111111b	;3,3,3,3
	pxor		xmm2, xmm3
	pxor		xmm0, xmm2
	pslldq		xmm2, 4
	pxor		xmm0, xmm2
	pslldq		xmm2, 4
	pxor		xmm0, xmm2
	pslldq		xmm2, 4
	pxor		xmm0, xmm2
	movdqa		XMMWORD PTR [ecx], xmm0	;[24][25][26][27]

;	;[7]
	movdqa		xmm2, xmm1
	lea		ecx, XMMWORD PTR [eax + 48]
	psrldq		xmm2, 8
	movdqa		xmm3, xmm0
	pslldq		xmm3, 8
	pshufd		xmm4, xmm0, 11111111b
	pxor		xmm2, xmm3
	pand		xmm4, xmm6
	movdqa		xmm5, xmm2		
	pand		xmm5, xmm7
	pslldq		xmm5, 4
	pxor		xmm5, xmm2
	pxor		xmm5, xmm4
	aeskeygenassist	xmm1, xmm5, 10h
	pshufd		xmm1, xmm1, 01010101b	;3,3,3,3
	pslldq		xmm1, 8
	pxor		xmm1, xmm5
	movdqa		XMMWORD PTR [ecx], xmm1	;[28][29][30][31]

;	;[8]
	movdqa		xmm2, xmm0
	lea		eax, XMMWORD PTR [ecx + 16]
	psrldq		xmm2, 8
	movdqa		xmm3, xmm1
	pslldq		xmm3, 8
	pshufd		xmm0, xmm1, 11111111b	;3,3,3,3
	pxor		xmm2, xmm3
	pxor		xmm0, xmm2
	pslldq		xmm2, 4
	pxor		xmm0, xmm2
	pslldq		xmm2, 4
	pxor		xmm0, xmm2
	pslldq		xmm2, 4
	pxor		xmm0, xmm2
	movdqa		XMMWORD PTR [eax], xmm0

;	;[9]
	movdqa		xmm2, xmm1
	lea		eax, XMMWORD PTR [ecx + 32]
	psrldq		xmm2, 8
	movdqa		xmm3, xmm0
	aeskeygenassist	xmm1, xmm0, 20h
	pslldq		xmm3, 8
	pshufd		xmm1, xmm1, 11111111b	;3,3,3,3
	pxor		xmm2, xmm3
	pxor		xmm1, xmm2
	pslldq		xmm2, 4
	pxor		xmm1, xmm2
	pslldq		xmm2, 4
	pxor		xmm1, xmm2
	pslldq		xmm2, 4
	pxor		xmm1, xmm2
	movdqa		XMMWORD PTR [eax], xmm1

;	;[10]
	movdqa		xmm2, xmm0
	lea		eax, XMMWORD PTR [ecx + 48]
	psrldq		xmm2, 8
	movdqa		xmm3, xmm1
	pslldq		xmm3, 8
	pshufd		xmm4, xmm1, 11111111b
	pxor		xmm2, xmm3
	pand		xmm4, xmm6
	movdqa		xmm5, xmm2		
	pand		xmm5, xmm7
	pslldq		xmm5, 4
	pxor		xmm5, xmm2
	pxor		xmm5, xmm4
	aeskeygenassist	xmm0, xmm5, 40h
	pshufd		xmm0, xmm0, 01010101b	;3,3,3,3
	pslldq		xmm0, 8
	pxor		xmm0, xmm5
	movdqa		XMMWORD PTR [eax], xmm0

;	;[11]
	movdqa		xmm2, xmm1
	lea		ecx, XMMWORD PTR [eax + 16]
	psrldq		xmm2, 8
	movdqa		xmm3, xmm0
	pslldq		xmm3, 8
	pshufd		xmm1, xmm0, 11111111b	;3,3,3,3
	pxor		xmm2, xmm3
	pxor		xmm1, xmm2
	pslldq		xmm2, 4
	pxor		xmm1, xmm2
	pslldq		xmm2, 4
	pxor		xmm1, xmm2
	pslldq		xmm2, 4
	pxor		xmm1, xmm2
	movdqa		XMMWORD PTR [ecx], xmm1

;	;[12]
	movdqa		xmm2, xmm0
	lea		ecx, XMMWORD PTR [eax + 32]
	psrldq		xmm2, 8
	movdqa		xmm3, xmm1
	aeskeygenassist	xmm0, xmm1, 80h
	pslldq		xmm3, 8
	pshufd		xmm0, xmm0, 11111111b	;3,3,3,3
	pxor		xmm2, xmm3
	pxor		xmm0, xmm2
	pslldq		xmm2, 4
	pxor		xmm0, xmm2
	pslldq		xmm2, 4
	pxor		xmm0, xmm2
	pslldq		xmm2, 4
	pxor		xmm0, xmm2
	movdqa		XMMWORD PTR [ecx], xmm0

	ret
@AES_NI_KeyExpansion192@8	endp
;---------------------------------------------------------------|
@AES_NI_KeyExpansion256@8	proc	SYSCALL

	lea		eax, XMMWORD PTR [edx + 16]
	movdqu		xmm0, XMMWORD PTR [edx]
	movdqu		xmm1, XMMWORD PTR [eax]

	lea		eax, XMMWORD PTR [ecx + 16]
	movdqa		XMMWORD PTR [ecx], xmm0
	movdqa		XMMWORD PTR [eax], xmm1

	aeskeygenassist	xmm2, xmm1, 01h
	call		AES_NI_KeyExpansion256_Sub

	aeskeygenassist	xmm2, xmm1, 02h
	call		AES_NI_KeyExpansion256_Sub

	aeskeygenassist	xmm2, xmm1, 04h
	call		AES_NI_KeyExpansion256_Sub

	aeskeygenassist	xmm2, xmm1, 08h
	call		AES_NI_KeyExpansion256_Sub

	aeskeygenassist	xmm2, xmm1, 10h
	call		AES_NI_KeyExpansion256_Sub

	aeskeygenassist	xmm2, xmm1, 20h
	call		AES_NI_KeyExpansion256_Sub

	movdqa		xmm3, xmm0
	lea		ecx,  XMMWORD PTR [ecx + 32]
	pslldq		xmm3, 4
	aeskeygenassist	xmm2, xmm1, 40h
	pxor		xmm0, xmm3
	pslldq		xmm3, 4
	pshufd		xmm2, xmm2, 11111111b	;3,3,3,3
	pxor		xmm0, xmm3
	pslldq		xmm3, 4
	pxor		xmm0, xmm2
	pxor		xmm0, xmm3
	movdqa		XMMWORD PTR [ecx], xmm0

	ret
@AES_NI_KeyExpansion256@8	endp

AES_NI_KeyExpansion256_Sub	proc
	movdqa		xmm3, xmm0
	lea		ecx,  XMMWORD PTR [ecx + 32]
	pslldq		xmm3, 4
	pxor		xmm0, xmm3
	pslldq		xmm3, 4
	pshufd		xmm2, xmm2, 11111111b	;3,3,3,3
	pxor		xmm0, xmm3
	pslldq		xmm3, 4
	pxor		xmm0, xmm2
	pxor		xmm0, xmm3
	movdqa		XMMWORD PTR [ecx], xmm0

	movdqa		xmm3, xmm1
	lea		edx,  XMMWORD PTR [ecx + 16]
	pslldq		xmm3, 4
	aeskeygenassist	xmm2, xmm0, 0
	pxor		xmm1, xmm3
	pslldq		xmm3, 4
	pshufd		xmm2, xmm2, 10101010b	;2,2,2,2
	pxor		xmm1, xmm3
	pslldq		xmm3, 4
	pxor		xmm1, xmm2
	pxor		xmm1, xmm3
	movdqa		XMMWORD PTR [edx], xmm1

	ret
AES_NI_KeyExpansion256_Sub	endp

;****************************************************************
	end
