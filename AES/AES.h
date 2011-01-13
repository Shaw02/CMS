#pragma once
//======================================================================
//	fips-197	AES		Encoder / Decorder
//======================================================================
//
//	本プログラムは、ＡＥＳ暗号をSIMD命令（SSE2）で処理する事を
//	試みる為に開発しました。私の知的興味による産物です。
//
//	次世代ＣＰＵより、ＡＥＳ暗号を処理する為のSIMD（AVX）が
//	追加されるそうですが、それ以前ＣＰＵが搭載されているＰＣで
//	SIMD命令による暗号・複合を試みる物です。
//	"SSE2"に対応しているCPUであれば、動作するはずです。
//
//	尚、本クラスや、ソースコードの流用をする際は、ご一報ください。
//	又、本クラスや、ソースコードの利用により発生したいかなる
//	損害につきましては法律が許容する最大限において責任を負いませんので、
//	使用者の責任の元、ご利用頂ければ幸いです。
//
//	使い方は、Ｃ++言語のソースを読んでください。
//	"main.c"は、本クラス"AES"の使用方法のサンプル程度にお考え下さい。
//
//						Copyright (c) A.Watanabe (2010)
//
//----------------------------------------------------------------------
//	Revision
//		2010.12.27	初版
//		2010.12.28	大部分がアセンブリ言語（MASM）だったのを、
//					Ｃ++言語で書き直した。
//======================================================================
union _mm_i8
{
	__declspec(align(16))	unsigned	char	i8[16];
							__m128i				m128i;
};
union _mm_i16
{
	__declspec(align(16))	unsigned	__int16	i16[8];
							__m128i				m128i;
};
union _mm_i32
{
	__declspec(align(16))	unsigned	int		i32[4];
							__m128i				m128i;
};
/****************************************************************/
/*			定数定義											*/
/****************************************************************/
#define		Nb		4			//Number of columns (32-bit words) comprising the State.
								//For this standard, Nb = 4. (Also see Sec. 6.3.)
#define		Nbb		Nb*4		//[Byte]

/****************************************************************/
/*			プロトタイプ宣言									*/
/****************************************************************/
//アセンブリ言語で書かれた関数	"AES_sse.asm"
extern "C"{
				__m128i	__fastcall	AES_SSE_Cipher(unsigned char cNr,unsigned int *ptrKs, __m128i data);
				__m128i	__fastcall	AES_SSE_InvCipher(unsigned char cNr,unsigned int *ptrKs, __m128i data);
//	unsigned	int		__fastcall	SubWord(unsigned int data);
//	unsigned	int		__fastcall	SubWord2(unsigned int data);
//	unsigned	int		__fastcall	SubWord3(unsigned int data);
//	unsigned	int		__fastcall	InvSubWord(unsigned int data);
}

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class __declspec(align(16)) AES
{
public:
	//Variable
__declspec(align(16)) unsigned	int	w[60];	//Key Schedule	(16byte align)
	unsigned	char	Nk;					//Number of 32-bit words comprising the Cipher Key.
											//For this standard, Nk = 4, 6, or 8. (Also see Sec. 6.3.)
	unsigned	char	Nr;					//Number of rounds, which is a function of Nk and Nb (which is fixed).
											//For this standard, Nr = 10, 12, or 14. (Also see Sec. 6.3.)
	__m128i				IV;

public:
	//Function
	AES();											//
	AES(char cNk,unsigned char Key[]);				//鍵スケジュール生成付きでクラス作成
	~AES(void);										//

	__m128i	mul(__m128i data, unsigned char n);					//4,2	Multiplication

	void	KeyExpansion(char cNK, unsigned char *key);			//5.2	Key Expansion
	unsigned	int		RotWord(unsigned int data);				//
	unsigned	int		SubWord(unsigned int data);				//
	unsigned	int		SubWord2(unsigned int data);			//(x 02)
	unsigned	int		SubWord3(unsigned int data);			//(x 03)
	unsigned	int		InvSubWord(unsigned int data);			//

	void	Cipher_One(void *ind, void *outd);					//
	__m128i	Cipher(__m128i data);								//5.1	Cipher
	__m128i	SubBytes(__m128i data);								//5.1.1	SubBytes
	__m128i	SubBytes2(__m128i data);							//5.1.1	SubBytes(x02)
	__m128i	SubBytes3(__m128i data);							//5.1.1	SubBytes(x03)
	__m128i	ShiftRows(__m128i data);							//5.1.2	ShiftRows
	__m128i	MixColumns(__m128i data);							//5.1.3	MixColumns
	__m128i	AddRoundKey(__m128i data, int i);					//5.1.4	AddRoundKey

	void	InvCipher_One(void *ind, void *outd);				//
	__m128i	InvCipher(__m128i data);							//5.3	InvCipher
	__m128i	InvShiftRows(__m128i data);							//5.3.1	InvShiftRows
	__m128i	InvSubBytes(__m128i data);							//5.3.2	InvSubBytes
	__m128i	InvMixColumns(__m128i data);						//5.3.3	InvMixColumns
	__m128i	InvAddRoundKey(__m128i data, int i);				//5.3.4	InvAddRoundKey

	void	SetIV(__m128i data);
	void	CBC_Cipher(void *data);
	void	CBC_InvCipher(void *data);

};
