#pragma once
#include "Encryption.h"

//======================================================================
//	FIPS Pub 46-3	DATA ENCRYPTION STANDARD (DES)
//----------------------------------------------------------------------
//  Reference:
//	sp800-17	Modes of Operation Validation System(MOVS) : Requirements and Procedures
//	sp800-67	Recommendation for the Triple Data Encryption Algorithm (TDEA) Block Cipher
//======================================================================
//
//	本プログラムは、ＤＥＳ暗号を処理します。
//	PBKDF2関数のデバッグの為に作成しました。
//	i80x86 32bit用（SIMD命令未使用）にコーディングしています。
//
//	尚、本クラスや、ソースコードの流用をする際は、ご一報ください。
//	又、本クラスや、ソースコードの利用により発生したいかなる
//	損害につきましては法律が許容する最大限において責任を負いませんので、
//	使用者の責任の元、ご利用頂ければ幸いです。
//
//	使い方は、Ｃ++言語のソースを読んでください。
//
//						Copyright (c) A.Watanabe (2011)
//
//----------------------------------------------------------------------
//	Revision
//		2011.11. 9	初版
//======================================================================
/****************************************************************/
/*			定数定義											*/
/****************************************************************/
#define		DES_BlockSize		8
#define		DES_KeySize_b		64
#define		DES_KeySize			DES_KeySize_b/8
#define		DES_Round			16
/****************************************************************/
/*			プロトタイプ宣言									*/
/****************************************************************/
//アセンブリ言語で書かれた関数	"AES_sse.asm"
/*
extern "C"{
				__m128i	__fastcall	AES_SSE_Cipher(unsigned char cNr,unsigned int *ptrKs, __m128i data);
				__m128i	__fastcall	AES_SSE_InvCipher(unsigned char cNr,unsigned int *ptrKs, __m128i data);}
*/

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class __declspec(align(16)) DES :
	public Encryption
{
//Variable
public:
	enum				useMode{ECB, CBC, OFB, CFB, CTR, CTS}	mode;

	unsigned	__int64	k[DES_Round];

//Function
public:
	DES(const char _strName[]="DES");							//
	~DES(void);													//

			void	Set_Key(void *key){KeyExpansion((unsigned char *)key, k);};		//暗号鍵 設定
			void	Clear_Key();								//鍵Zero化
//			void	init(){};									//初期化
			void	encrypt_ecb(void *data);
			void	decrypt_ecb(void *data);

//protected:
				void	KeyExpansion(void *key, unsigned __int64 ptKS[DES_Round]);		//暗号鍵 設定
	unsigned __int64	Cipher(unsigned __int64 iData);
	unsigned __int64	InvCipher(unsigned __int64 iData);

	unsigned	__int64	IP(unsigned __int64	data);						//Initial Premutation
	unsigned	__int64	invIP(unsigned __int64 data);					//Inverse Initial Premutation
	unsigned	int		f(unsigned	int	iData, unsigned __int64 iKey);	//Cipher function
	unsigned	__int64	E(unsigned int iData);							//Expand function
	unsigned	int		P(unsigned	int	iData);							//Permutation function
};
