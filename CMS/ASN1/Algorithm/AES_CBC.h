#pragma once
#include "AES.h"

//======================================================================
//					AES-CBC	Encoder / Decorder
//----------------------------------------------------------------------
//  Reference:
//	RFC 3565		Use of the Advanced Encryption Standard (AES) Encryption
//					Algorithm in Cryptographic Message Syntax (CMS)
//======================================================================
//
//	本プログラムは、ＡＥＳ暗号における
//	暗号利用モードＣＢＣのための基底クラスです。
//
//						Copyright (c) A.Watanabe (2011)
//
//----------------------------------------------------------------------
//	Revision
//		2011.10. 7	初版
//======================================================================
/****************************************************************/
/*			定数定義											*/
/****************************************************************/


/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class AES_CBC :
	public AES
{
public:
	__m128i				vector;

	OctetString			IV;

//--------------
//関数
					AES_CBC(const char _strName[]="AES-CBC");
					~AES_CBC(void);

			void	Set_AES(__m128i _xmm_IV);
			void	SetIV(void *data);
			void	initIV();

			void	init(){initIV();};			//初期化
			void	encrypt(void *data);
			void	decrypt(void *data);

			//ブロック暗号用
			//高速化の為、専用のを作る。
			void	encipher(void *data,unsigned int iSize);
			void	decipher(void *data,unsigned int iSize);
			int		encipher_last(void *data,unsigned int iSize);
			int		decipher_last(void *data,unsigned int iSize);
};
