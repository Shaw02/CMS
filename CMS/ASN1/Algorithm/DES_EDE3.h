#pragma once
#include "DES_EDE3.h"

//======================================================================
//					DES-EDE3	Encoder / Decorder
//----------------------------------------------------------------------
//  Reference:
//	sp800-17	Modes of Operation Validation System(MOVS) : Requirements and Procedures
//	sp800-67	Recommendation for the Triple Data Encryption Algorithm (TDEA) Block Cipher
//======================================================================
//
//	本プログラムは、３ＤＥＳ暗号を処理します。
//
//						Copyright (c) A.Watanabe (2011)
//
//----------------------------------------------------------------------
//	Revision
//		2011.11. 9	初版
//======================================================================
/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class DES_EDE3 :
	public DES
{
public:
	unsigned	__int64	k2[DES_Round];
	unsigned	__int64	k3[DES_Round];

//--------------
//関数
					DES_EDE3(const char _strName[]="DES_EDE3");
					~DES_EDE3(void);

	unsigned __int64	Cipher3(unsigned __int64 iData);
	unsigned __int64	InvCipher3(unsigned __int64 iData);

			void	Set_Key(void *key);
//			void	init(){};					//初期化
			void	encrypt(void *data);
			void	decrypt(void *data);
};
