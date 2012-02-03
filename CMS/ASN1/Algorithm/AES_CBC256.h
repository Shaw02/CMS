#pragma once
#include "AES_CBC.h"

//======================================================================
//					AES-CBC-256	Encoder / Decorder
//----------------------------------------------------------------------
//  Reference:
//	RFC 3565		Use of the Advanced Encryption Standard (AES) Encryption
//					Algorithm in Cryptographic Message Syntax (CMS)
//======================================================================
//
//	本プログラムは、AES-CBC-256を処理します。
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
class AES_CBC256 :
	public AES_CBC
{
public:
	static	unsigned	int		oid[];	//	= (2,16,840,1,101,3,4,1,42);

//--------------
//関数
					AES_CBC256(const char _strName[]="AES-CBC-256");
					~AES_CBC256(void);
};
