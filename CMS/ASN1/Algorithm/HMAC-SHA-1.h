#pragma once
#include "HMAC.h"

//======================================================================
//					HMAC-SHA-1
//----------------------------------------------------------------------
//  Reference:
//	RFC 2898		PKCS #5: Password-Based Cryptography Specification
//======================================================================
//
//	本プログラムは、HMAC-SHA-1を算出するクラスです。
//
//						Copyright (c) A.Watanabe (2011)
//
//----------------------------------------------------------------------
//	Revision
//		2011. 4.21	初版
//======================================================================
/****************************************************************/
/*			定数定義											*/
/****************************************************************/



/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class HMAC_SHA1 :
	public HMAC
{
public:
	static	unsigned	int		oid[];
	static	unsigned	int		oid2[];

	HMAC_SHA1(SHA1* _cSHA1, const char _strName[]="HMAC-SHA-1");
	~HMAC_SHA1(void);

	void	Set_HMAC_SHA1(void);		//ASN.1用の構造体作成

};
