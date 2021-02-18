#pragma once
#include "AlgorithmIdentifier.h"

//======================================================================
//					HMAC: Keyed-Hashing for Message Authentication
//======================================================================
//	Reference:
//	RFC 5652		Cryptographic Message Syntax (CMS)
//	RFC 3370		Cryptographic Message Syntax (CMS) Algorithms
//	RFC	2104		HMAC: Keyed-Hashing for Message Authentication
//======================================================================
//
//	本プログラムは、HMACを算出する為の基底クラスです。
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
class HMAC :
	public AlgorithmIdentifier
{
//--------------
//型定義
union _mm_i32
{
	__declspec(align(16))	unsigned	int		i32[4];
							__m128i				m128i;
};

//--------------
//変数
public:
	Digest*	cHash;		//ハッシュ関数
	ASN1	null;		//Param

	char*	Kipad;
	char*	Kopad;

//--------------
//関数
public:
	HMAC(Digest* _cHash, const char _strName[]="HMAC");
	~HMAC(void);

	void	SetKey(void* Key, size_t szKey);
	void	calc(void* result, void* data, size_t szData);
};
