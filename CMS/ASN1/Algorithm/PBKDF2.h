#pragma once
#include "KeyDerivation.h"

//======================================================================
//					PBKDF2: Password-Based Key Derivation Function 2
//----------------------------------------------------------------------
//	Reference:
//	RFC 5652		Cryptographic Message Syntax (CMS)
//	RFC 3370		Cryptographic Message Syntax (CMS) Algorithms
//	RFC 2898		PKCS #5: Password-Based Cryptography Specification
//	RFC 3211		Password-based Encryption for CMS
//	RFC 6070		Password-Based Key Derivation Function 2 (PBKDF2) Test Vectors
//======================================================================
//
//	本プログラムは、PBKDF2を算出するクラスです。
//
//						Copyright (c) A.Watanabe (2011)
//
//----------------------------------------------------------------------
//	Revision
//		2011. 4.28		初版
//======================================================================
/****************************************************************/
/*			定数定義											*/
/****************************************************************/

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class PBKDF2 :
	public KeyDerivation
{
//--------------
//変数

/*
PBKDF2-params ::= SEQUENCE {
  salt CHOICE {
    specified OCTET STRING,
    otherSource AlgorithmIdentifier {{PBKDF2-SaltSources} },
  iterationCount INTEGER (1..MAX),
  keyLength INTEGER (1..MAX) OPTIONAL,
  prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1 }
*/
			Sequence			parameters;			//
			OctetString			salt;				//ソルト
			Integer				iterationCount;		//繰り返し回数
			Integer				keyLength;			//option
			HMAC*				cHMAC;				//ハッシュ関数

			string				S;			//サルト
			unsigned	int		c;			//繰り返し回数

			//繰り返し計算用バッファ
			unsigned	int		hLen;
			unsigned	char*	U_;

			unsigned	char*	US;

			//排他的論理和を格納するバッファ
			unsigned	int		__m128_hLen;
					__m128i*	__m128_U;

			//ASN.1用
	static	unsigned	int		oid[];		//	= {1.2.840.113549.1.5.12};

//--------------
//関数
public:
	PBKDF2(HMAC* _cHash, const char _strName[]="PBKDF2");
	~PBKDF2(void);

	void	Set_PBKDF2(void* _S, unsigned int _szS, unsigned int _c, unsigned int _dkLen);

	void	F(void* T, unsigned int szT, unsigned int n);
	void	calc(void* DK, void* P, unsigned int szP);
};
