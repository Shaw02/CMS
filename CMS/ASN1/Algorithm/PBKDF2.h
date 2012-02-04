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
//	�{�v���O�����́APBKDF2���Z�o����N���X�ł��B
//
//						Copyright (c) A.Watanabe (2011)
//
//----------------------------------------------------------------------
//	Revision
//		2011. 4.28		����
//======================================================================
/****************************************************************/
/*			�萔��`											*/
/****************************************************************/

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class PBKDF2 :
	public KeyDerivation
{
//--------------
//�ϐ�

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
			OctetString			salt;				//�\���g
			Integer				iterationCount;		//�J��Ԃ���
			Integer				keyLength;			//option
			HMAC*				cHMAC;				//�n�b�V���֐�

			string				S;			//�T���g
			unsigned	int		c;			//�J��Ԃ���

			//�J��Ԃ��v�Z�p�o�b�t�@
			unsigned	int		hLen;
			unsigned	char*	U_;

			unsigned	char*	US;

			//�r���I�_���a���i�[����o�b�t�@
			unsigned	int		__m128_hLen;
					__m128i*	__m128_U;

			//ASN.1�p
	static	unsigned	int		oid[];		//	= {1.2.840.113549.1.5.12};

//--------------
//�֐�
public:
	PBKDF2(HMAC* _cHash, const char _strName[]="PBKDF2");
	~PBKDF2(void);

	void	Set_PBKDF2(void* _S, unsigned int _szS, unsigned int _c, unsigned int _dkLen);

	void	F(void* T, unsigned int szT, unsigned int n);
	void	calc(void* DK, void* P, unsigned int szP);
};
