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
//	�{�v���O�����́AHMAC���Z�o����ׂ̊��N���X�ł��B
//
//						Copyright (c) A.Watanabe (2011)
//
//----------------------------------------------------------------------
//	Revision
//		2011. 4.21	����
//======================================================================
/****************************************************************/
/*			�萔��`											*/
/****************************************************************/

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class HMAC :
	public AlgorithmIdentifier
{
//--------------
//�^��`
union _mm_i32
{
	__declspec(align(16))	unsigned	int		i32[4];
							__m128i				m128i;
};

//--------------
//�ϐ�
public:
	Digest*	cHash;		//�n�b�V���֐�
	ASN1	null;		//Param

	char*	Kipad;
	char*	Kopad;

//--------------
//�֐�
public:
	HMAC(Digest* _cHash, const char _strName[]="HMAC");
	~HMAC(void);

	void	SetKey(void* Key, size_t szKey);
	void	calc(void* result, void* data, size_t szData);
};
