#pragma once
#include "sha.h"

//======================================================================
//					SHA-256
//----------------------------------------------------------------------
//  Reference:
//	RFC 4634		US Secure Hash Algorithms (SHA and HMAC-SHA)
//	RFC 5754		Using SHA2 Algorithms with Cryptographic Message Syntax
//======================================================================
//
//	�{�v���O�����́ASHA-256�n�b�V�����Z�o����N���X�ł��B
//
//						Copyright (c) A.Watanabe (2011)
//
//----------------------------------------------------------------------
//	Revision
//		2011. 1.17	����
//		2011. 4.21	�n�b�V���l��4Byte�P�ʂŏ�ʁE���ʃo�C�g�����]���Ă����o�O���C���B
//======================================================================
/****************************************************************/
/*			�萔��`											*/
/****************************************************************/


/****************************************************************/
/*			�v�Z����`											*/
/****************************************************************/
#define S256_0(x)		(ROTR( 2,x) ^ ROTR(13,x) ^ ROTR(22,x))
#define S256_1(x)		(ROTR( 6,x) ^ ROTR(11,x) ^ ROTR(25,x))
#define A0_256(x)		(ROTR( 7,x) ^ ROTR(18,x) ^  SHR( 3,x))
#define A1_256(x)		(ROTR(17,x) ^ ROTR(19,x) ^  SHR(10,x))

#define	_mm_S256_0(x)	(_mm_xor_si128(_mm_ROTRD(2,x)	,_mm_xor_si128(_mm_ROTRD(13,x)	,_mm_ROTRD(22,x))))
#define	_mm_S256_1(x)	(_mm_xor_si128(_mm_ROTRD(6,x)	,_mm_xor_si128(_mm_ROTRD(11,x)	,_mm_ROTRD(25,x))))
#define	_mm_A0_256(x)	(_mm_xor_si128(_mm_ROTRD(7,x)	,_mm_xor_si128(_mm_ROTRD(18,x)	, _mm_SHRD( 3,x))))
#define	_mm_A1_256(x)	(_mm_xor_si128(_mm_ROTRD(17,x)	,_mm_xor_si128(_mm_ROTRD(19,x)	, _mm_SHRD(10,x))))

/****************************************************************/
/*			�萔��`											*/
/****************************************************************/
#define	SHA256_HashSizeB	256
#define	SHA256_HashSize		(SHA256_HashSizeB/8)

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class SHA256 :
	public SHA
{
public:
	static	unsigned	int		oid[];
			unsigned	int		H[8];				//�n�b�V���l

	SHA256(const char _strName[]="SHA-256");
	~SHA256(void);

	void	Set_SHA256(void);		//ASN.1�p�̍\���̍쐬

			void	calc(void *data);
	virtual	void	init(void);
			void	getHash(void *result);
};
