#pragma once
#include "sha.h"

/****************************************************************/
/*			計算式定義											*/
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
/*			定数定義											*/
/****************************************************************/
#define	SHA256_HashSizeB	256
#define	SHA256_HashSize		(SHA256_HashSizeB/8)

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class SHA256 :
	public SHA
{
public:
	unsigned	int		H[8];				//ハッシュ値

	SHA256(void);
	~SHA256(void);

			void	calc(void *data);
	virtual	void	init(void);
	virtual	void	getHash(void *result);
};
