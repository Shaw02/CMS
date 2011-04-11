#pragma once
#include "AlgorithmIdentifier.h"
/****************************************************************/
/*			計算式定義											*/
/****************************************************************/
#define ROTL(n,x)		((x<<n) | (x>>((sizeof(x)*8)-n)))
#define ROTR(n,x)		((x>>n) | (x<<((sizeof(x)*8)-n)))
#define SHR(n,x)		(x>>n)

#define	_mm_ROTLD(n,x)	_mm_or_si128(_mm_slli_epi32(x,n),_mm_srli_epi32(x,32-n))
#define	_mm_ROTRD(n,x)	_mm_or_si128(_mm_srli_epi32(x,n),_mm_slli_epi32(x,32-n))
#define	_mm_SHRD(n,x)	_mm_srli_epi32(x,n)

#define	Ch(x,y,z)		((x & y) ^ ((~x) & z))
#define	Parity(x,y,z)	(x ^ y ^ z)
#define	Maj(x,y,z)		((x & y) ^ (x & z) ^ (y & z))

/****************************************************************/
/*			定数定義											*/
/****************************************************************/
#define	SHA_BlockSize	64
#define	SHA_BlockSizeB	SHA_BlockSize * 8

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class SHA :
	public AlgorithmIdentifier
{
public:
	unsigned	int		iCountBlock;		//Block数のカウント

	SHA(void);
	~SHA(void);

			void	CalcHash(void *result, void *data,unsigned int iSize);
			void	add(void *data);
			void	final(void *data,unsigned int iSize);

	virtual	void	init(void){};
	virtual	void	calc(void *data){};
	virtual	void	getHash(void *result){};
};
