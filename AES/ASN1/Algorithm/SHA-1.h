#pragma once
#include "sha.h"

/****************************************************************/
/*			�萔��`											*/
/****************************************************************/
#define	SHA1_HashSizeB	160
#define	SHA1_HashSize	(SHA1_HashSizeB/8)

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class SHA1 :
	public SHA
{
public:
	unsigned	int		H[5];				//�n�b�V���l

	SHA1(void);
	~SHA1(void);

	void	init(void);
	void	calc(void *data);
	void	getHash(void *result);
};
