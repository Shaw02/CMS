#pragma once
#include "sha.h"

/****************************************************************/
/*			定数定義											*/
/****************************************************************/
#define	SHA1_HashSizeB	160
#define	SHA1_HashSize	(SHA1_HashSizeB/8)

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class SHA1 :
	public SHA
{
public:
	unsigned	int		H[5];				//ハッシュ値

	SHA1(void);
	~SHA1(void);

	void	init(void);
	void	calc(void *data);
	void	getHash(void *result);
};
