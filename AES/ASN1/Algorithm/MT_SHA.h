#pragma once
#include "MT.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class MT_SHA :
	public MT
{
public:
	SHA256*	cSHA;
	//ハッシュ計算用のバッファ
	union {
		unsigned	char	c[	(SHA_BlockSize)];
		unsigned	int		i[	(SHA_BlockSize/sizeof(int))];
		unsigned	__int64	i64[(SHA_BlockSize/sizeof(__int64))];
					__m128i	xmm[(SHA_BlockSize/sizeof(__m128i))];
	} __declspec(align(16)) cHashBuff;				//ハッシュ計算用バッファ（暗号のパディング用に16Byte余分に。）

	MT_SHA(unsigned long init_key[], unsigned int key_length, SHA256* _cSHA);
	~MT_SHA(void);

	void	generate(void);
	void	get256(void *result);
	__m128i	get__m128i(void);
};
