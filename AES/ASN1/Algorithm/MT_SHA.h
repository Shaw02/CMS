#pragma once
#include "MT.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class MT_SHA :
	public MT
{
public:
	SHA256*	cSHA;
	//�n�b�V���v�Z�p�̃o�b�t�@
	union {
		unsigned	char	c[	(SHA_BlockSize)];
		unsigned	int		i[	(SHA_BlockSize/sizeof(int))];
		unsigned	__int64	i64[(SHA_BlockSize/sizeof(__int64))];
					__m128i	xmm[(SHA_BlockSize/sizeof(__m128i))];
	} __declspec(align(16)) cHashBuff;				//�n�b�V���v�Z�p�o�b�t�@�i�Í��̃p�f�B���O�p��16Byte�]���ɁB�j

	MT_SHA(unsigned long init_key[], unsigned int key_length, SHA256* _cSHA);
	~MT_SHA(void);

	void	generate(void);
	void	get256(void *result);
	__m128i	get__m128i(void);
};
