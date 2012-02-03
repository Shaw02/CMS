#pragma once
#include "MT.h"

//======================================================================
//					Mersenne Twister with SHA-256
//======================================================================
//
//	�{�v���O�����́A�^������"Mersenne Twister"�̏o�͂ɁA
//	�X�ɁA�Í��w�I�n�b�V���֐��ł���"SHA-256"��ʂ��A
//	�Í��_�I�[������������Ɠ����̗������������܂��B
//
//						Copyright (c) A.Watanabe (2011)
//
//----------------------------------------------------------------------
//	���ӁF
//		�����̎�́A�����G���g���s�[�i��葽�����ʁj�����A
//		����׏�񌹂�����ꂽ�l���g�p���ĉ������B
//			��F	�d���N��������́ACPU�̌o�߃N���b�N��
//					HDD�̃V�[�N����
//					etc..
//
//		��	�Q�[�����ł͌��ݎ����𗐐��̎�ɂ��鎖�������ł����A
//			�Z�L�����e�B�̐��E�ł́A�����߂��܂���B
//			�����������Ԃ����������ꍇ�A�������Č��ł��Ă��܂��A
//			�e�ՂȍU�����\�ɂȂ��Ă��܂��܂��B
//
//======================================================================
/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class MT_SHA :
	public MT
{
public:
	SHA256	cSHA;
	//�n�b�V���v�Z�p�̃o�b�t�@
	union {
		unsigned	char	c[	(SHA_BlockSize)];
		unsigned	int		i[	(SHA_BlockSize/sizeof(int))];
		unsigned	__int64	i64[(SHA_BlockSize/sizeof(__int64))];
					__m128i	xmm[(SHA_BlockSize/sizeof(__m128i))];
	} __declspec(align(16)) cHashBuff;				//�n�b�V���v�Z�p�o�b�t�@�i�Í��̃p�f�B���O�p��16Byte�]���ɁB�j

	MT_SHA(unsigned long init_key[], unsigned int key_length);
	~MT_SHA(void);

	void	generate(void);
	int		get_int(void);
	__int64	get_int64(void);
	void	get256(void *result);
	__m128i	get__m128i(void);
};
