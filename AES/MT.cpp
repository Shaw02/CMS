#include "stdafx.h"
#include "mt.h"

//==============================================================
//		
//--------------------------------------------------------------
//	������
//		����
//	���Ԓl
//		����	
//==============================================================
MT::MT():
	mti(N+1)
{
	//Default seed	�X�^�e�B�b�N�̈�ɒu���B�i�X�^�b�N�ɒu����mov���߂�4�f���B�j
	static	unsigned	long	init[4]	=	{0x123, 0x234, 0x345, 0x456};

	init_by_array(init, 4);
}
//==============================================================
//		
//--------------------------------------------------------------
//	������
//		unsigned long init_key[]	��
//		unsigned int key_length		��̐�
//	���Ԓl
//		����	
//==============================================================
MT::MT(unsigned long init_key[], unsigned int key_length):
	mti(N+1)
{
	init_by_array(init_key, key_length);
}
//==============================================================
//		initializes mt[N] with a seed
//--------------------------------------------------------------
//	������
//		unsigned	long	s		��
//	���Ԓl
//		����	
//==============================================================
void MT::init_genrand(unsigned long s)
{

	unsigned	int	iMT = 0;	//��U���W�X�^�ɓ����B

	mt[iMT++] = s & 0xffffffffUL;

	do{
	//	__asm	prefetchnta	mt[iMT+8]
		_mm_prefetch((const char *)&mt[iMT+4], 0);	//���߂̔z����AL1�L���b�V���Ƀt�F�b�`���Ă����B
		_mm_prefetch((const char *)&mt[iMT+8], 1);	//���낻��̂��AL2�L���b�V���Ƀt�F�b�`���Ă����B

		//���������g��Ȃ��ŁA���W�X�^�[�����Ōv�Z����B
		//�ϐ�"s"�ɂ́A���� mt[iMT-1]�������Ă���B
		s = ((unsigned long)1812433253 * (s ^ (s >> 30)) + iMT) & 0xffffffffUL;
	
		//�z��ϐ��ւ̏������݂́A���̈�񂾂��ɁB
		mt[iMT++] = s;

	} while (iMT < N);

	mti = iMT;
}

//==============================================================
//		initialize by an array with array-length
//		init_key is the array for initializing keys
//		key_length is its length
//		slight change for C++, 2004/2/26
//--------------------------------------------------------------
//	������
//		unsigned long init_key[]	��
//		unsigned int key_length		��̐�
//	���Ԓl
//		����
//==============================================================
void MT::init_by_array(unsigned long init_key[], unsigned int key_length)
{

	//���̕ӂ́A���W�X�^�[�ϐ��ɂȂ��Ă����B
	unsigned	int		iMT		= 0;	
	unsigned	int		iKey	= 0;	
	unsigned	int		k		= ((N>key_length)? N : key_length);
	unsigned	long	r;		//result

	init_genrand(19650218UL);

	r = mt[iMT++];		//���[�v���ł̃������ǂݍ��݂𖳂����ׁA�����œǂ�ł����B
						//�����������x���A�N�Z�X����ƁA�������̃L���b�V����R/W�������ׁB

	while(k--){
	//	__asm	prefetchnta	mt[iMT+8]
		_mm_prefetch((const char *)&mt[iMT+4], 0);	//���߂̔z����AL1�L���b�V���Ƀt�F�b�`���Ă����B
	//	_mm_prefetch((const char *)&mt[iMT+8], 1);	//���낻��̂��AL2�L���b�V���Ƀt�F�b�`���Ă����B

		//���������g��Ȃ��ŁA���W�X�^�[�����Ōv�Z����B
		//�ϐ�"r"�ɂ́A���� mt[iMT-1]�������Ă���B
		r = ((mt[iMT] ^ ((r ^ (r >> 30)) * (unsigned long)1664525)) + init_key[iKey] + iKey) & 0xffffffffUL;

		//�z��ϐ��ւ̏������݂́A���̈�񂾂��ɁB
		mt[iMT++] = r;

		if (iMT>=N){
			iMT=1;
//			mt[iMT++] = r;		//�ϐ�"r"�ɓ����Ă���̂ŗv��Ȃ�
		}
		iKey++;
		if(iKey>=key_length){iKey=0;}
	};

	k = N-1;
	while(k--){
	//	__asm	prefetchnta	mt[iMT+8]
		_mm_prefetch((const char *)&mt[iMT+4], 0);	//���߂̔z����AL1�L���b�V���Ƀt�F�b�`���Ă����B
	//	_mm_prefetch((const char *)&mt[iMT+8], 1);	//���낻��̂��AL2�L���b�V���Ƀt�F�b�`���Ă����B

		//���������g��Ȃ��ŁA���W�X�^�[�����Ōv�Z����B
		//�ϐ�"r"�ɂ́A���� mt[iMT-1]�������Ă���B
		r = ((mt[iMT] ^ ((r ^ (r >> 30)) * (unsigned long)1566083941)) - iMT) & 0xffffffffUL;

		mt[iMT++] = r;		//�z��ւ̏������݁B
        if (iMT>=N){
			iMT=1;
//			mt[iMT++] = r;		//�ϐ�"r"�ɓ����Ă���̂ŗv��Ȃ�
		}
	};

	mt[0] = 0x80000000UL; /* MSB is 1; assuring non-zero initial array */ 

}

//==============================================================
//		generates a random number on [0,0xffffffff]-interval
//--------------------------------------------------------------
//	������
//		����
//	���Ԓl
//		unsigned long		����
//==============================================================
unsigned long MT::genrand_int32(void)
{

	unsigned	int		iMT = mti;	//��U���W�X�^�ɓ����B
	unsigned	long	y;
	unsigned	long	n;

	if(iMT >= N){

		if(iMT >= N+1){		//����������Ă��Ȃ�������A����������B
			init_genrand(5489);
		}

		iMT		= 0;
		n		= mt[iMT];
		do{
			y = (n & UPPER_MASK);
			n = mt[iMT+1];			//���̒l�Ƃ��Ďg���B
			y |= (n & LOWER_MASK);
			mt[iMT] = (mt[iMT+M]) ^ ((y)&1UL ? MATRIX_A : 0) ^ (y >> 1);
			iMT++;
		} while (iMT < N-M);

		do{
			y = (n & UPPER_MASK);
			n = mt[iMT+1];			//���̒l�Ƃ��Ďg���B
			y |= (n & LOWER_MASK);
			mt[iMT] = (mt[iMT+M-N]) ^ ((y)&1UL ? MATRIX_A : 0) ^ (y >> 1);
			iMT++;
		} while (iMT < N-1);

			y = (n & UPPER_MASK) | (mt[0] & LOWER_MASK);
			mt[N-1] = (mt[M-1]) ^ ((y)&1UL ? MATRIX_A : 0) ^ (y >> 1);
			iMT = 0;
	}

    /* Tempering */
	y	= mt[iMT++];
	mti	= iMT;

	y ^= (y >> 11);
    y ^= (y << 7) & 0x9d2c5680UL;
    y ^= (y << 15) & 0xefc60000UL;
    y ^= (y >> 18);

    return y;
}
