#include "StdAfx.h"
#include "SHA.h"

//==============================================================
//			�R���X�g���N�^
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//==============================================================
SHA::SHA(void)
{
}
//==============================================================
//			�f�X�g���N�^
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//==============================================================
SHA::~SHA(void)
{
}
//==============================================================
//			�n�b�V���l�v�Z
//--------------------------------------------------------------
//	������
//			void *result	�n�b�V���l���i�[����A�h���X
//			void *data		���̓f�[�^�̃|�C���^�i64Byte�j
//			unsigned int n	���̓f�[�^�̃T�C�Y[Byte]
//	���Ԓl
//			����
//==============================================================
void	SHA::CalcHash(void *result, void *data, unsigned int iSize)
{
	unsigned	int		i		= iSize;
	unsigned	int		ptData	= 0;
	unsigned	char*	cData	= (unsigned	char*)data;

	init();

	while(i>0){
		if(i>=SHA_BlockSize){
			add(&cData[ptData]);
			ptData += SHA_BlockSize;
			i -= SHA_BlockSize;
		} else {
			final(&cData[ptData],i);
			break;
		}
	}

	getHash(result);
}
//==============================================================
//			�P�u���b�N�i64Byte�j�̓���
//--------------------------------------------------------------
//	������
//			void *data	�v�Z����P�u���b�N�̃|�C���^�i64Byte�j
//	���Ԓl
//			����
//==============================================================
void	SHA::add(void *data)
{
	calc(data);
	iCountBlock++;
}
//==============================================================
//			�ŏI�u���b�N�i64Byte�����j�̓���
//--------------------------------------------------------------
//	������
//			void *data		�v�Z����P�u���b�N�̃|�C���^�i64Byte�����j
//			unsigned int n	�u���b�N�̃T�C�Y[Byte]
//	���Ԓl
//			����
//==============================================================
void	SHA::final(void *data,unsigned int iSize)
{
	unsigned	char		M[SHA_BlockSize];

	unsigned	__int64		iTotalSize = ((iCountBlock*64)+iSize)*8;
	unsigned	char*		cData = (unsigned char*)data;

	unsigned	int			i = 0;

	//--------------------
	//BlockSize�҂����肾�����B
	if(iSize==SHA_BlockSize){
		add(data);
		iSize = 0;
	}

	//--------------------
	//�z���
	else if(iSize>0){
		memcpy(M, cData, iSize);
		i = iSize;
	}

	M[i] = 0x80;
	i++;

	//--------------------
	//�T�C�Y���������߂Ȃ��ꍇ
	if(iSize >= (SHA_BlockSize-8)){
		memset(&M[i],0,SHA_BlockSize-i);
		add(M);
		i = 0;
	}

	//--------------------
	//�T�C�Y�̏��܂ŁA0x00�Ŗ��߂�B
	memset(&M[i],0,(SHA_BlockSize-8)-i);
	i = (SHA_BlockSize-8)-i;

	//--------------------
	//�T�C�Y�������݁B
	M[SHA_BlockSize-8] = (iTotalSize>>56) & 0xFF;
	M[SHA_BlockSize-7] = (iTotalSize>>48) & 0xFF;
	M[SHA_BlockSize-6] = (iTotalSize>>40) & 0xFF;
	M[SHA_BlockSize-5] = (iTotalSize>>32) & 0xFF;
	M[SHA_BlockSize-4] = (iTotalSize>>24) & 0xFF;
	M[SHA_BlockSize-3] = (iTotalSize>>16) & 0xFF;
	M[SHA_BlockSize-2] = (iTotalSize>>8) & 0xFF;
	M[SHA_BlockSize-1] = iTotalSize & 0xFF;

	calc(M);
}
