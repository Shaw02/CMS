#include "StdAfx.h"
#include "Digest.h"

//==============================================================
//			�R���X�g���N�^
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//==============================================================
Digest::Digest(const char _strName[]):
	AlgorithmIdentifier(_strName)
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
Digest::~Digest(void)
{
}
//==============================================================
//			�n�b�V���l�v�Z
//--------------------------------------------------------------
//	������
//			void	*result		�n�b�V���l���i�[����A�h���X
//			void	*data		���̓f�[�^�̃|�C���^�i64Byte�j
//			size_t	n			���̓f�[�^�̃T�C�Y[Byte]
//	���Ԓl
//			����
//==============================================================
void	Digest::CalcHash(void *result, void *data, size_t iSize)
{
				size_t	i			= iSize;
				size_t	_szBlock	= szBlock;	//�p�x�Ɏg���̂Ń��W�X�^�ɓ����ĖႤ�B
	unsigned	char*	cData		= (unsigned	char*)data;

	init();

	while(i>0){
		if(i>=_szBlock){
			add(cData);
			cData += _szBlock;
			i -= _szBlock;
		} else {
			final(cData,i);
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
void	Digest::add(void *data)
{
	calc(data);
	iCountBlock++;
}
//==============================================================
//			�ŏI�u���b�N�i64Byte�����j�̓���
//--------------------------------------------------------------
//	������
//			void	*data		�v�Z����P�u���b�N�̃|�C���^�i64Byte�����j
//			size_t	n			�u���b�N�̃T�C�Y[Byte]
//	���Ԓl
//			����
//	���Ԓl
//			�f�t�H���g�́AMD5, SHA-1, SHA-2�p�@���p
//==============================================================
void	Digest::final(void *data, size_t iSize)
{
				size_t	i = 0;

	unsigned	__int64		iTotalSize	= ((iCountBlock*64)+iSize)*8;
	unsigned	char*		cData		= (unsigned char*)data;

	//�p�x�Ɏg���̂Ń��W�X�^�ɓ����ĖႤ�B
	unsigned	char*		_M			= M;
				size_t		_szBlock	= szBlock;

	//--------------------
	//BlockSize�҂����肾�����B
	if(iSize == _szBlock){
		add(data);
		iSize = 0;
	}

	//--------------------
	//�z���
	else if(iSize>0){
		memcpy(_M, cData, iSize);
		i = iSize;
	}

	_M[i] = 0x80;
	i++;

	//--------------------
	//�T�C�Y���������߂Ȃ��ꍇ
	if(iSize >= (_szBlock-8)){
		memset(&_M[i],0,_szBlock - i);
		add(_M);
		i = 0;
	}

	//--------------------
	//�T�C�Y�̏��܂ŁA0x00�Ŗ��߂�B
	memset(&_M[i],0,(_szBlock-8)-i);
	i = (_szBlock - 8)-i;

	//--------------------
	//�T�C�Y�������݁B
	_M[_szBlock - 8] = (iTotalSize>>56) & 0xFF;
	_M[_szBlock - 7] = (iTotalSize>>48) & 0xFF;
	_M[_szBlock - 6] = (iTotalSize>>40) & 0xFF;
	_M[_szBlock - 5] = (iTotalSize>>32) & 0xFF;
	_M[_szBlock - 4] = (iTotalSize>>24) & 0xFF;
	_M[_szBlock - 3] = (iTotalSize>>16) & 0xFF;
	_M[_szBlock - 2] = (iTotalSize>>8) & 0xFF;
	_M[_szBlock - 1] = iTotalSize & 0xFF;

	calc(_M);
}
