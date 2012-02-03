#include "StdAfx.h"
#include "FileOutput.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//		const char*		strFileName		�t�@�C����
//	���Ԓl
//				����
//==============================================================
FileOutput::FileOutput(const char*	strFileName)
{
	fileopen(strFileName);
}

//==============================================================
//		�f�X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
FileOutput::~FileOutput(void)
{
	close();
}

//--------------------------------
//�t�@�C�����J���@�G���[�����t��
//--------------------------------
void	FileOutput::fileopen(const char*	strFileName){

	//File open
	open(strFileName,ios_base::out | ios_base::binary);
	if(good()==false){
		perror(strFileName);
		exit(EXIT_FAILURE);
	};
};

//--------------------------------
//���΃V�[�N
//--------------------------------
void	FileOutput::StreamPointerAdd(__int32 iSize){
	seekp((long)iSize,ios::cur);
};

//--------------------------------
//��΃V�[�N
//--------------------------------
void	FileOutput::StreamPointerMove(__int32 iSize){
	seekp((long)iSize,ios::beg);
};
