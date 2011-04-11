#include "StdAfx.h"
#include "FileInput.h"

//==============================================================
//		�f�X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
FileInput::FileInput(void)
{
}
//==============================================================
//		�f�X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
FileInput::FileInput(const char*	strFileName)
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
FileInput::~FileInput(void)
{
}

//--------------------------------
//	�t�@�C�����J���@�G���[�����t��
//--------------------------------
void	FileInput::fileopen(const char*	strFileName){

	open(strFileName,ios_base::in | ios_base::binary);
	if(good()==false){
		perror(strFileName);
		exit(EXIT_FAILURE);
	};
};

//--------------------------------
//	���΃V�[�N
//--------------------------------
void	FileInput::StreamPointerAdd(__int32 iSize){
	seekg((long)iSize,ios::cur);
};

//--------------------------------
//	��΃V�[�N
//--------------------------------
void	FileInput::StreamPointerMove(__int32 iSize){
	seekg((long)iSize,ios::beg);
};

//--------------------------------
//1Byte�ǂݍ���
//--------------------------------
unsigned	char	FileInput::cRead(){

	unsigned	char	cData;

	read((char*)&cData, sizeof(unsigned char));
	return(cData);
};

//--------------------------------
//2Byte�ǂݍ���
//--------------------------------
unsigned	__int16	FileInput::i16Read(){

	unsigned	__int16	iData;

	read((char*)&iData, sizeof(unsigned __int16));
	return(iData);
};
//--------------------------------
//�T�C�Y
//--------------------------------
unsigned	int	FileInput::GetSize(){

	unsigned	int	iData;
	unsigned	int	iDataT = tellg();

	seekg(0		,ios::end);
	iData = tellg();
	seekg(iDataT,ios::beg);

	return(iData);
};
