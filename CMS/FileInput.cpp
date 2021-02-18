#include "StdAfx.h"
#include "FileInput.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//		const char*		strFileName		�t�@�C����
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
	close();
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
void	FileInput::StreamPointerAdd(std::streamoff iSize){
	seekg(iSize,ios::cur);
};

//--------------------------------
//	��΃V�[�N
//--------------------------------
void	FileInput::StreamPointerMove(std::streamoff iSize){
	seekg(iSize,ios::beg);
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
std::streamoff	FileInput::GetSize(){

	std::streamoff	iData;
	std::streamoff	iDataT = tellg();

	seekg(0		,ios::end);
	iData = tellg();
	seekg(iDataT,ios::beg);

	return(iData);
};
