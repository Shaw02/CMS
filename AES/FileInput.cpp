#include "StdAfx.h"
#include "FileInput.h"

//==============================================================
//		デストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
FileInput::FileInput(void)
{
}
//==============================================================
//		デストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
FileInput::FileInput(const char*	strFileName)
{
	fileopen(strFileName);
}

//==============================================================
//		デストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
FileInput::~FileInput(void)
{
}

//--------------------------------
//	ファイルを開く　エラー処理付き
//--------------------------------
void	FileInput::fileopen(const char*	strFileName){

	open(strFileName,ios_base::in | ios_base::binary);
	if(good()==false){
		perror(strFileName);
		exit(EXIT_FAILURE);
	};
};

//--------------------------------
//	相対シーク
//--------------------------------
void	FileInput::StreamPointerAdd(__int32 iSize){
	seekg((long)iSize,ios::cur);
};

//--------------------------------
//	絶対シーク
//--------------------------------
void	FileInput::StreamPointerMove(__int32 iSize){
	seekg((long)iSize,ios::beg);
};

//--------------------------------
//1Byte読み込み
//--------------------------------
unsigned	char	FileInput::cRead(){

	unsigned	char	cData;

	read((char*)&cData, sizeof(unsigned char));
	return(cData);
};

//--------------------------------
//2Byte読み込み
//--------------------------------
unsigned	__int16	FileInput::i16Read(){

	unsigned	__int16	iData;

	read((char*)&iData, sizeof(unsigned __int16));
	return(iData);
};
//--------------------------------
//サイズ
//--------------------------------
unsigned	int	FileInput::GetSize(){

	unsigned	int	iData;
	unsigned	int	iDataT = tellg();

	seekg(0		,ios::end);
	iData = tellg();
	seekg(iDataT,ios::beg);

	return(iData);
};
