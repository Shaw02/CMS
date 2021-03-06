#include "StdAfx.h"
#include "FileOutput.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//		const char*		strFileName		ファイル名
//	●返値
//				無し
//==============================================================
FileOutput::FileOutput(const char*	strFileName)
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
FileOutput::~FileOutput(void)
{
	close();
}

//--------------------------------
//ファイルを開く　エラー処理付き
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
//相対シーク
//--------------------------------
void	FileOutput::StreamPointerAdd(__int32 iSize){
	seekp((long)iSize,ios::cur);
};

//--------------------------------
//絶対シーク
//--------------------------------
void	FileOutput::StreamPointerMove(__int32 iSize){
	seekp((long)iSize,ios::beg);
};

