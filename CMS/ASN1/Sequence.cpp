#include "StdAfx.h"
#include "Sequence.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
Sequence::Sequence(const char _strName[]):
	ASN1(_strName)
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
Sequence::~Sequence(void)
{
}
//==============================================================
//		ＢＥＲ符号化
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
void	Sequence::encodeBER()
{
	encodeBER_Constructed(BER_Class_General, BER_TAG_SEQUENCE);
}
