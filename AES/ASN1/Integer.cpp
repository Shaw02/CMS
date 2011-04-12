#include "StdAfx.h"
#include "Integer.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
Integer::Integer(const char _strName[]):
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
Integer::~Integer(void)
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
void	Integer::encodeBER()
{
	encodeBER_TAG(BER_Class_General, false, BER_TAG_INTEGER, Get_szInt_for_BER(iValue));
	encodeBER_int(iValue);
}
//==============================================================
//		値を設定
//--------------------------------------------------------------
//	●引数
//			int		i		設定する整数値
//	●返値
//			無し
//==============================================================
void	Integer::Set(int i)
{
	iValue = i;
}
