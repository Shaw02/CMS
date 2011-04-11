#include "StdAfx.h"
#include "PKCS7_Output.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
PKCS7_Output::PKCS7_Output(const char*	strFileName):
	BER_Output(strFileName),
	ContentInfo("PKCS#7 File output")
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
PKCS7_Output::~PKCS7_Output(void)
{
}
//==============================================================
//		
//--------------------------------------------------------------
//	●引数
//				type	データタイプ
//	●返値
//				無し
//==============================================================
void	PKCS7_Output::Set_for_PKCS7(unsigned int type)
{
	static	unsigned	int		oid_pkcs7[]	=	{1,2,840,113549,1,7,type};

	Set(oid_pkcs7, sizeof(oid_pkcs7)/sizeof(int));
}