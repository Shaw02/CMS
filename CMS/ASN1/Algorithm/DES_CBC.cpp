#include "StdAfx.h"
#include "DES_CBC.h"

unsigned	int		DES_CBC::oid[] = {1,3,14,3,2,7};

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
DES_CBC::DES_CBC(const char _strName[]):
	DES(_strName)
{
	mode	= CBC;
	Set_oid(oid,sizeof(oid)/sizeof(int));
}
//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
DES_CBC::DES_CBC(unsigned __int64 IV, const char _strName[]):
	DES(_strName)
{
	mode	= CBC;
	Set_oid(oid,sizeof(oid)/sizeof(int));
	Set_DES(IV);
}
//==============================================================
//		デストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
DES_CBC::~DES_CBC(void)
{
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
void	DES_CBC::SetIV(void *data)
{
	unsigned __int64*	iData = (unsigned __int64*)data;
	vector = *iData;
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
void	DES_CBC::initIV()
{
	unsigned __int64*	cIV = (unsigned __int64*)IV.strValue.c_str();

	vector	= *cIV;
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	●引数
//			void *data		平文
//	●返値
//			無し
//==============================================================
void	DES_CBC::encrypt(void *data)
{
	unsigned __int64*	iData	= (unsigned __int64*)data;
	unsigned __int64	temp	= Cipher(*iData ^ vector);

	vector	= temp;
	*iData	= temp;
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	●引数
//			void *data		暗号文
//	●返値
//			無し
//==============================================================
void	DES_CBC::decrypt(void *data)
{
	unsigned __int64*	iData	= (unsigned __int64*)data;
	unsigned __int64	temp	= InvCipher(*iData) ^ vector;

	vector	= *iData;
	*iData	= temp;
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	●引数
//			__m128i		_xmm_IV		初期化ベクタIV
//	●返値
//			無し
//==============================================================
void	DES_CBC::Set_DES(unsigned __int64 _IV)
{
	//ASN.1の定義
	Set();
	vector = _IV;	//	SetIV()と同じ意味。
	IV.Set((char*)&_IV,sizeof(_IV));
	Set_Construct(&IV);
}
