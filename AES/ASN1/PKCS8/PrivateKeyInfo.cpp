#include "StdAfx.h"
#include "PrivateKeyInfo.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
PrivateKeyInfo::PrivateKeyInfo(const char _strName[]):
	Sequence(_strName)
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
PrivateKeyInfo::~PrivateKeyInfo(void)
{
}
//==============================================================
//		値を設定
//--------------------------------------------------------------
//	●引数
//			ASN1* asn1		memberとなるobject
//	●返値
//			無し
//==============================================================
void	PrivateKeyInfo::Set(
			AlgorithmIdentifier*	_algorithm,
						char		c[],
			unsigned	int			iSize)
{
	//version                   Version,
	version.Set(0);
	Set_Construct(&version);

	//privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
	privateKeyAlgorithm = _algorithm;
	Set_Construct(privateKeyAlgorithm);

	//privateKey                PrivateKey,
	privateKey.Set(c, iSize);
	Set_Construct(&privateKey);

	//attributes           [0]  IMPLICIT Attributes OPTIONAL }


}
