#include "StdAfx.h"
#include "EncryptedData.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
EncryptedData::EncryptedData(const char _strName[]):
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
EncryptedData::~EncryptedData(void)
{
}
//==============================================================
//				オブジェクトの設定
//--------------------------------------------------------------
//	●引数
//			ObjectIdentifier*		_type		暗号文のタイプ
//			Encryption*				_algorithm	暗号アルゴリズム
//			size_t					_szContent	暗号文のサイズ（実体はとりあえず外部に）
//	●返値
//			無し
//==============================================================
void	EncryptedData::Set(
			ObjectIdentifier*		_type,
			Encryption*				_algorithm, 
			size_t					_szContent)
{
	unsigned	int	iVersion;

	//------
	//version CMSVersion
	if(unprotectedAttrs.Constructed.size()>0){
		iVersion = 2;
	} else {
		iVersion = 0;
	}
	version.Set(iVersion);
	Set_Construct(&version);

	//------
	//encryptedContentInfo EncryptedContentInfo
	encryptedContentInfo.Set(_type, _algorithm, _szContent);
	Set_Construct(&encryptedContentInfo);

	//------
	//unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
	if(iVersion == 2){
		//	to do	属性情報を入れる場合の処理。
		Set_Construct(&unprotectedAttrs);
	}
}
