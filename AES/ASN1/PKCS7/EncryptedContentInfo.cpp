#include "StdAfx.h"
#include "EncryptedContentInfo.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
EncryptedContentInfo::EncryptedContentInfo(const char _strName[]):
	Sequence(_strName),
	encryptedContent(0)
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
EncryptedContentInfo::~EncryptedContentInfo(void)
{
}

//==============================================================
//				オブジェクトの設定
//--------------------------------------------------------------
//	●引数
//			ObjectIdentifier*		_type		暗号文のタイプ
//			AlgorithmIdentifier*	_algorithm	暗号アルゴリズム
//			unsigned	int			_szContent	暗号文のサイズ（実体はとりあえず外部に）
//	●返値
//			無し
//==============================================================
void	EncryptedContentInfo::Set(
			ObjectIdentifier*		_type,
			AlgorithmIdentifier*	_algorithm,
			unsigned	int			_szContent)
{
	//contentType ContentType
	contentType	= _type;
	Set_Construct(contentType);

	//contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier
	contentEncryptionAlgorithm = _algorithm;
	Set_Construct(contentEncryptionAlgorithm);

	//encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
	encryptedContent.Set_ExternalDataSize(_szContent);
	Set_Construct(&encryptedContent);
}
