#include "StdAfx.h"
#include "EnvelopedData.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
EnvelopedData::EnvelopedData(const char _strName[]):
	Sequence(_strName),
	originatorInfo(0),
	unprotectedAttrs(1)
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
EnvelopedData::~EnvelopedData(void)
{
}
//==============================================================
//				オブジェクトの設定
//--------------------------------------------------------------
//	●引数
//			ObjectIdentifier*		_type			暗号文のタイプ
//			Encryption*				_algorithm		暗号アルゴリズム
//			size_t					_szContent		暗号文のサイズ（実体はとりあえず外部に）
//	●返値
//			無し
//	●注意
//			この関数を呼ぶ前に、受信者情報（_recipientinfo）を設定する事
//==============================================================
void	EnvelopedData::Set(
			ObjectIdentifier*		_type,
			Encryption*				_algorithm, 
			size_t					_szContent)
{
	unsigned	int	iVersion;

	//------
	//version CMSVersion
//	if(originatorInfo.Constructed.size()>0){
		// or "pwri" or "ori" or ATTRv3 
		iVersion = 3;
//	} else {
//		if((originatorInfo.Constructed.size()==0) && (unprotectedAttrs.Constructed.size()==0)){
//			//recipientInfos.version == 0
//			iVersion = 0;
//		} else {
//			iVersion = 2;
//		}
//	}
	version.Set(iVersion);
	Set_Construct(&version);

	//------
	//originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
	if(originatorInfo.Constructed.size() > 0){
		Set_Construct(&originatorInfo);
	}

	//------
	//recipientInfos RecipientInfos,
	Set_Construct(&recipientInfos);

	//------
	//encryptedContentInfo EncryptedContentInfo
	encryptedContentInfo.Set(_type, _algorithm, _szContent);
	Set_Construct(&encryptedContentInfo);

	//------
	//unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
	if(unprotectedAttrs.Constructed.size() > 0){
		//	to do	属性情報を入れる場合の処理。
		Set_Construct(&unprotectedAttrs);
	}
}
