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
//			unsigned	int			_szContent	暗号文のサイズ（実体はとりあえず外部に）
//	●返値
//			無し
//==============================================================
void	EncryptedData::Set(
			ObjectIdentifier*		_type,
			Encryption*				_algorithm, 
			unsigned	int			_szContent)
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
/*
//==============================================================
//				暗号
//--------------------------------------------------------------
//	●引数
//			unsigned char*	CEK			暗号鍵
//			FileInput*		f_Plain		入力ファイル（平文）
//			FileOutput*		f_Cipher	出力ファイル（暗号文）
//			unsigned int	szContent	サイズ
//	●返値
//			int				0			正常（これしか返さないけど…）
//							-1			異常
//	●注意
//			これより前のASN.1データは、事前にエンコードしてファイルに出力しておく事。
//			引数"f_Cipher"には、上述の途中までエンコードされたファイルオブジェクトを渡す。
//==============================================================
int		EncryptedData::encrypt(
			unsigned char*	CEK,
			FileInput*	f_Plain, 
			FileOutput*	f_Cipher,
			unsigned int szContent)
{
	unsigned	int	iResult;

	iResult = encryptedContentInfo.encrypt(CEK, f_Plain, f_Cipher, szContent);

	return(iResult);
}
*/
