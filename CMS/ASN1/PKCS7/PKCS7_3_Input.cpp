#include "StdAfx.h"
#include "PKCS7_3_Input.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
PKCS7_3_Input::PKCS7_3_Input(const char*	strFileName):
	PKCS7_Input(strFileName)
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
PKCS7_3_Input::~PKCS7_3_Input(void)
{
}
//==============================================================
//		【ファイル読み込み】EnvelopedData
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
void	PKCS7_3_Input::Get_EnvelopedData()
{
	//ContentInfo
	read_ContentInfo(EnvelopedData_type);

	//EnvelopedData
	ptEncryptedContent = read_EnvelopedData(&enveloped_data);
}
//==============================================================
//			受信
//--------------------------------------------------------------
//	●引数
//			string*	strPassword	パスワード
//	●返値
//			無し
//==============================================================
void	PKCS7_3_Input::Receipt(string*	strPassword)
{
	int	szCEK;
	PasswordRecipientInfo*	_password	= &enveloped_data.recipientInfos.cPassword;

	//"PasswordRecipientInfo"があるかチェック
	if(enveloped_data.recipientInfos.fPassword = false){
		errPrint("Decrypt",": 暗号文にPasswordRecipientInfoがありません。");
	}

	//鍵導出
	szCEK = _password->GetKey((void*)strPassword->c_str(), strPassword->size(), (void*)_password->EncryptedKey.strValue.c_str(), _password->EncryptedKey.strValue.size());
	if(szCEK != enveloped_data.encryptedContentInfo.contentEncryptionAlgorithm->szKey){
		errPrint("Decrypt",": Passwordが違います。");
	}

	//コンテンツ用暗号鍵の設定
	CEK.Set((char *)_password->keyEncryptionAlgorithm->GetKey(), szCEK);
}
//==============================================================
//				暗号化
//--------------------------------------------------------------
//	●引数
//			FileOutput*			f_Plain			平文ファイル
//	●返値
//			ObjectIdentifier*	_contentType	
//	●処理
//			暗号鍵（*.Key）ファイルを暗号鍵にして暗号化
//==============================================================
void	PKCS7_3_Input::decrypt(
			FileOutput*			f_Plain)
{
	int	iResult;

	//暗号文本体
	StreamPointerMove(ptEncryptedContent);
	iResult = enveloped_data.encryptedContentInfo.decrypt((unsigned char*)CEK.strValue.c_str(), this, f_Plain);

	if(iResult != 0){
		errPrint("Decrypt",": Content-Encryption-Key may be different.");
	}

}
