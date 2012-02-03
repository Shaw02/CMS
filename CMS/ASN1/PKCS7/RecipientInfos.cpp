#include "StdAfx.h"
#include "RecipientInfos.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//		const char	_strName		クラス名
//	●返値
//				無し
//==============================================================
RecipientInfos::RecipientInfos(const char _strName[]):
	Set(_strName)
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
RecipientInfos::~RecipientInfos(void)
{
	Context*	_RecipientInfo;

	//Contextの開放
	while(!RecipientInfo.empty()){
		_RecipientInfo = RecipientInfo.back();
		delete	_RecipientInfo;
		RecipientInfo.pop_back();
	}

}
//==============================================================
//		受信者情報の追加
//--------------------------------------------------------------
//	●引数
//				int	type			受信者情報（鍵管理手法）のタイプ
//										[0]	公開鍵暗号
//										[1]	
//										[2]	
//										[3]	鍵導出（パスワード）
//										[4]	
//		Sequence*	_recipientinfo	受信者情報
//	●返値
//				無し
//==============================================================
void	RecipientInfos::AddRecipientInfo(int type, Sequence* _recipientinfo)
{
	Context*	_RecipientInfo	=	new Context(type);

	if(type == 0){
		//Setのまま
		Set_Construct(_recipientinfo);
	} else {
		//Contextにする
		_recipientinfo->mode = _IMPLICIT;
		_RecipientInfo->Set_Construct(_recipientinfo);
		Set_Construct(_RecipientInfo);
		RecipientInfo.push_back(_RecipientInfo);
	}
}
//==============================================================
//			受信者情報の追加（受信者は、パスワード）
//--------------------------------------------------------------
//	●引数
//		string*				strPassword		パスワード
//		OctetString*		CEK				コンテンツ用暗号鍵
//		HMAC*				hmac			PBKDF2関数に設定するHMAC関数
//		unsigned	int		count			PBKDF2関数に設定する繰り返し回数
//		unsigned	int		mode			PWRI_KEKで使用する鍵暗号
//	●返値
//		無し。
//	●処理
//		パスワードから鍵暗号化鍵KEKを導出し、セッション鍵をラップする。
//	●備考
//		以下のアルゴリズムを使用します。
//		keyDerivationAlgorithm	…	PBKDF2(hmac)
//		keyEncryptionAlgorithm	…	PWRI_KEK(mode)
//==============================================================
void	RecipientInfos::AddRecipient(
			string*			strPassword,
			OctetString*	CEK,
			HMAC*			hmac,
			unsigned int	count,
			unsigned int	mode)
{
				//乱数で、鍵暗号用のIVと、PBKDF2用のソルト値を生成。
				__m128i		_IV		= cRandom->get__m128i();	
				__int64		i64Salt	= cRandom->get_int64();

	//------------------
	//鍵導出

	//※keyDerivationは、クラス"PasswordRecipientInfo"でメモリ開放を行う。
	cPBKDF2	= new PBKDF2(hmac);

	cPBKDF2->Set_PBKDF2(&i64Salt,sizeof(i64Salt),count,CEK->strValue.size());
	cPWRI_KEK.Set_PWRI_KEK(mode, _IV);
	cPassword.SetInfo(cPBKDF2, &cPWRI_KEK);
	cPassword.SetKey((void *)strPassword->c_str(), strPassword->length(), (void *)CEK->strValue.c_str(), CEK->strValue.size());
	AddRecipientInfo(3,&cPassword);
}
