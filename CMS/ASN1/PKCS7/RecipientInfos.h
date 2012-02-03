#pragma once
#include "..\Set.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class RecipientInfos :
	public Set
{
public:
//--------------
//変数
/*
RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
*/
	//ContextのASN.1オブジェクトを作るので、そのポインターを保存しておく。
	vector<Context*>	RecipientInfo;

	//------
	//鍵配送
//	vector<>				;		//各受信者情報

	//------
	//鍵導出（パスワード）
	PasswordRecipientInfo	cPassword;			//パスワード
	PBKDF2*					cPBKDF2;			//	= PBKDF2(&cHMAC);		//
	PWRI_KEK				cPWRI_KEK;			//

//--------------
//関数
			RecipientInfos(const char _strName[]="RecipientInfos");
			~RecipientInfos(void);
					
	//受信者情報の追加
	void	AddRecipientInfo(int type, Sequence* _recipientinfo);

	//鍵導出（パスワード）の追加
	void	AddRecipient(		string*				strPassword,
								OctetString*		CEK,
								HMAC*				hmac,
								unsigned int		count,
								unsigned int		mode);

};
