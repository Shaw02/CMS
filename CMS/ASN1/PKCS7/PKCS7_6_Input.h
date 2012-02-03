#pragma once
#include "PKCS7_Input.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class PKCS7_6_Input :
	public PKCS7_Input
{
public:
//--------------
//変数
			//----------
			//"PKCS#7-6"の構造体	context[0]に持つ。
			EncryptedData			encrypted_data;
		//	Encryption*				cCE;				//暗号モジュール
			OctetString				CEK;				//暗号鍵（セッション鍵）

			//encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
			unsigned	int			ptEncryptedContent;
		//	unsigned	int			szEncryptedContent;

//--------------
//関数
public:
	PKCS7_6_Input(const char*	strFileName);
	~PKCS7_6_Input(void);

	void	Get_EncryptedData();

	void	Set_Encryption(		PKCS8_Input*		f_KEY);
	void	Set_Encryption(		string*				strPassword);

	void	decrypt(			FileOutput*			f_Plain);
};
