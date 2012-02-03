#pragma once
#include "PKCS7_Input.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class PKCS7_3_Input :
	public PKCS7_Input
{
public:
//--------------
//変数
			//----------
			//"PKCS#7-3"の構造体	context[0]に持つ。
			EnvelopedData			enveloped_data;
		//	Encryption*				cCE;				//暗号モジュール
			OctetString				CEK;				//暗号鍵（セッション鍵）

			//encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
			unsigned	int			ptEncryptedContent;
		//	unsigned	int			szEncryptedContent;

//--------------
//関数
public:
	PKCS7_3_Input(const char*	strFileName);
	~PKCS7_3_Input(void);

	void	Get_EnvelopedData();

//	void			StreamPointerMove_AlgorithmPara(void);
//	void			StreamPointerMove_EncryptedContent(void);

	void	decrypt(			FileOutput*			f_Plain);
};
