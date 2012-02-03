#pragma once
#include "pkcs7_output.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class PKCS7_6_Output :
	public PKCS7_Output		//つまり、このクラスは"ContentInfo"から派生している孫クラス。
{
public:
//--------------
//変数
			//----------
			//"PKCS#7-6"の構造体	context[0]に持つ。
			EncryptedData			encrypted_data;
			Encryption*				cCE;				//暗号モジュール
			OctetString				CEK;				//暗号鍵（セッション鍵）

//--------------
//関数
			PKCS7_6_Output(	const char*				strFileName);
			~PKCS7_6_Output(void);

	void	Set_EncryptedData(	ObjectIdentifier*	_type,
								Encryption*			_algorithm,
								unsigned int		_szContent);

	void	Set_Encryption(		PKCS8_Input*		f_KEY);

	void	Set_Encryption(		PKCS8_Output*		f_KEY,
								unsigned int		mode);

	void	Set_Encryption(		string*				strPassword,
								unsigned int		mode);

	void	encrypt(			FileInput*			f_Plain,
								ObjectIdentifier*	contentType);
};
