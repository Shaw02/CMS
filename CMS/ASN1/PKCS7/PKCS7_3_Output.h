#pragma once
#include "pkcs7_output.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class PKCS7_3_Output :
	public PKCS7_Output		//つまり、このクラスは"ContentInfo"から派生している孫クラス。
{
public:
//--------------
//変数
			//----------
			//"PKCS#7-3"の構造体	context[0]に持つ。
			EnvelopedData			enveloped_data;		//
			Encryption*				cCE;				//暗号モジュール
			OctetString				CEK;				//暗号鍵（セッション鍵）

//--------------
//関数
			PKCS7_3_Output(	const char*				strFileName);
			~PKCS7_3_Output(void);

	void	Set_EnvelopedData(	ObjectIdentifier*	_type,
								Encryption*			_algorithm,
								unsigned int		_szContent);

	void	MakeEncryption(		unsigned int		mode);

	void	AddRecipient(		string*				strPassword,
								unsigned int		count,
								unsigned int		mode);

	void	encrypt(			FileInput*			f_Plain,
								ObjectIdentifier*	contentType);

};
