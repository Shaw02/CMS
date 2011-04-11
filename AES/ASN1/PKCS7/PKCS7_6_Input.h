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
			//"PKCS#7-6"の構造体	context[0]に持つ。
			EncryptedData			encrypted_data;

			//"EncryptedContentInfo"のmemberであるべきだが、
			//ポインターのみ保存されているので、こっちに情報をおいておく。

			//contentType ContentType,
			ObjectIdentifier		contentType;					//暗号文のType

			//contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier
			ObjectIdentifier		Algorithm;
			unsigned	int			szAlgorithm;
			unsigned	int			ptAlgorithm;
			unsigned	int			ptAlgorithmPara;

			//encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
			unsigned	int			ptEncryptedContent;
			unsigned	int			szEncryptedContent;


public:
	PKCS7_6_Input(const char*	strFileName);
	~PKCS7_6_Input(void);

	unsigned	int	Get_EncryptedData(void);
	void			StreamPointerMove_AlgorithmPara(void);
	void			StreamPointerMove_EncryptedContent(void);

};
