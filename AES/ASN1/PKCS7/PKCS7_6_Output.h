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
			//"PKCS#7-6"の構造体	context[0]に持つ。
			EncryptedData	encrypted_data;

//--------------
//関数
			PKCS7_6_Output(const char*	strFileName);
			~PKCS7_6_Output(void);

	void	Set_EncryptedData(	ObjectIdentifier*		_type,
								AlgorithmIdentifier*	_algorithm,
								unsigned int			_szContent
							);
	void	write_header(void);


};
