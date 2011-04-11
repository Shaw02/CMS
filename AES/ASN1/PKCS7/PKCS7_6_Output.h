#pragma once
#include "pkcs7_output.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class PKCS7_6_Output :
	public PKCS7_Output		//�܂�A���̃N���X��"ContentInfo"����h�����Ă��鑷�N���X�B
{
public:
//--------------
//�ϐ�
			//"PKCS#7-6"�̍\����	context[0]�Ɏ��B
			EncryptedData	encrypted_data;

//--------------
//�֐�
			PKCS7_6_Output(const char*	strFileName);
			~PKCS7_6_Output(void);

	void	Set_EncryptedData(	ObjectIdentifier*		_type,
								AlgorithmIdentifier*	_algorithm,
								unsigned int			_szContent
							);
	void	write_header(void);


};
