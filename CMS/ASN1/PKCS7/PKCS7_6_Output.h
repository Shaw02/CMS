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
			//----------
			//"PKCS#7-6"�̍\����	context[0]�Ɏ��B
			EncryptedData			encrypted_data;
			Encryption*				cCE;				//�Í����W���[��
			OctetString				CEK;				//�Í����i�Z�b�V�������j

//--------------
//�֐�
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
