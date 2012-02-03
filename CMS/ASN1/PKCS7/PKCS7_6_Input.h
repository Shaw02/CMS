#pragma once
#include "PKCS7_Input.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class PKCS7_6_Input :
	public PKCS7_Input
{
public:
//--------------
//�ϐ�
			//----------
			//"PKCS#7-6"�̍\����	context[0]�Ɏ��B
			EncryptedData			encrypted_data;
		//	Encryption*				cCE;				//�Í����W���[��
			OctetString				CEK;				//�Í����i�Z�b�V�������j

			//encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
			unsigned	int			ptEncryptedContent;
		//	unsigned	int			szEncryptedContent;

//--------------
//�֐�
public:
	PKCS7_6_Input(const char*	strFileName);
	~PKCS7_6_Input(void);

	void	Get_EncryptedData();

	void	Set_Encryption(		PKCS8_Input*		f_KEY);
	void	Set_Encryption(		string*				strPassword);

	void	decrypt(			FileOutput*			f_Plain);
};
