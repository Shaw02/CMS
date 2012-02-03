#pragma once
#include "PKCS7_Input.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class PKCS7_3_Input :
	public PKCS7_Input
{
public:
//--------------
//�ϐ�
			//----------
			//"PKCS#7-3"�̍\����	context[0]�Ɏ��B
			EnvelopedData			enveloped_data;
		//	Encryption*				cCE;				//�Í����W���[��
			OctetString				CEK;				//�Í����i�Z�b�V�������j

			//encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
			unsigned	int			ptEncryptedContent;
		//	unsigned	int			szEncryptedContent;

//--------------
//�֐�
public:
	PKCS7_3_Input(const char*	strFileName);
	~PKCS7_3_Input(void);

	void	Get_EnvelopedData();

//	void			StreamPointerMove_AlgorithmPara(void);
//	void			StreamPointerMove_EncryptedContent(void);

	void	decrypt(			FileOutput*			f_Plain);
};
