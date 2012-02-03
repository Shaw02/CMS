#pragma once
#include "pkcs7_output.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class PKCS7_3_Output :
	public PKCS7_Output		//�܂�A���̃N���X��"ContentInfo"����h�����Ă��鑷�N���X�B
{
public:
//--------------
//�ϐ�
			//----------
			//"PKCS#7-3"�̍\����	context[0]�Ɏ��B
			EnvelopedData			enveloped_data;		//
			Encryption*				cCE;				//�Í����W���[��
			OctetString				CEK;				//�Í����i�Z�b�V�������j

//--------------
//�֐�
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
