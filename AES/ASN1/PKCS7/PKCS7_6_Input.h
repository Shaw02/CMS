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
			//"PKCS#7-6"�̍\����	context[0]�Ɏ��B
			EncryptedData			encrypted_data;

			//"EncryptedContentInfo"��member�ł���ׂ������A
			//�|�C���^�[�̂ݕۑ�����Ă���̂ŁA�������ɏ��������Ă����B

			//contentType ContentType,
			ObjectIdentifier		contentType;					//�Í�����Type

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
