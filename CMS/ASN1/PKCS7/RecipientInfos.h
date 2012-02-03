#pragma once
#include "..\Set.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class RecipientInfos :
	public Set
{
public:
//--------------
//�ϐ�
/*
RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
*/
	//Context��ASN.1�I�u�W�F�N�g�����̂ŁA���̃|�C���^�[��ۑ����Ă����B
	vector<Context*>	RecipientInfo;

	//------
	//���z��
//	vector<>				;		//�e��M�ҏ��

	//------
	//�����o�i�p�X���[�h�j
	PasswordRecipientInfo	cPassword;			//�p�X���[�h
	PBKDF2*					cPBKDF2;			//	= PBKDF2(&cHMAC);		//
	PWRI_KEK				cPWRI_KEK;			//

//--------------
//�֐�
			RecipientInfos(const char _strName[]="RecipientInfos");
			~RecipientInfos(void);
					
	//��M�ҏ��̒ǉ�
	void	AddRecipientInfo(int type, Sequence* _recipientinfo);

	//�����o�i�p�X���[�h�j�̒ǉ�
	void	AddRecipient(		string*				strPassword,
								OctetString*		CEK,
								HMAC*				hmac,
								unsigned int		count,
								unsigned int		mode);

};
