#include "StdAfx.h"
#include "RecipientInfos.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//		const char	_strName		�N���X��
//	���Ԓl
//				����
//==============================================================
RecipientInfos::RecipientInfos(const char _strName[]):
	Set(_strName)
{
}

//==============================================================
//		�f�X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
RecipientInfos::~RecipientInfos(void)
{
	Context*	_RecipientInfo;

	//Context�̊J��
	while(!RecipientInfo.empty()){
		_RecipientInfo = RecipientInfo.back();
		delete	_RecipientInfo;
		RecipientInfo.pop_back();
	}

}
//==============================================================
//		��M�ҏ��̒ǉ�
//--------------------------------------------------------------
//	������
//				int	type			��M�ҏ��i���Ǘ���@�j�̃^�C�v
//										[0]	���J���Í�
//										[1]	
//										[2]	
//										[3]	�����o�i�p�X���[�h�j
//										[4]	
//		Sequence*	_recipientinfo	��M�ҏ��
//	���Ԓl
//				����
//==============================================================
void	RecipientInfos::AddRecipientInfo(int type, Sequence* _recipientinfo)
{
	Context*	_RecipientInfo	=	new Context(type);

	if(type == 0){
		//Set�̂܂�
		Set_Construct(_recipientinfo);
	} else {
		//Context�ɂ���
		_recipientinfo->mode = _IMPLICIT;
		_RecipientInfo->Set_Construct(_recipientinfo);
		Set_Construct(_RecipientInfo);
		RecipientInfo.push_back(_RecipientInfo);
	}
}
//==============================================================
//			��M�ҏ��̒ǉ��i��M�҂́A�p�X���[�h�j
//--------------------------------------------------------------
//	������
//		string*				strPassword		�p�X���[�h
//		OctetString*		CEK				�R���e���c�p�Í���
//		HMAC*				hmac			PBKDF2�֐��ɐݒ肷��HMAC�֐�
//		unsigned	int		count			PBKDF2�֐��ɐݒ肷��J��Ԃ���
//		unsigned	int		mode			PWRI_KEK�Ŏg�p���錮�Í�
//	���Ԓl
//		�����B
//	������
//		�p�X���[�h���献�Í�����KEK�𓱏o���A�Z�b�V�����������b�v����B
//	�����l
//		�ȉ��̃A���S���Y�����g�p���܂��B
//		keyDerivationAlgorithm	�c	PBKDF2(hmac)
//		keyEncryptionAlgorithm	�c	PWRI_KEK(mode)
//==============================================================
void	RecipientInfos::AddRecipient(
			string*			strPassword,
			OctetString*	CEK,
			HMAC*			hmac,
			unsigned int	count,
			unsigned int	mode)
{
				//�����ŁA���Í��p��IV�ƁAPBKDF2�p�̃\���g�l�𐶐��B
				__m128i		_IV		= cRandom->get__m128i();	
				__int64		i64Salt	= cRandom->get_int64();

	//------------------
	//�����o

	//��keyDerivation�́A�N���X"PasswordRecipientInfo"�Ń������J�����s���B
	cPBKDF2	= new PBKDF2(hmac);

	cPBKDF2->Set_PBKDF2(&i64Salt,sizeof(i64Salt),count,CEK->strValue.size());
	cPWRI_KEK.Set_PWRI_KEK(mode, _IV);
	cPassword.SetInfo(cPBKDF2, &cPWRI_KEK);
	cPassword.SetKey((void *)strPassword->c_str(), strPassword->length(), (void *)CEK->strValue.c_str(), CEK->strValue.size());
	AddRecipientInfo(3,&cPassword);
}
