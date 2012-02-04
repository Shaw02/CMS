#include "StdAfx.h"
#include "PasswordRecipientInfo.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
PasswordRecipientInfo::PasswordRecipientInfo(const char _strName[]):
	Sequence(_strName),
	keyDerivationAlgorithm(0)
{
}
//==============================================================
//		�f�X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//	������
//				keyDerivation, keyEncryptionAlgorithm�͂����ŊJ������B
//==============================================================
PasswordRecipientInfo::~PasswordRecipientInfo(void)
{
	delete	keyDerivation;
	delete	keyEncryptionAlgorithm;
}
//==============================================================
//				�I�u�W�F�N�g�̐ݒ�
//--------------------------------------------------------------
//	������
//			AlgorithmIdentifier*	_keyDerivation	�����o�A���S���Y��
//			Encryption*				_keyEncryption	���Í����A���S���Y��
//	���Ԓl
//			����
//==============================================================
void	PasswordRecipientInfo::SetInfo(
			KeyDerivation*	_keyDerivation,
			Encryption*		_keyEncryption)
{

	//version CMSVersion,   -- Always set to 0
	version.Set(0);
	Set_Construct(&version);

	//keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier OPTIONAL,
	_keyDerivation->mode = _IMPLICIT;
	keyDerivation = _keyDerivation;
	keyDerivationAlgorithm.Set_Construct(keyDerivation);
	Set_Construct(&keyDerivationAlgorithm);

	//keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
	keyEncryptionAlgorithm = _keyEncryption;
	Set_Construct(keyEncryptionAlgorithm);

	//encryptedKey EncryptedKey }
	//SetKey()�֐��ŏ�������B
}
//==============================================================
//				Key Wrap & Set
//--------------------------------------------------------------
//	������
//			void*			ptPassword		�p�X�t���[�Y
//			unsigned	int	szPassword		�p�X�t���[�Y�̃T�C�Y
//			void*			Key				CEK
//			unsigned	int	szKey			CEK�̃T�C�Y
//	���Ԓl
//			void					
//==============================================================
void	PasswordRecipientInfo::SetKey(void* ptPassword, unsigned int szPassword, void* CEK, unsigned int szCEK)
{
	//�Í��� for ��
	unsigned	char*	KEK	= new unsigned char [keyEncryptionAlgorithm->szKey];
	unsigned	int		szECEK;

	//���Í������̓��o
	keyDerivation->calc(KEK, ptPassword, szPassword);

	//�Í���ɓ��o��������ݒ�
	keyEncryptionAlgorithm->Set_Key(KEK);

	//�R���e���c�Í����������Í������Ń��b�v
	szECEK = keyEncryptionAlgorithm->KeyWrap(CEK,szCEK);	//random

	//���b�v��������ASN.1 BER�ցB
	EncryptedKey.Set((char *)keyEncryptionAlgorithm->GetEncrptedKey(),szECEK);
	Set_Construct(&EncryptedKey);

	delete	KEK;
}
//==============================================================
//				Key Wrap & Set
//--------------------------------------------------------------
//	������
//			void*			ptPassword		�p�X�t���[�Y
//			unsigned	int	szPassword		�p�X�t���[�Y�̃T�C�Y
//			void*			Key				CEK
//			unsigned	int	szKey			CEK�̃T�C�Y
//	���Ԓl
//			void					
//==============================================================
int	PasswordRecipientInfo::GetKey(void* ptPassword, unsigned int szPassword, void* EK, unsigned int szEK)
{
	//�Í��� for ��
	unsigned	int		szKEK;
	unsigned	char*	KEK;
	unsigned	int		szCEK;

	//���Í������̓��o
	szKEK = keyEncryptionAlgorithm->szKey;
	KEK = new unsigned char [szKEK];
	keyDerivation->dkLen = szKEK;
	keyDerivation->calc(KEK, ptPassword, szPassword);

	//�Í���ɓ��o��������ݒ�
	keyEncryptionAlgorithm->Set_Key(KEK);

	//�R���e���c�Í����������Í������Ń��b�v
	szCEK = keyEncryptionAlgorithm->KeyUnWrap(EK,szEK);	//random

	delete	KEK;

	return(szCEK);
}