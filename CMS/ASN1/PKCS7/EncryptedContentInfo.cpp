#include "StdAfx.h"
#include "EncryptedContentInfo.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
EncryptedContentInfo::EncryptedContentInfo(const char _strName[]):
	Sequence(_strName),
	encryptedContent(0)
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
EncryptedContentInfo::~EncryptedContentInfo(void)
{
}

//==============================================================
//				�I�u�W�F�N�g�̐ݒ�
//--------------------------------------------------------------
//	������
//			ObjectIdentifier*		_type		�Í����̃^�C�v
//			Encryption*				_algorithm	�Í��A���S���Y���iIV���Z�b�g���鎖�j
//			unsigned	int			_szContent	�Í����̃T�C�Y�i���̂͂Ƃ肠�����O���Ɂj
//	���Ԓl
//			����
//==============================================================
void	EncryptedContentInfo::Set(
			ObjectIdentifier*		_type,
			Encryption*				_algorithm,
			unsigned	int			_szContent)
{
	//contentType ContentType
	contentType	= _type;
	Set_Construct(contentType);

	//contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier
	contentEncryptionAlgorithm = _algorithm;
	Set_Construct(contentEncryptionAlgorithm);

	//encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
	encryptedContent.Set_ExternalDataSize(_szContent - (_szContent % _algorithm->szBlock) + _algorithm->szBlock);
	Set_Construct(&encryptedContent);

	szContent = _szContent;
}
//==============================================================
//				�Í�
//--------------------------------------------------------------
//	������
//			unsigned char*	CEK			�Í���
//			FileInput*		f_Plain		���̓t�@�C���i�����j
//			FileOutput*		f_Cipher	�o�̓t�@�C���i�Í����j
//	���Ԓl
//			int				0			����i���ꂵ���Ԃ��Ȃ����ǁc�j
//							-1			�ُ�
//	������
//			������O��ASN.1�f�[�^�́A���O�ɃG���R�[�h���ăt�@�C���ɏo�͂��Ă������B
//			����"f_Cipher"�ɂ́A��q�̓r���܂ŃG���R�[�h���ꂽ�t�@�C���I�u�W�F�N�g��n���B
//==============================================================
int		EncryptedContentInfo::encrypt(
			unsigned char*	CEK,
			FileInput*	f_Plain, 
			FileOutput*	f_Cipher)
{
	//�Í��p�̏����o�b�t�@
	union {
		unsigned	char	c[	(Encrypt_Buff)];
					__m128i	xmm[(Encrypt_Buff/sizeof(__m128i))];
	} static __declspec(align(16)) Buff;

	int		iPad;

	//------------------
	//���̐ݒ�
	contentEncryptionAlgorithm->Set_Key(CEK);

	//------------------
	//�Í�����
	do{
		//�������ׁ̈A������x�ǂݍ���ŁA��C�ɈÍ�����������B
		f_Plain->read((char *)Buff.c, Encrypt_Buff);

		if(szContent >= Encrypt_Buff){
			contentEncryptionAlgorithm->encipher((char *)Buff.c, Encrypt_Buff);
			f_Cipher->write((char *)Buff.c, Encrypt_Buff);
			szContent -= Encrypt_Buff;
		} else {
			iPad = contentEncryptionAlgorithm->encipher_last((char *)Buff.c, szContent);
			f_Cipher->write((char *)Buff.c, szContent + iPad);
			break;
		}

	} while(1);

	return(0);
}
//==============================================================
//				����
//--------------------------------------------------------------
//	������
//			unsigned char*	CEK			�Í���
//			FileInput*		f_Cipherf	���̓t�@�C���i�Í����j
//			FileOutput*		f_Plain		�o�̓t�@�C���i�����j
//			unsigned int	szContent	�T�C�Y
//	���Ԓl
//			int				0			����
//							-1			�ُ�
//	������
//			������O��ASN.1�f�[�^�́A���O�Ƀt�@�C��������͂��ăf�R�[�h���Ă������B
//			����"f_Cipher"�̃t�@�C���ǂݍ��݃|�C���^�[�́A�Í����{�̂̈ʒu�ɂ��鎖�B
//==============================================================
int		EncryptedContentInfo::decrypt(
			unsigned char*	CEK,
			FileInput*		f_Cipher,
			FileOutput*		f_Plain)
{
	//�Í��p�̏����o�b�t�@
	union {
		unsigned	char	c[	(Encrypt_Buff)];
					__m128i	xmm[(Encrypt_Buff/sizeof(__m128i))];
	} static __declspec(align(16)) Buff;

	int		iPad;

	//------------------
	//���̐ݒ�
	contentEncryptionAlgorithm->Set_Key(CEK);

	//------------------
	//��������
	do {
		//�������ׁ̈A������x�ǂݍ���ŁA��C�ɈÍ�����������B
		f_Cipher->read((char *)Buff.c, Encrypt_Buff);

		if(szContent > Encrypt_Buff){
			contentEncryptionAlgorithm->decipher((char *)Buff.c, Encrypt_Buff);
			f_Plain->write((char *)Buff.c, Encrypt_Buff);
			szContent -= Encrypt_Buff;
		} else {
			iPad = contentEncryptionAlgorithm->decipher_last((char *)Buff.c, szContent);
			if(iPad == -1){
				return(iPad);
			}
			//Padding�f�[�^�Ɋ�Â��ăt�@�C���o��
			f_Plain->write((char *)Buff.c, szContent - iPad);
			break;
		}
	} while(1);

	return(0);
}
