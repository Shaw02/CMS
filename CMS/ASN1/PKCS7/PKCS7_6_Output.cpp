#include "StdAfx.h"
#include "PKCS7_6_Output.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
PKCS7_6_Output::PKCS7_6_Output(const char*	strFileName):
	PKCS7_Output(strFileName)
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
PKCS7_6_Output::~PKCS7_6_Output(void)
{
}
//==============================================================
//				�I�u�W�F�N�g�̐ݒ�
//--------------------------------------------------------------
//	������
//			ObjectIdentifier*		_type		�Í����̃^�C�v
//			AlgorithmIdentifier*	_algorithm	�Í��A���S���Y��
//			unsigned	int			_szContent	�Í����̃T�C�Y�i���̂͂Ƃ肠�����O���Ɂj
//	���Ԓl
//			����
//	������
//			(1)	object "EncryptedData" ��ݒ肷��B
//			(2)	Context[0]�ɁA�ݒ肵��object "EncryptedData" ���i�[����B
//			(3) object "ContentInfo" �i��this class�j��ݒ肷��B
//==============================================================
void	PKCS7_6_Output::Set_EncryptedData(
			ObjectIdentifier*		_type,
			Encryption*				_algorithm, 
			unsigned	int			_szContent)
{
	//------
	//����
	encrypted_data.Set(_type, _algorithm, _szContent);
	context.Set_Construct(&encrypted_data);		//ContentInfo�N���X��member
	Set_Type(EncryptedData_type);
}
//==============================================================
//				�Í����W���[���ƁA�Í����̏���
//--------------------------------------------------------------
//	������
//			PKCS8_Output*		f_KEY			���t�@�C��
//			unsigned	int		mode			�g�p����R���e���c�Í�
//	���Ԓl
//			����
//	������
//			�Í����́A������萶���B
//			�Í����i*.Key�j�t�@�C���ɁA�Í�����ۑ�����B
//==============================================================
void	PKCS7_6_Output::Set_Encryption(
			PKCS8_Output*		f_KEY,
			unsigned	int		mode)
{
	unsigned	char*	_CEK;

	//------------------
	//�Í����W���[���̎擾
	cCE = Get_Encryption(mode);

	//------------------
	//���͗�����莩������
	_CEK	= new unsigned char [(cCE->szKey<32)?32:cCE->szKey];

	cRandom->get256(_CEK);
	CEK.Set((char *)_CEK, cCE->szKey);

	//����*.key�t�@�C���ɕۑ�
	f_KEY->Set(cCE, (char *)_CEK, cCE->szKey);
	f_KEY->encodeBER_to_File();

	delete	_CEK;

}
//==============================================================
//				�Í����W���[���ƁA�Í����̏���
//--------------------------------------------------------------
//	������
//			PKCS8_Input*		f_Key			�Í����iKey�t�@�C���j
//	���Ԓl
//			����
//	������
//			�Í����i*.Key�j�t�@�C�����A�Í����ɂ���B
//==============================================================
void	PKCS7_6_Output::Set_Encryption(
			PKCS8_Input*		f_KEY)
{
				__m128i	_IV	= cRandom->get__m128i();
	unsigned	char*	_CEK;

	//------------------
	//�Í����W���[���ƁA�Í����̏���

	//���t�@�C���ŁA���ƃA���S���Y�����w��H
	f_KEY->Get_PrivateKeyInfo();

	//�Í��A���S���Y�� �� �Í����p���[�h�́H
	//�ǉ��̈Í��A���S���Y��������ꍇ�́A�����ɒǉ��B
	if(cDES_CBC.Check_OID(&f_KEY->Algorithm) != -1){
		cDES_CBC.Set_DES(_IV.m128i_i64[0]);
		cCE = &cDES_CBC;
	} else if(cTDES_CBC.Check_OID(&f_KEY->Algorithm) != -1){
		cTDES_CBC.Set_DES(_IV.m128i_i64[0]);
		cCE = &cTDES_CBC;
	} else if(cAES_CBC128.Check_OID(&f_KEY->Algorithm) != -1){
		cAES_CBC128.Set_AES(_IV);
		cCE = &cAES_CBC128;
	} else if(cAES_CBC192.Check_OID(&f_KEY->Algorithm) != -1){
		cAES_CBC192.Set_AES(_IV);
		cCE = &cAES_CBC128;
	} else if(cAES_CBC256.Check_OID(&f_KEY->Algorithm) != -1){
		cAES_CBC256.Set_AES(_IV);
		cCE = &cAES_CBC256;
	} else {
		errPrint("",": Unknown encryption algorithm.");
	}

	//���擾
	_CEK	= new unsigned char [cCE->szKey];
	f_KEY->Get_PrivateKey(_CEK, cCE->szKey);
	CEK.Set((char *)_CEK, cCE->szKey);
	delete	_CEK;

}
//==============================================================
//				�Í���
//--------------------------------------------------------------
//	������
//			string*				strPassword		�p�X���[�h
//			unsigned	int		mode			�g�p����R���e���c�Í�
//	���Ԓl
//	������
//==============================================================
void	PKCS7_6_Output::Set_Encryption(
			string*				strPassword,
			unsigned	int		mode)
{
	unsigned	char*	_CEK;
	unsigned	int*	iCEK;
	unsigned	int		i = 0;
	unsigned	int		n;

	//------------------
	//�Í����W���[���̎擾
	cCE = Get_Encryption(mode);

	//------------------
	//Password������̃n�b�V���l���A�Í����ɂ���B
	_CEK	= new unsigned char [(cCE->szKey<32)?32:cCE->szKey];
	iCEK	= (unsigned	int*)_CEK;
	cSHA256.CalcHash(_CEK, (void *)strPassword->c_str(), strPassword->length());
	while(i<8){
		n = iCEK[i];
		iCEK[i] = ((n>>24) & 0xFF) | ((n>>8) & 0xFF00) | ((n & 0xFF00)<<8) | ((n & 0xFF)<<24);
		i++;
	}

	CEK.Set((char *)_CEK, cCE->szKey);
	delete	_CEK;

}
//==============================================================
//				�Í���
//--------------------------------------------------------------
//	������
//			FileInput*			f_Plain			�����t�@�C��
//			ObjectIdentifier*	_contentType	
//	���Ԓl
//	������
//			�Í���
//==============================================================
void	PKCS7_6_Output::encrypt(
			FileInput*			f_Plain,
			ObjectIdentifier*	contentType)
{

	//------------------
	//PKCS#7-6 �̃I�u�W�F�N�g�쐬
	Set_EncryptedData(contentType, cCE, f_Plain->GetSize());

	//------------------
	//�Í��t�@�C���̏o��

	//�Í����{�̂܂�
	write_header();

	//�Í����{��
	encrypted_data.encryptedContentInfo.encrypt((unsigned char*)CEK.strValue.c_str(), f_Plain, this);
}
