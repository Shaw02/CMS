#include "StdAfx.h"
#include "PKCS7_Input.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
PKCS7_Input::PKCS7_Input(const char*	strFileName,const char _strName[]):
	BER_Input(strFileName),
	PKCS7(_strName)
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
PKCS7_Input::~PKCS7_Input(void)
{
}
//==============================================================
//		�w�b�_�[�\���`�F�b�N
//--------------------------------------------------------------
//	������
//			unsigned	char	cType	�R���e���c�^�C�v
//	���Ԓl
//			unsigned	int				�R���e���c�̃T�C�Y
//==============================================================
unsigned int	PKCS7_Input::read_ContentInfo(unsigned int type)
{
	static	unsigned	int		oid_pkcs7[]	=	{1,2,840,113549,1,7,type};

	//SEQUENCE
	read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);

		//OID
		read_Object_Identifier_with_Check(&contentType, oid_pkcs7, sizeof(oid_pkcs7)/sizeof(int));

		//Content Info
		szAddValue = read_TAG_with_Check(BER_Class_Context, true, 0);

	return(szAddValue);
}
//==============================================================
//		�y�t�@�C���ǂݍ��݁zEnvelopedData
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			unsigned	int					�Í����̃|�C���^
//==============================================================
unsigned	int	PKCS7_Input::read_EnvelopedData(EnvelopedData* _envelopedData)
{
	unsigned	int	ptEncryptedContent;

	//EnvelopedData
	read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);

		//version
		read_Integer(&_envelopedData->version);
		if(_envelopedData->version.iValue != 3){
			error(0);	//���Ή���Version
		}
		_envelopedData->Set_Construct(&_envelopedData->version);

		//originatorInfo
		

		//recipientInfos
		read_RecipientInfos(&_envelopedData->recipientInfos);

		//encryptedContentInfo
		ptEncryptedContent = read_EncryptedContentInfo(&_envelopedData->encryptedContentInfo);
		//�Í����W���[���̃|�C���^���擾���Ă����B
	//	cCE = _envelopedData->encryptedContentInfo.contentEncryptionAlgorithm;

	//------
	//����
	context.Set_Construct(_envelopedData);		//ContentInfo�N���X��member

	return(ptEncryptedContent);
}
//==============================================================
//		�w�b�_�[�\���`�F�b�N
//--------------------------------------------------------------
//	������
//			
//	���Ԓl
//			unsigned	int					�Í����̃|�C���^
//==============================================================
unsigned	int	PKCS7_Input::read_EncryptedData(EncryptedData* _encryptedData)
{
	unsigned	int	ptEncryptedContent;

	//EncryptedData
	read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);

		//version
		read_Integer(&_encryptedData->version);
		if(_encryptedData->version.iValue != 0){
			error(0);	//���Ή���Version
		}
		_encryptedData->Set_Construct(&_encryptedData->version);

		//encryptedContentInfo
		ptEncryptedContent = read_EncryptedContentInfo(&_encryptedData->encryptedContentInfo);
		//�Í����W���[���̃|�C���^���擾���Ă����B
	//	cCE = _encryptedData->encryptedContentInfo.contentEncryptionAlgorithm;

	//------
	//����
	context.Set_Construct(_encryptedData);		//ContentInfo�N���X��member

	return(ptEncryptedContent);
}
//==============================================================
//		�y�t�@�C���ǂݍ��݁zRecipientInfos
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//==============================================================
void	PKCS7_Input::read_RecipientInfos(RecipientInfos* _recipientInfos)
{
	unsigned	int		ptTemp;				//�t�@�C���|�C���^�ꎟ�ۑ��p

	unsigned	int		read_tag;			//ASN.1 �^�O
	unsigned	char	read_class;			//ASN.1 �N���X
				bool	read_fStruct;		//ASN.1 �\����
	unsigned	int		iSize;				//ASN.1 �T�C�Y

	//----------
	//"SET RecipientInfo"�łȂ��Ȃ�܂ŌJ��Ԃ��B
	while(1){
		//���݂̃t�@�C���|�C���^���擾
		ptTemp = tellg();

		//RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
		iSize = read_TAG(&read_class, &read_fStruct, &read_tag);
		//SET�łȂ�������A�|�C���^�[��߂��ďI��
		if((read_class != BER_Class_General)||(read_tag != BER_TAG_SET)||(read_fStruct != true)){
			StreamPointerMove(ptTemp);
			break;
		}
		
		//RecipientInfo ::= CHOICE {
		iSize = read_TAG(&read_class, &read_fStruct, &read_tag);
		switch(read_class){
			//[SEQUENCE]	ktri KeyTransRecipientInfo
			case(BER_Class_General):
			//	Get_KeyTransRecipientInfo();
				StreamPointerAdd(iSize);
				break;
			//[CONTEXT]		
			case(BER_Class_Context):
				switch(read_tag){
					//pwri [3] PasswordRecipientinfo
					case(3):
						read_PasswordRecipientInfo(&_recipientInfos->cPassword);
						break;
					default:
						StreamPointerAdd(iSize);
						break;
				}
				break;
			default:
				errPrint("RecipientInfos",": ���Ή�");
				break;
		}
	}
}

//==============================================================
//		�y�t�@�C���ǂݍ��݁zPasswordRecipientinfo
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//==============================================================
void	PKCS7_Input::read_PasswordRecipientInfo(PasswordRecipientInfo* _passwordRecipientInfo)
{
	KeyDerivation*			_keyDerivation;
	Encryption*				_keyEncryption;

	//version CMSVersion,   -- Always set to 0
	read_Integer(&_passwordRecipientInfo->version);
	if(_passwordRecipientInfo->version.iValue != 0){
		errPrint("PasswordRecipientinfo",": ���Ή���Version");
	}

	//keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier OPTIONAL,
	_keyDerivation = read_KeyDerivationAlgorithm();

	//keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
	read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);

		//�� to do

	_passwordRecipientInfo->SetInfo(_keyDerivation, _keyEncryption);

	//encryptedKey EncryptedKey }
	read_Octet_Strings(&_passwordRecipientInfo->EncryptedKey);
}

//==============================================================
//		�y�t�@�C���ǂݍ��݁zEncryptedContentInfo
//--------------------------------------------------------------
//	������
//			EncryptedContentInfo*	ECinfo	�ǂݍ��ݓ��e���i�[����I�u�W�F�N�g�̃|�C���^
//	���Ԓl
//			unsigned	int					�Í����̃|�C���^
//==============================================================
unsigned	int		PKCS7_Input::read_EncryptedContentInfo(EncryptedContentInfo*	ECinfo)
{
	//contentType ContentType,
	ObjectIdentifier		contentType;					//�Í�����Type
	Encryption*				cCE;
	unsigned	int			szEncryptedContent;

	//encryptedContentInfo
	read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);

		//contentType 
		read_Object_Identifier(&contentType);

		//contentEncryptionAlgorithm
		cCE = read_ContentEncryptionAlgorithm();

		//�����ɓ����Ă���̂��A�Í������̂̃T�C�Y
		szEncryptedContent	= read_TAG_with_Check(BER_Class_Context, false, 0);

	//EncryptedContentInfo��ݒ�
	ECinfo->Set(&contentType, cCE, szEncryptedContent);
	return(tellg());
}
//==============================================================
//		�y�t�@�C���ǂݍ��݁z�R���e���c�p�Í����W���[���̎擾
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			Encryption*				�Í����W���[���̃|�C���^
//==============================================================
Encryption*	PKCS7_Input::read_ContentEncryptionAlgorithm()
{
	//contentType ContentType,
	ObjectIdentifier		oid_algCE;

	OctetString		_IV;
	__m128i			IV;

	Encryption*	cCE;

	//EncryptionAlgorithm
	//SEQUENCE
	read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);
		//algorithm OBJECT IDENTIFIER
		read_Object_Identifier(&oid_algCE);
		//�Í����p���[�h, �������x�N�^IV ���A�ݒ�
		//�ǉ��̈Í��A���S���Y��������ꍇ�́A�����ɒǉ��B
		if(cDES_CBC.Check_OID(&oid_algCE) != -1){
			read_Octet_Strings(&_IV);
			memcpy(&IV, _IV.strValue.c_str(), sizeof(__int64));
			cDES_CBC.Set_DES(IV.m128i_i64[0]);
			cCE = &cDES_CBC;
		} else if(cTDES_CBC.Check_OID(&oid_algCE) != -1){
			read_Octet_Strings(&_IV);
			memcpy(&IV, _IV.strValue.c_str(), sizeof(__int64));
			cTDES_CBC.Set_DES(IV.m128i_i64[0]);
			cCE = &cTDES_CBC;
		} else if(cAES_CBC128.Check_OID(&oid_algCE) != -1){
			read_Octet_Strings(&_IV);
			memcpy(&IV, _IV.strValue.c_str(), sizeof(__m128i));
			cAES_CBC128.Set_AES(IV);
			cCE = &cAES_CBC128;
		} else if(cAES_CBC192.Check_OID(&oid_algCE) != -1){
			read_Octet_Strings(&_IV);
			memcpy(&IV, _IV.strValue.c_str(), sizeof(__m128i));
			cAES_CBC192.Set_AES(IV);
			cCE = &cAES_CBC192;
		} else if(cAES_CBC256.Check_OID(&oid_algCE) != -1){
			read_Octet_Strings(&_IV);
			memcpy(&IV, _IV.strValue.c_str(), sizeof(__m128i));
			cAES_CBC256.Set_AES(IV);
			cCE = &cAES_CBC256;
		} else {
			errPrint("contentEncryptionAlgorithm",": Unknown encryption algorithm.");
		}

		if(cCE->szBlock != _IV.strValue.size()){
			errPrint("contentEncryptionAlgorithm",": Different Parameter size.");
		}

	return(cCE);
}
//==============================================================
//		�y�t�@�C���ǂݍ��݁z�n�b�V���֐��̎擾
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			HMAC*				�n�b�V���֐��̃|�C���^
//==============================================================
HMAC*	PKCS7_Input::read_HmacAlgorithm()
{
	//contentType ContentType,
	ObjectIdentifier		_oid;

	HMAC*					cHMAC;

	//HMAC Algorithm
	//SEQUENCE
	read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);
		//algorithm OBJECT IDENTIFIER
		read_Object_Identifier(&_oid);
		if(cHMAC_SHA1.Check_OID(&_oid) != -1){
			cHMAC = &cHMAC_SHA1;
			read_TAG_with_Check(BER_Class_General, false, BER_TAG_NULL);
		} else if(cHMAC_SHA224.Check_OID(&_oid) != -1){
			cHMAC = &cHMAC_SHA224;
			read_TAG_with_Check(BER_Class_General, false, BER_TAG_NULL);
		} else if(cHMAC_SHA256.Check_OID(&_oid) != -1){
			cHMAC = &cHMAC_SHA256;
			read_TAG_with_Check(BER_Class_General, false, BER_TAG_NULL);
		} else {
			errPrint("HmacAlgorithm",": Unknown HMAC algorithm.");
		}

	return(cHMAC);
}
//==============================================================
//		�y�t�@�C���ǂݍ��݁z�����o�֐��̎擾
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			HMAC*				�����o�֐��̃|�C���^
//==============================================================
KeyDerivation*		PKCS7_Input::read_KeyDerivationAlgorithm()
{
	unsigned	int		ptTemp;				//�t�@�C���|�C���^�ꎟ�ۑ��p

	unsigned	int		read_tag;			//ASN.1 �^�O
	unsigned	char	read_class;			//ASN.1 �N���X
				bool	read_fStruct;		//ASN.1 �\����
	unsigned	int		iSize;				//ASN.1 �T�C�Y

	static	PBKDF2	_pbkdf2	=	PBKDF2(&cHMAC_SHA256);
	PBKDF2*					_pbkdf;
	HMAC*					cHMAC;

	//contentType ContentType,
	ObjectIdentifier		_oid;

	//��keyDerivation�́A�N���X"PasswordRecipientInfo"�Ń������J�����s���B
	KeyDerivation*			_keyDerivation;

	OctetString	_Salt;
	Integer		_Count;
	Integer		_dkLen;

	read_TAG_with_Check(BER_Class_Context, true, 0);
		//algorithm OBJECT IDENTIFIER
		read_Object_Identifier(&_oid);
		if(_pbkdf2.Check_OID(&_oid) != -1){
			//PBKDF2-params ::= SEQUENCE {
			read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);
				//salt	pecified OCTET STRING
				read_Octet_Strings(&_Salt);
				//iterationCount INTEGER (1..MAX)
				read_Integer(&_Count);
				//keyLength INTEGER (1..MAX) OPTIONAL
				ptTemp = tellg();
				iSize = read_TAG(&read_class, &read_fStruct, &read_tag);
				StreamPointerMove(ptTemp);
				if((read_class == BER_Class_General)&&(read_tag == BER_TAG_INTEGER)&&(read_fStruct == false)){
					read_Integer(&_dkLen);
				} else {
					_dkLen.Set(0);
				}
				//prf AlgorithmIdentifier {{PBKDF2-PRFs}}
				ptTemp = tellg();
				iSize = read_TAG(&read_class, &read_fStruct, &read_tag);
				StreamPointerMove(ptTemp);
				if((read_class != BER_Class_General)||(read_tag != BER_TAG_SEQUENCE)||(read_fStruct != true)){
					//DEFAULT algid-hmacWithSHA1
					cHMAC = &cHMAC_SHA1;
				} else {
					cHMAC = read_HmacAlgorithm();
				}
			_pbkdf = new PBKDF2(cHMAC);
			//�� to do �������s���ȏꍇ���l������B
			_pbkdf->Set_PBKDF2((void *)_Salt.strValue.c_str(), _Salt.strValue.size(), _Count.iValue, _dkLen.iValue);
		} else {
			errPrint("KeyDerivationAlgorithm",": Unknown KeyDerivationAlgorithm algorithm.");
		}
	return(_keyDerivation);
}
