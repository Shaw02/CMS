#include "StdAfx.h"
#include "EnvelopedData.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
EnvelopedData::EnvelopedData(const char _strName[]):
	Sequence(_strName),
	originatorInfo(0),
	unprotectedAttrs(1)
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
EnvelopedData::~EnvelopedData(void)
{
}
//==============================================================
//				�I�u�W�F�N�g�̐ݒ�
//--------------------------------------------------------------
//	������
//			ObjectIdentifier*		_type			�Í����̃^�C�v
//			Encryption*				_algorithm		�Í��A���S���Y��
//			size_t					_szContent		�Í����̃T�C�Y�i���̂͂Ƃ肠�����O���Ɂj
//	���Ԓl
//			����
//	������
//			���̊֐����ĂԑO�ɁA��M�ҏ��i_recipientinfo�j��ݒ肷�鎖
//==============================================================
void	EnvelopedData::Set(
			ObjectIdentifier*		_type,
			Encryption*				_algorithm, 
			size_t					_szContent)
{
	unsigned	int	iVersion;

	//------
	//version CMSVersion
//	if(originatorInfo.Constructed.size()>0){
		// or "pwri" or "ori" or ATTRv3 
		iVersion = 3;
//	} else {
//		if((originatorInfo.Constructed.size()==0) && (unprotectedAttrs.Constructed.size()==0)){
//			//recipientInfos.version == 0
//			iVersion = 0;
//		} else {
//			iVersion = 2;
//		}
//	}
	version.Set(iVersion);
	Set_Construct(&version);

	//------
	//originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
	if(originatorInfo.Constructed.size() > 0){
		Set_Construct(&originatorInfo);
	}

	//------
	//recipientInfos RecipientInfos,
	Set_Construct(&recipientInfos);

	//------
	//encryptedContentInfo EncryptedContentInfo
	encryptedContentInfo.Set(_type, _algorithm, _szContent);
	Set_Construct(&encryptedContentInfo);

	//------
	//unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
	if(unprotectedAttrs.Constructed.size() > 0){
		//	to do	������������ꍇ�̏����B
		Set_Construct(&unprotectedAttrs);
	}
}
