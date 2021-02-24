#pragma once
#include "..\Sequence.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
#define		EnvelopedData_cmsVersion	0
#define		EnvelopedData_type			3

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class EnvelopedData :
	public Sequence
{
public:
//--------------
//�ϐ�
/*
EnvelopedData ::= SEQUENCE {
  version CMSVersion,
  originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
  recipientInfos RecipientInfos,
  encryptedContentInfo EncryptedContentInfo,
  unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
*/
	Integer					version;					//cmsVersion
	Context					originatorInfo;
	RecipientInfos			recipientInfos;				//"SET"����h������B
	EncryptedContentInfo	encryptedContentInfo;
	Context					unprotectedAttrs;			//�b��

//--------------
//�֐�
						EnvelopedData(const char _strName[]="EnvelopedData");
						~EnvelopedData(void);

				void	Set(
							ObjectIdentifier*		_type,
							Encryption*				_algorithm,
							size_t					_szContent);
};
