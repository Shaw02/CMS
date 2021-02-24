#pragma once
#include "..\Sequence.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
#define		EncryptedData_cmsVersion	0
#define		EncryptedData_type			6

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class EncryptedData :
	public Sequence
{
public:
//--------------
//�ϐ�
/*
EncryptedData ::= SEQUENCE {
  version CMSVersion,
  encryptedContentInfo EncryptedContentInfo,
  unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
*/
	Integer					version;					//cmsVersion
	EncryptedContentInfo	encryptedContentInfo;
	Sequence				unprotectedAttrs;			//�b��

//--------------
//�֐�
						EncryptedData(const char _strName[]="EncryptedData");
						~EncryptedData(void);

				void	Set(ObjectIdentifier*		_type,
							Encryption*				_algorithm,
							size_t					_szContent);
};
