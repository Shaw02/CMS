#pragma once
#include "..\Sequence.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
#define		EncryptedData_cmsVersion	0
#define		EncryptedData_type			6

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class EncryptedData :
	public Sequence
{
public:
//--------------
//変数
/*
EncryptedData ::= SEQUENCE {
  version CMSVersion,
  encryptedContentInfo EncryptedContentInfo,
  unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
*/
	Integer					version;					//cmsVersion
	EncryptedContentInfo	encryptedContentInfo;
	Sequence				unprotectedAttrs;			//暫定

//--------------
//関数
						EncryptedData(const char _strName[]="EncryptedData");
						~EncryptedData(void);

				void	Set(ObjectIdentifier*		_type,
							Encryption*				_algorithm,
							size_t					_szContent);
};
