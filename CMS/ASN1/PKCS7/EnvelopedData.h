#pragma once
#include "..\Sequence.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
#define		EnvelopedData_cmsVersion	0
#define		EnvelopedData_type			3

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class EnvelopedData :
	public Sequence
{
public:
//--------------
//変数
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
	RecipientInfos			recipientInfos;				//"SET"から派生する。
	EncryptedContentInfo	encryptedContentInfo;
	Context					unprotectedAttrs;			//暫定

//--------------
//関数
						EnvelopedData(const char _strName[]="EnvelopedData");
						~EnvelopedData(void);

				void	Set(
							ObjectIdentifier*		_type,
							Encryption*				_algorithm,
							size_t					_szContent);
};
