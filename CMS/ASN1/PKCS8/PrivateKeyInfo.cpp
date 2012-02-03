#include "StdAfx.h"
#include "PrivateKeyInfo.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
PrivateKeyInfo::PrivateKeyInfo(const char _strName[]):
	Sequence(_strName)
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
PrivateKeyInfo::~PrivateKeyInfo(void)
{
}
//==============================================================
//		�l��ݒ�
//--------------------------------------------------------------
//	������
//			ASN1* asn1		member�ƂȂ�object
//	���Ԓl
//			����
//==============================================================
void	PrivateKeyInfo::Set(
			AlgorithmIdentifier*	_algorithm,
						char		c[],
			unsigned	int			iSize)
{
	//version                   Version,
	version.Set(0);
	Set_Construct(&version);

	//privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
	privateKeyAlgorithm = _algorithm;
	Set_Construct(privateKeyAlgorithm);

	//privateKey                PrivateKey,
	privateKey.Set(c, iSize);
	Set_Construct(&privateKey);

	//attributes           [0]  IMPLICIT Attributes OPTIONAL }


}