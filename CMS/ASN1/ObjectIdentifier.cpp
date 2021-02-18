#include "StdAfx.h"
#include "ObjectIdentifier.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
ObjectIdentifier::ObjectIdentifier(const char _strName[]):
	ASN1(_strName)
{
}
//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//			unsigned int i[]	OID
//			unsigned int n		OID�̃T�C�Y(�����������邩�H)
//	���Ԓl
//				����
//==============================================================
ObjectIdentifier::ObjectIdentifier(unsigned int i[], unsigned int n, const char _strName[]):
	ASN1(_strName)
{
	Set(i,n);
}
//==============================================================
//		�f�X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
ObjectIdentifier::~ObjectIdentifier(void)
{
}

//==============================================================
//		�a�d�q������
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
void	ObjectIdentifier::encodeBER()
{
	unsigned	int	iCount	= 2;
	string			oid;

	strBER.assign(1, iValue[0] * 40 + iValue[1]);

	while(iCount < iValue.size()){
		encodeBER_variable(iValue[iCount]);
		iCount++;
	}
	oid = strBER;	//�G���R�[�h�����f�[�^����U�������ɑޔ�

	encodeBER_TAG(BER_Class_General, false, BER_TAG_OBJECT_IDENTIFIER, oid.size());
	strBER += oid;
}
//==============================================================
//		�l��ݒ�
//--------------------------------------------------------------
//	������
//			unsigned int i[]	OID
//			size_t		 n		OID�̃T�C�Y(�����������邩�H)
//	���Ԓl
//			����
//==============================================================
void	ObjectIdentifier::Set(unsigned int i[], size_t n)
{
	size_t	count = 0;

	while(count < n){
		iValue.push_back(i[count]);
		count++;
	}
}
//==============================================================
//		�l��ݒ�
//--------------------------------------------------------------
//	������
//			unsigned int i[]	OID
//			unsigned int n		OID�̃T�C�Y(�����������邩�H)
//	���Ԓl
//			����
//==============================================================
void	ObjectIdentifier::SetVector(vector<unsigned int> i)
{
	unsigned	int	count = 0;

	while(count < i.size()){
		iValue.push_back(i[count]);
		count++;
	}
}
