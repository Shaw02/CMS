#include "StdAfx.h"
#include "Context.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
Context::Context(unsigned int num, const char _strName[]):
	number(num),
	ASN1(_strName)
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
Context::~Context(void)
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
void	Context::encodeBER()
{
	unsigned	int		i		= 0;
//	unsigned	int		iSize	= 0;
	string				strContext;

	//�����̃f�[�^������ꍇ�B
	if((Constructed.size()>0 )&& ((strValue.size() > 0)||(szAddValue>0))){
		error(0);

	//�R���e���c���AASN.1�̏ꍇ�B	"SEQENCE"�Ɠ��������Ƃ���B
	} else if(Constructed.size() > 0){
		encodeBER_Constructed(BER_Class_Context, number);

	//�R���e���c���AASN.1�Ŗ����ꍇ�B
	} else if(strValue.size() > 0) {
		while(i < strValue.size()){
			strContext += strValue[i];
			i++;
		}
		encodeBER_TAG(BER_Class_Context, (strValue.size() == 1)? false : true, number, strContext.size());
		strBER += strContext;

	//�R���e���c��Object�O�f�[�^�̏ꍇ�B�i�^�O�����o�͂��Ă����B�j
	} else if(szAddValue>0){
		encodeBER_TAG(BER_Class_Context, false, number, szAddValue);
	}
}
//==============================================================
//		�l��ݒ�i�o�C�i���f�[�^�j
//--------------------------------------------------------------
//	������
//			ASN1* asn1		member�ƂȂ�object
//	���Ԓl
//			����
//==============================================================
void	Context::Set(string strData)
{
	strValue.push_back(strData);
}
