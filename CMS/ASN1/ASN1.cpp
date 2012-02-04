#include "StdAfx.h"
#include "ASN1.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
ASN1::ASN1(const char _strName[]):
	strName(_strName),
	szAddValue(0),
	mode(_EXPLICIT)
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
ASN1::~ASN1(void)
{
	Clear_Construct();
}
//==============================================================
//		ASN.1�I�u�W�F�N�g�̒ǉ�
//--------------------------------------------------------------
//	������
//			ASN1* asn1		�ǉ�����ASN.1�I�u�W�F�N�g
//	���Ԓl
//			����
//==============================================================
void	ASN1::Set_Construct(ASN1* asn1)
{
	Constructed.push_back(asn1);
}

//==============================================================
//		ASN.1�I�u�W�F�N�g�̑S�폜
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//==============================================================
void	ASN1::Clear_Construct()
{
	Constructed.clear();
}

//==============================================================
//		�O���f�[�^�T�C�Y�̐ݒ�
//--------------------------------------------------------------
//	������
//			unsigned int	iSize	�O���f�[�^�̃T�C�Y
//	���Ԓl
//			����
//==============================================================
void	ASN1::Set_ExternalDataSize(unsigned int iSize)
{
	szAddValue = iSize;
}
//==============================================================
//		�G���[����
//--------------------------------------------------------------
//	������
//				unsigned int iEer	�G���[�R�[�h
//	���Ԓl
//				����
//==============================================================
void	ASN1::error(unsigned int iEer)
{
	static	const	char*	const	msg_err[2]={
		"Context include ASN.1 and Binary.",					//0x00: Context�ɁAASN.1��BIN����������B
		"Part of the constructed data include external data."	//0x01: �\�����f�[�^�̓r���ɁA�O���f�[�^������B
	};
	errPrint("ASN.1 BER Encode Error :", msg_err[iEer]);
}

//==============================================================
//			�y�a�d�q�G���R�[�h�z�^�O���T�C�Y
//--------------------------------------------------------------
//	������
//		unsigned	char	cClass	�N���X
//					bool	fStruct	�\�����t���O
//		unsigned	int		iTag	�^�ONo.
//		unsigned	int		iSize	�f�[�^�T�C�Y
//	���Ԓl
//			����
//==============================================================
void	ASN1::encodeBER_TAG(unsigned char cClass, bool fStruct,unsigned int iTag, unsigned int iSize)
{
	const	unsigned	char	cTag = ((fStruct&0x01)<<5) | (cClass<<6);

	if(mode != _IMPLICIT){
		if(iTag <= 30){
			strBER.assign(1,cTag | iTag);
		} else {
			strBER.assign(1,cTag | 31);
			encodeBER_variable(iTag);
		}
		encodeBER_size(iSize);
	}
}
//==============================================================
//			�y�a�d�q�G���R�[�h�z�T�C�Y
//--------------------------------------------------------------
//	������
//		unsigned int iSize		�l	�i��32bit�l�܂ł̂ݑΉ��j
//	���Ԓl
//			����
//==============================================================
void	ASN1::encodeBER_size(unsigned int iSize)
{
	if(iSize < (1<<7)){			//0�`127
		strBER.append(1,iSize & 0x7F);
	} else if(iSize < (1<<8)) {	//128�`256
		strBER.append(1,0x81);
		strBER.append(1,iSize & 0xFF);
	} else if(iSize < (1<<16)) {	//256�`65535,	
		strBER.append(1,0x82);
		strBER.append(1,((iSize>>8) & 0xFF));
		strBER.append(1,(iSize & 0xFF));
	} else if(iSize < (1<<24)) {	//
		strBER.append(1,0x83);
		strBER.append(1,((iSize>>16) & 0xFF));
		strBER.append(1,((iSize>>8) & 0xFF));
		strBER.append(1,(iSize & 0xFF));
	} else {
		strBER.append(1,0x84);
		strBER.append(1,((iSize>>24) & 0xFF));
		strBER.append(1,((iSize>>16) & 0xFF));
		strBER.append(1,((iSize>>8) & 0xFF));
		strBER.append(1,(iSize & 0xFF));
	}
}
//==============================================================
//			�y�a�d�q�G���R�[�h�z�����l
//--------------------------------------------------------------
//	������
//		int		_i		�l	�i��32bit�l�܂ł̂ݑΉ��j
//	���Ԓl
//			����
//==============================================================
void	ASN1::encodeBER_int(int _i)
{
	if((_i < 64) && (_i >= -64)){		//-64�`63
		strBER.append(1,_i & 0x7F);
	} else if((_i < 128) && (_i >= -128)) {	//-128�`127
		strBER.append(1,_i & 0xFF);
	} else if((_i < 32768) && (_i >= -32768)) {	//128�`32767,	
		strBER.append(1,(_i>> 8) & 0xFF);
		strBER.append(1,_i & 0xFF);
	} else if((_i < 8388608) && (_i >= -8388608)) {
		strBER.append(1,(_i>>16) & 0xFF);
		strBER.append(1,(_i>> 8) & 0xFF);
		strBER.append(1,_i & 0xFF);
	} else {
		strBER.append(1,(_i>>24) & 0xFF);
		strBER.append(1,(_i>>16) & 0xFF);
		strBER.append(1,(_i>> 8) & 0xFF);
		strBER.append(1,_i & 0xFF);
	}
}
//==============================================================
//			�y�a�d�q�G���R�[�h�z�ϒ��l
//--------------------------------------------------------------
//	������
//		unsigned int	_i		�l	�i��32bit�l�܂ł̂ݑΉ��j
//	���Ԓl
//			����
//==============================================================
void	ASN1::encodeBER_variable(unsigned int _i)
{
	unsigned	int		count=0;		//�ǂݍ��݉񐔃J�E���g�p
				char	cData[9];

	//----------------------------------
	//���ϒ��G���R�[�h
	do{
		cData[count] = _i & 0x7F;
		_i>>=7;
		count++;
	} while((count<9) && (_i > 0));

	//���ϒ��o��
	do{
		count--;
		strBER.append(1,cData[count] | ((count==0)? 0 : 0x80));
	} while(count > 0);
}
//==============================================================
//			�y�a�d�q�G���R�[�h�z�����o�[ ANS.1�I�u�W�F�N�g
//--------------------------------------------------------------
//	������
//		unsigned char	cClass		�N���X
//		unsigned int	iTag		�^�O
//	���Ԓl
//				����
//==============================================================
void	ASN1::encodeBER_Constructed(unsigned char cClass, unsigned int iTag)
{
	unsigned	int		i=0;
	string				strSEQ;

	while(i < Constructed.size()){
		Constructed[i]->encodeBER();
		szAddValue += Constructed[i]->Get_ExternalDataSize();	//�ǉ��f�[�^���L�邩�H
		strSEQ.append(Constructed[i]->Get_BERcode(), Constructed[i]->Get_BERsize());
		i++;
		if(i < Constructed.size()){
			if(szAddValue != 0){
				error(1);
			}
		}
	}
	encodeBER_TAG(cClass, true, iTag, strSEQ.size() + szAddValue);
	strBER += strSEQ;
}
//==============================================================
//			�y�a�d�q�G���R�[�h�z
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
void	ASN1::encodeBER()
{
	encodeBER_TAG(BER_Class_General, false, BER_TAG_NULL, 0);
}
//==============================================================
//			�s�a�d�q�G���R�[�h�t��������̐����l�̃T�C�Y���擾
//--------------------------------------------------------------
//	������
//						int	_i		�����l
//	���Ԓl
//			unsigned	int			BER���������ꂽ�����l�̃T�C�Y
//==============================================================
unsigned int ASN1::Get_szInt_for_BER(int _i){

	unsigned int	iResult;

	if((_i < 128) && (_i >= -128)) {	//-128�`127
		iResult = 1;
	} else if((_i < 32768) && (_i >= -32768)) {	//128�`32767,	
		iResult = 2;
	} else if((_i < 8388608) && (_i >= -8388608)) {
		iResult = 3;
	} else {
		iResult = 4;
	}

	return(iResult);
}
//==============================================================
//			�s�a�d�q�G���R�[�h�t��������̃T�C�Y�l�̃T�C�Y���擾
//--------------------------------------------------------------
//	������
//			unsigned	int	iSize	�T�C�Y�l
//	���Ԓl
//			unsigned	int			BER���������ꂽ�T�C�Y�l�̃T�C�Y
//==============================================================
unsigned int ASN1::Get_szSize_for_BER(unsigned int iSize){

	unsigned int	szSize;

	if(iSize < (1<<7)){			//�`127
		szSize = 1;
	} else if(iSize < (1<<8)) {	//�`255
		szSize = 2;
	} else if(iSize < (1<<16)) {	//�`65535,	
		szSize = 3;
	} else if(iSize < (1<<24)) {
		szSize = 4;
	} else {
		szSize = 5;
	}

	return(szSize);
}
//==============================================================
//		BER�R�[�h�̎擾
//--------------------------------------------------------------
//	������
//							����
//	���Ԓl
//		const	char*		BER�R�[�h
//==============================================================
const	char*	ASN1::Get_BERcode(void){
	return(strBER.c_str());
};
//==============================================================
//		BER�R�[�h�̃T�C�Y�擾
//--------------------------------------------------------------
//	������
//							����
//	���Ԓl
//		unsigned	int		BER�R�[�h�̃T�C�Y
//==============================================================
unsigned	int	ASN1::Get_BERsize(void){
	return(strBER.size());
};
