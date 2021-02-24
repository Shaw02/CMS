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

	for(vector<ASN1*>::iterator	it=Constructed.begin(), e=Constructed.end(); it!=e; it++){
		//������ To Do:	�e�N���X���|�C���^�ɂ���
	}

	Constructed.clear();
}

//==============================================================
//		�O���f�[�^�T�C�Y�̐ݒ�
//--------------------------------------------------------------
//	������
//			size_t	iSize	�O���f�[�^�̃T�C�Y
//	���Ԓl
//			����
//==============================================================
void	ASN1::Set_ExternalDataSize(size_t iSize)
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
//					size_t	iSize	�f�[�^�T�C�Y
//	���Ԓl
//			����
//==============================================================
void	ASN1::encodeBER_TAG(unsigned char cClass, bool fStruct,unsigned int iTag, size_t iSize)
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
//		size_t	iSize		�l	�i��64bit�l�܂ł̂ݑΉ��j
//	���Ԓl
//			����
//==============================================================
void	ASN1::encodeBER_size(size_t iSize)
{
	if(iSize < 128){			//0�`127
		strBER.append(1,iSize & 0x7F);
	} else {
		string	_code;
		size_t	i = 0;
		while(iSize > 0){
			_code.append(1, (char)(iSize & 0xFF));
			iSize >>= 8;
			i++;
		}
		strBER.append(1, (char)(0x80 + i));
		while(i > 0){
			i--;
			strBER.append(1,_code[i]);
		}
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
void	ASN1::encodeBER_int(__int64 _i)
{
	if(_i == 0){
		strBER.append(1,0);
	} else {
		string	_code;
		size_t	i = 0;
		while((_i != 0) && (_i != -1)){
			_code.append(1, (char)(_i & 0xFF));
			_i >>= 8;
			i++;
		}
		while(i > 0){
			i--;
			strBER.append(1,_code[i]);
		}
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
				size_t	count=0;		//�ǂݍ��݉񐔃J�E���g�p
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
//						__int64	_i		�����l
//	���Ԓl
//						size_t			BER���������ꂽ�����l�̃T�C�Y
//==============================================================
size_t ASN1::Get_szInt_for_BER(__int64 _i){

	size_t	iResult = 7;

	union{
		__int64	i64;
		char	c[8];
	} _num;

	_num.i64 = _i;

	while(iResult>0){
		if(_num.c[iResult] != 0){
			break;
		}
		iResult--;
	}
	return(iResult+1);
}
//==============================================================
//			�s�a�d�q�G���R�[�h�t��������̃T�C�Y�l�̃T�C�Y���擾
//--------------------------------------------------------------
//	������
//			unsigned	int	iSize	�T�C�Y�l
//	���Ԓl
//						size_t		BER���������ꂽ�T�C�Y�l�̃T�C�Y
//==============================================================
size_t ASN1::Get_szSize_for_BER(size_t iSize){

	size_t	szSize;

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
//				size_t		BER�R�[�h�̃T�C�Y
//==============================================================
size_t	ASN1::Get_BERsize(void){
	return(strBER.size());
};
