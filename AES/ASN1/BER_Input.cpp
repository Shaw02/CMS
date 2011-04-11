#include "StdAfx.h"
#include "BER_Input.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
BER_Input::BER_Input(const char*	strFileName):
	FileInput(strFileName)
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
BER_Input::~BER_Input(void)
{
}

//==============================================================
//		�G���[����
//--------------------------------------------------------------
//	������
//				unsigned int iEer	�G���[�R�[�h
//	���Ԓl
//				����
//==============================================================
void	BER_Input::DecodeError(unsigned int iEer)
{
	static	const	char*	const	msg_err[2]={
		"Different Struct.",		//0x00: �\�����Ⴄ�B
	};

	errPrint("ASN.1 BER Decode Error :", msg_err[iEer]);
}

//==============================================================
//		�����l�ǂݍ���
//--------------------------------------------------------------
//	������
//			unsigned int	iSize	�����l�̃T�C�Y[Byte]
//	���Ԓl
//			unsigned int			���l
//==============================================================
int	BER_Input::read_int(int iSize)
{
	int		iResult	= cRead();

	if(iResult & 0x80){
		iResult |= 0xFFFFFF00;
	}

	iSize--;
	while(iSize>0){
		iResult <<= 8;
		iSize--;
	};

	return(iResult);
}
//==============================================================
//		�����l�ǂݍ���
//--------------------------------------------------------------
//	������
//			unsigned int	iSize	�����l�̃T�C�Y[Byte]
//	���Ԓl
//			unsigned int			���l
//==============================================================
unsigned int	BER_Input::read_uint(int iSize)
{
	unsigned int	iResult = 0;

	do{
		iResult <<= 8;
		iResult |= cRead();
		iSize--;
	} while (iSize>0);

	return(iResult);
}
//==============================================================
//		�ϒ��l�ǂݍ���
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				unsigned int	���l
//==============================================================
unsigned int	BER_Input::read_variable(void)
{
	//----------------------------------
	//��Local �ϐ�
	unsigned	int			iData=0;		//�ǂݍ��񂾉ϒ����l
	unsigned	int			count=9;		//�ǂݍ��݉񐔃J�E���g�p
	unsigned	char		cData;			//�ǂݍ��ݗp�ϐ�

	//----------------------------------
	//���f���^�^�C���ǂݍ���
	do{
		iData <<= 7;
		cData = cRead();
		iData	|= (unsigned int)cData & 0x7F;
		count--;
	} while ( (count > 0) && (cData & 0x80) );

	return(iData);
}

//==============================================================
//		
//--------------------------------------------------------------
//	������
//				*cClass		�߂�l�p�̃|�C���^	�N���X
//				*fStruct	�߂�l�p�̃|�C���^	�\�����t���O
//				*iTag		�߂�l�p�̃|�C���^	�^�O
//	���Ԓl
//				����
//==============================================================
void	BER_Input::read_TAG(unsigned char* cClass, bool* fStruct, unsigned int* iTag)
{
	unsigned	char	cTag = cRead();

	*cClass		= cTag>>6;
	*fStruct	= (cTag & (0x01<<5))? true : false;
	
	cTag &= 0x1F;

	*iTag = ((cTag <= 30)? cTag : read_variable());
}
//==============================================================
//		�^�O�ǂݍ���
//--------------------------------------------------------------
//	������
//				cClass		�N���X
//				iTag		�^�O
//				*fStruct	�߂�l�p�̃|�C���^	�\�����t���O
//	���Ԓl
//				�T�C�Y
//==============================================================
unsigned	int	BER_Input::read_TAG_with_Check(unsigned char cClass, unsigned int iTag, bool* fStruct)
{
	unsigned	int		read_tag;
	unsigned	char	read_class;
	unsigned	int		iSize;

	read_TAG(&read_class, fStruct, &read_tag);

	if((read_class != cClass)||(read_tag != iTag)){
		DecodeError(0);
	}

	iSize = cRead();
	if(iSize >= 0x81){
		iSize = read_uint(iSize & 0x7F);
	}

	return(iSize);
}
//==============================================================
//			Integer
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			�ǂݍ��񂾐��l
//==============================================================
unsigned int	BER_Input::read_Integer(Integer* i)
{
	int		iSize;
	bool	fStruct;

	iSize = read_TAG_with_Check(BER_Class_General, BER_TAG_INTEGER, &fStruct);
	if(fStruct){
		DecodeError(0);
	}
	i->Set(read_int(iSize));

	return(iSize);
}
//==============================================================
//			Object Identifier
//--------------------------------------------------------------
//	������
//			ObjectIdentifier*	oid		�ǂݍ���oid������object�̃|�C���^
//	���Ԓl
//			unsigned int		�T�C�Y
//==============================================================
unsigned int	BER_Input::read_Object_Identifier(ObjectIdentifier* oid)
{
	int		iSize;
	int		ptPos;
	int		n;
	bool	fStruct;
	vector<unsigned int>	iData;

	iSize = read_TAG_with_Check(BER_Class_General, BER_TAG_OBJECT_IDENTIFIER, &fStruct);
	if(fStruct){
		DecodeError(0);
	}
	
	//OID�ǂݍ���
	ptPos = iSize + tellg();
	n = read_variable();
	iData.push_back(n / 40);
	iData.push_back(n % 40);
	while(ptPos > tellg()){
		iData.push_back(read_variable());
	}
	oid->SetVector(iData);

	return(iSize);
}

//==============================================================
//			Object Identifier
//--------------------------------------------------------------
//	������
//			ObjectIdentifier*	oid		�ǂݍ���oid������object�̃|�C���^
//			unsigned	int		iData[]	�ƍ�����oid�̎���
//			unsigned	int		szData	�ƍ�����oid�̃T�C�Y
//	���Ԓl
//			unsigned int		�T�C�Y
//==============================================================
unsigned int	BER_Input::read_Object_Identifier_with_Check(
					ObjectIdentifier*	oid,
					unsigned	int		iData[],
					unsigned	int		szData
				)
{
				int	iSize = read_Object_Identifier(oid);

	unsigned	int	i = 0;

	if(oid->iValue.size() != szData){
		DecodeError(0);
	}

	while(i < szData){
		if(oid->iValue[i] != iData[i]){
			DecodeError(0);
		}
		i++;
	}

	return(iSize);
}
//==============================================================
//			Octet_Strings
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			unsigned int	�T�C�Y
//==============================================================
unsigned int	BER_Input::read_Octet_Strings(void)
{
	int		iSize;
	bool	fStruct;

	iSize = read_TAG_with_Check(BER_Class_General, BER_TAG_OCTET_STRING, &fStruct);
	if(fStruct){
		DecodeError(0);
	}

	return(iSize);
}
