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
//	������		�i�`�F�b�N�p�j
//				cClass		�N���X
//				fStruct		�\�����t���O
//				iTag		�^�O
//	���Ԓl
//				�T�C�Y
//==============================================================
unsigned	int	BER_Input::read_TAG_with_Check(unsigned char cClass, bool fStruct, unsigned int iTag)
{
	unsigned	int		read_tag;
	unsigned	char	read_class;
				bool	read_fStruct;
	unsigned	int		iSize;

	read_TAG(&read_class, &read_fStruct, &read_tag);

	if((read_class != cClass)||(read_tag != iTag)||(fStruct != read_fStruct)){
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
	const	int		iSize	= read_TAG_with_Check(BER_Class_General, false, BER_TAG_INTEGER);

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
		const		int		iSize	= read_TAG_with_Check(BER_Class_General, false, BER_TAG_OBJECT_IDENTIFIER);
		const		int		ptPos	= iSize + tellg();
		const		int		n		= read_variable();
	vector<unsigned int>	iData;

	//OID�ǂݍ���
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
		const	int	iSize	= read_Object_Identifier(oid);
	unsigned	int	i		= 0;

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
	return(read_TAG_with_Check(BER_Class_General, false, BER_TAG_OCTET_STRING));
}
