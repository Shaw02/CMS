#include "StdAfx.h"
#include "Encryption.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
Encryption::Encryption(const char _strName[]):
	AlgorithmIdentifier(_strName)
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
Encryption::~Encryption(void)
{
	//�N���X���������O�ɁA���X�P�W���[�����O�N���A����B
	Clear_Key();
}
//==============================================================
//			�����̓���
//--------------------------------------------------------------
//	������
//			void			*data	����
//			unsigned int	iSize	�����̃T�C�Y
//	���Ԓl
//			����
//==============================================================
void	Encryption::encipher(void *data,unsigned int iSize)
{
	unsigned	char*	cData		= (unsigned	char*)data;
	unsigned	int		n			= 0;

	while(n < iSize){
		encrypt(&cData[n]);
		n	+=	szBlock;
	}
}
//==============================================================
//			�����̓��́i�ŏI�j
//--------------------------------------------------------------
//	������
//			void			*data	����
//			unsigned	int	iSize	�����̃T�C�Y
//	���Ԓl
//						int			Padding�Ƃ��Ēǉ������T�C�Y
//==============================================================
int		Encryption::encipher_last(void *data,unsigned int iSize)
{
	unsigned	char*	cData		= (unsigned	char*)data;
	unsigned	int		n			= 0;

	unsigned	int		ptPadding;
	unsigned	char	cPadData;
	unsigned	char	cntPadData;

	//�Í��i�ŏI�u���b�N���O�܂Łj
	while(iSize >= szBlock){
		encrypt(&cData[n]);
		n		+= szBlock;
		iSize	-= szBlock;
	}

	//Padding����(PKCS#7)�����{
	ptPadding	= n + ((n%szBlock)?-1:szBlock-1);
	cPadData	= szBlock - iSize;
	cntPadData	= cPadData;
	do{
		cData[ptPadding] = cPadData;
		ptPadding--;
		cntPadData--;
	} while(cntPadData>0);

	//�Í��i�ŏI�j
	if(iSize == szBlock){
		encrypt(&cData[n]);
		n += szBlock;
	}
	encrypt(&cData[n]);
	n += szBlock;

	return(cPadData);
}
//==============================================================
//			�Í����̓���
//--------------------------------------------------------------
//	������
//			void			*data	�Í���
//			unsigned int	iSize	�Í����̃T�C�Y
//	���Ԓl
//			����
//==============================================================
void	Encryption::decipher(void *data,unsigned int iSize)
{
	unsigned	char*	cData		= (unsigned	char*)data;
	unsigned	int		n			= 0;

	while(n < iSize){
		decrypt(&cData[n]);
		n	+=	szBlock;
	}
}
//==============================================================
//			�Í����̓��́i�ŏI�j
//--------------------------------------------------------------
//	������
//			void			*data	�Í���
//			unsigned	int	iSize	�Í����̃T�C�Y
//	���Ԓl
//						int	1�`szBlock	Padding�f�[�^
//							-1			Padding���ُ�
//==============================================================
int		Encryption::decipher_last(void *data,unsigned int iSize)
{
	unsigned	char*	cData		= (unsigned	char*)data;
	unsigned	int		n			= 0;

	unsigned	char	cPadData;
	unsigned	char	cntPadData;

	//����
	while(iSize > 0){
		decrypt(&cData[n]);
		n		+= szBlock;
		iSize	-= szBlock;
	}

	//�Ō��Block�́APadding���܂ށB
	n--;
	cPadData	= cData[n];
	cntPadData	= cPadData;

	//Padding�̃`�F�b�N
	do{
		if(cData[n] != cPadData){	return(-1);	}
		n--;
		cntPadData--;
	} while(cntPadData>0);
	return(cPadData);
}
