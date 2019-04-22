#include "StdAfx.h"
#include "AES_CBC.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
AES_CBC::AES_CBC(const char _strName[]):
	AES(_strName)
{
	mode	= CBC;
}
//==============================================================
//		�f�X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
AES_CBC::~AES_CBC(void)
{
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//==============================================================
void	AES_CBC::SetIV(void *data)
{
	vector = _mm_load_si128((__m128i*)data);
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//==============================================================
void	AES_CBC::initIV()
{
	vector = _mm_loadu_si128((__m128i *)IV.strValue.c_str());
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	������
//			void *data		����
//	���Ԓl
//			����
//==============================================================
void	AES_CBC::encrypt(void *data)
{
	__m128i	temp = Cipher(_mm_xor_si128(_mm_load_si128((__m128i*)data), vector));

	vector = temp;
	_mm_store_si128((__m128i*)data, temp);

}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	������
//			void *data		�Í���
//	���Ԓl
//			����
//==============================================================
void	AES_CBC::decrypt(void *data)
{
	__m128i	temp = _mm_xor_si128(InvCipher(_mm_load_si128((__m128i*)data)), vector);

	vector	= _mm_load_si128((__m128i*)data);
	_mm_store_si128((__m128i*)data, temp);

}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	������
//			__m128i		_xmm_IV		�������x�N�^IV
//	���Ԓl
//			����
//==============================================================
void	AES_CBC::Set_AES(__m128i _xmm_IV)
{
	//ASN.1�̒�`
	Set();
	vector = _xmm_IV;	//	SetIV()�Ɠ����Ӗ��B
	IV.Set(_xmm_IV.m128i_i8,sizeof(_xmm_IV));
	Set_Construct(&IV);
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
void	AES_CBC::encipher(void *data,unsigned int iSize)
{
	__m128i				temp;
	__m128i				_vector		= vector;

	unsigned	char*	cData		= (unsigned	char*)data;
	unsigned	int		n			= 0;

	while(n < iSize){
		temp = Cipher(_mm_xor_si128(_mm_load_si128((__m128i*)&cData[n]), _vector));
		_mm_store_si128((__m128i*)&cData[n], temp);
		_vector = temp;
		n	+=	szBlock;
	}
	vector = _vector;

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
int		AES_CBC::encipher_last(void *data,unsigned int iSize)
{
	__m128i				temp;
	__m128i				_vector		= vector;

	unsigned	char*	cData		= (unsigned	char*)data;
	unsigned	int		n			= 0;

	unsigned	int		ptPadding;
	unsigned	char	cPadData;
	unsigned	char	cntPadData;

	//�Í��i�ŏI�u���b�N���O�܂Łj
	while(iSize >= szBlock){
		temp = Cipher(_mm_xor_si128(_mm_load_si128((__m128i*)&cData[n]), _vector));
		_mm_store_si128((__m128i*)&cData[n], temp);
		_vector = temp;
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
		temp = Cipher(_mm_xor_si128(_mm_load_si128((__m128i*)&cData[n]), _vector));
		_mm_store_si128((__m128i*)&cData[n], temp);
		_vector = temp;
		n		+= szBlock;
	}
	temp = Cipher(_mm_xor_si128(_mm_load_si128((__m128i*)&cData[n]), _vector));
	_mm_store_si128((__m128i*)&cData[n], temp);
	vector = temp;			//���̃����o�[�ϐ��ɓ����B
//	n		+= szBlock;		//����͂����B

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
void	AES_CBC::decipher(void *data,unsigned int iSize)
{
	__m128i				temp;

	unsigned	char*	cData		= (unsigned	char*)data;
	unsigned	int		n			= 0;

	if((iSize >= szBlock * 4) && (aesni == true)){
		while(n < iSize){
			vector = InvCipher_CBC4((__m128i*)&cData[n], vector);
			n	+=	szBlock * 4;
		}
	}

	while(n < iSize){
		temp = _mm_xor_si128(InvCipher(_mm_load_si128((__m128i*)&cData[n])), vector);
		vector	= _mm_load_si128((__m128i*)&cData[n]);
		_mm_store_si128((__m128i*)&cData[n], temp);
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
int		AES_CBC::decipher_last(void *data,unsigned int iSize)
{
	__m128i				temp;

	unsigned	char*	cData		= (unsigned	char*)data;
	unsigned	int		n			= 0;

	unsigned	char	cPadData;
	unsigned	char	cntPadData;

	//����
	if(aesni == true){
		while(iSize > szBlock * 4){
			vector = InvCipher_CBC4((__m128i*)&cData[n], vector);
			n		+= szBlock * 4;
			iSize	-= szBlock * 4;
		}
	}

	while(iSize > 0){
		temp = _mm_xor_si128(InvCipher(_mm_load_si128((__m128i*)&cData[n])), vector);
		vector	= _mm_load_si128((__m128i*)&cData[n]);
		_mm_store_si128((__m128i*)&cData[n], temp);
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
