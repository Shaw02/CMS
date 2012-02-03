#include "StdAfx.h"
#include "DES_EDE3.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
DES_EDE3::DES_EDE3(const char _strName[]):
	DES(_strName)
{
	szKey	= DES_KeySize * 3;
}
//==============================================================
//		�f�X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
DES_EDE3::~DES_EDE3(void)
{
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	������
//			void *data		����
//	���Ԓl
//			����
//==============================================================
void	DES_EDE3::Set_Key(void *key)
{
	unsigned __int64* cKey =	(unsigned __int64 *)key;
	
	KeyExpansion(&cKey[0], k);
	KeyExpansion(&cKey[1], k2);
	KeyExpansion(&cKey[2], k3);

}
//==============================================================
//			Encryption
//--------------------------------------------------------------
//	������
//		unsigned __int64
//	���Ԓl
//		unsigned __int64
//==============================================================
unsigned __int64	DES_EDE3::Cipher3(unsigned __int64 iData)
{
	union{
		struct{
			unsigned	int	R;	//����
			unsigned	int	L;	//���
		}	i;
		unsigned	__int64	l;
	}	Data;

	unsigned	int	i = 0;

	//--------------
	//IP
	Data.l	= IP(iData);

	//--------------
	//[E] Round
	while(i < DES_Round){
		Data.i.L =	Data.i.L ^ f(Data.i.R, k[i]);
		i++;
		Data.i.R =	Data.i.R ^ f(Data.i.L, k[i]);
		i++;
	}

	//--------------
	//[D] Round
	while(i>0){
		i--;
		Data.i.R =	Data.i.R ^ f(Data.i.L, k2[i]);
		i--;
		Data.i.L =	Data.i.L ^ f(Data.i.R, k2[i]);
	}

	//--------------
	//[E] Round
	while(i < DES_Round){
		Data.i.L =	Data.i.L ^ f(Data.i.R, k3[i]);
		i++;
		Data.i.R =	Data.i.R ^ f(Data.i.L, k3[i]);
		i++;
	}

	//--------------
	//IP-1
	return(invIP(Data.l));
	
}
//==============================================================
//			Decryption
//--------------------------------------------------------------
//	������
//		unsigned __int64
//	���Ԓl
//		unsigned __int64
//==============================================================
unsigned __int64	DES_EDE3::InvCipher3(unsigned __int64 iData)
{

	union{
		struct{
			unsigned	int	R;
			unsigned	int	L;
		}	i;
		unsigned	__int64	l;
	}	Data;

	unsigned	int	i = DES_Round;

	//--------------
	//IP
	Data.l	= IP(iData);

	//--------------
	//[D] Round
	while(i>0){
		i--;
		Data.i.L =	Data.i.L ^ f(Data.i.R, k3[i]);
		i--;
		Data.i.R =	Data.i.R ^ f(Data.i.L, k3[i]);
	}

	//--------------
	//[E] Round
	while(i < DES_Round){
		Data.i.R =	Data.i.R ^ f(Data.i.L, k2[i]);
		i++;
		Data.i.L =	Data.i.L ^ f(Data.i.R, k2[i]);
		i++;
	}

	//--------------
	//[D] Round
	while(i>0){
		i--;
		Data.i.L =	Data.i.L ^ f(Data.i.R, k[i]);
		i--;
		Data.i.R =	Data.i.R ^ f(Data.i.L, k[i]);
	}

	//--------------
	//IP-1
	return(invIP(Data.l));	
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	������
//			void *data		����
//	���Ԓl
//			����
//==============================================================
void	DES_EDE3::encrypt(void *data)
{
	unsigned __int64*	iData	= (unsigned __int64*)data;

	*iData	= Cipher3(*iData);
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	������
//			void *data		�Í���
//	���Ԓl
//			����
//==============================================================
void	DES_EDE3::decrypt(void *data)
{
	unsigned __int64*	iData	= (unsigned __int64*)data;

	*iData	= InvCipher3(*iData);
}
