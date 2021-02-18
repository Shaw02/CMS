#include "StdAfx.h"
#include "AlgorithmIdentifier.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
AlgorithmIdentifier::AlgorithmIdentifier(const char _strName[]):
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
AlgorithmIdentifier::~AlgorithmIdentifier(void)
{
}
//==============================================================
//		�l��ݒ�
//--------------------------------------------------------------
//	������
//			unsigned	int		i[]		oid
//						size_t	n		oid�̐�
//	���Ԓl
//			����
//==============================================================
void	AlgorithmIdentifier::Set_oid(unsigned int i[], size_t n)
{
	algorithm.Set(i,n);
}
//==============================================================
//		�l��ݒ�
//--------------------------------------------------------------
//	������
//			unsigned int i[]	oid
//			unsigned int n		oid�̐�
//	���Ԓl
//			����
//==============================================================
void	AlgorithmIdentifier::Set()
{
	//------
	//Clear_Construct
	Clear_Construct();

	//------
	//contentType ContentType
	Set_Construct(&algorithm);
}
//==============================================================
//		oid�̃`�F�b�N
//--------------------------------------------------------------
//	������
//			ObjectIdentifier*	ptOID	�A���S���Y��
//	���Ԓl
//			int					0	
//								-1	�G���[
//==============================================================
int	AlgorithmIdentifier::Check_OID(ObjectIdentifier* ptOID)
{
	size_t	i = algorithm.iValue.size();

	if(i != ptOID->iValue.size()){
		return(-1);
	} else {
		while(i > 0){
			i--;
			if(ptOID->iValue[i] != algorithm.iValue[i]){
				return(-1);
			}
		}
		return(0);
	}

/*	if(ptOID->iValue.size() != (sizeof(oid)/sizeof(int))){
		return(-1);
	} else {
		while(i < ((sizeof(oid)/sizeof(int))-1)){
			if(ptOID->iValue[i] != oid[i]){
				return(-1);
			}
			i++;
		}
		return(ptOID->iValue[i]);
	}
*/
}
