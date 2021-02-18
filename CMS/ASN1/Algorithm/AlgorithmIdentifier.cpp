#include "StdAfx.h"
#include "AlgorithmIdentifier.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
AlgorithmIdentifier::AlgorithmIdentifier(const char _strName[]):
	Sequence(_strName)
{
}
//==============================================================
//		デストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
AlgorithmIdentifier::~AlgorithmIdentifier(void)
{
}
//==============================================================
//		値を設定
//--------------------------------------------------------------
//	●引数
//			unsigned	int		i[]		oid
//						size_t	n		oidの数
//	●返値
//			無し
//==============================================================
void	AlgorithmIdentifier::Set_oid(unsigned int i[], size_t n)
{
	algorithm.Set(i,n);
}
//==============================================================
//		値を設定
//--------------------------------------------------------------
//	●引数
//			unsigned int i[]	oid
//			unsigned int n		oidの数
//	●返値
//			無し
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
//		oidのチェック
//--------------------------------------------------------------
//	●引数
//			ObjectIdentifier*	ptOID	アルゴリズム
//	●返値
//			int					0	
//								-1	エラー
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
