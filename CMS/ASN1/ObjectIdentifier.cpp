#include "StdAfx.h"
#include "ObjectIdentifier.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
ObjectIdentifier::ObjectIdentifier(const char _strName[]):
	ASN1(_strName)
{
}
//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//			unsigned int i[]	OID
//			unsigned int n		OIDのサイズ(整数が何個あるか？)
//	●返値
//				無し
//==============================================================
ObjectIdentifier::ObjectIdentifier(unsigned int i[], unsigned int n, const char _strName[]):
	ASN1(_strName)
{
	Set(i,n);
}
//==============================================================
//		デストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
ObjectIdentifier::~ObjectIdentifier(void)
{
}

//==============================================================
//		ＢＥＲ符号化
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
void	ObjectIdentifier::encodeBER()
{
	unsigned	int	iCount	= 2;
	string			oid;

	strBER.assign(1, iValue[0] * 40 + iValue[1]);

	while(iCount < iValue.size()){
		encodeBER_variable(iValue[iCount]);
		iCount++;
	}
	oid = strBER;	//エンコードしたデータを一旦こっちに退避

	encodeBER_TAG(BER_Class_General, false, BER_TAG_OBJECT_IDENTIFIER, oid.size());
	strBER += oid;
}
//==============================================================
//		値を設定
//--------------------------------------------------------------
//	●引数
//			unsigned int i[]	OID
//			size_t		 n		OIDのサイズ(整数が何個あるか？)
//	●返値
//			無し
//==============================================================
void	ObjectIdentifier::Set(unsigned int i[], size_t n)
{
	size_t	count = 0;

	while(count < n){
		iValue.push_back(i[count]);
		count++;
	}
}
//==============================================================
//		値を設定
//--------------------------------------------------------------
//	●引数
//			unsigned int i[]	OID
//			unsigned int n		OIDのサイズ(整数が何個あるか？)
//	●返値
//			無し
//==============================================================
void	ObjectIdentifier::SetVector(vector<unsigned int> i)
{
	unsigned	int	count = 0;

	while(count < i.size()){
		iValue.push_back(i[count]);
		count++;
	}
}
