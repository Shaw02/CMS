#include "StdAfx.h"
#include "Context.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
Context::Context(unsigned int num, const char _strName[]):
	number(num),
	ASN1(_strName)
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
Context::~Context(void)
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
void	Context::encodeBER()
{
	unsigned	int		i		= 0;
//	unsigned	int		iSize	= 0;
	string				strContext;

	//両方のデータがある場合。
	if((Constructed.size()>0 )&& ((strValue.size() > 0)||(szAddValue>0))){
		error(0);

	//コンテンツが、ASN.1の場合。	"SEQENCE"と同じ挙動とする。
	} else if(Constructed.size() > 0){
		encodeBER_Constructed(BER_Class_Context, number);

	//コンテンツが、ASN.1で無い場合。
	} else if(strValue.size() > 0) {
		while(i < strValue.size()){
			strContext += strValue[i];
			i++;
		}
		encodeBER_TAG(BER_Class_Context, (strValue.size() == 1)? false : true, number, strContext.size());
		strBER += strContext;

	//コンテンツがObject外データの場合。（タグだけ出力しておく。）
	} else if(szAddValue>0){
		encodeBER_TAG(BER_Class_Context, false, number, szAddValue);
	}
}
//==============================================================
//		値を設定（バイナリデータ）
//--------------------------------------------------------------
//	●引数
//			ASN1* asn1		memberとなるobject
//	●返値
//			無し
//==============================================================
void	Context::Set(string strData)
{
	strValue.push_back(strData);
}
