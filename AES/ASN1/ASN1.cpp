#include "StdAfx.h"
#include "ASN1.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
ASN1::ASN1(const char _strName[]):
	strName(_strName),
	szAddValue(0)
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
ASN1::~ASN1(void)
{
}

//==============================================================
//		値を設定
//--------------------------------------------------------------
//	●引数
//			ASN1* asn1		memberとなるobject
//	●返値
//			無し
//==============================================================
void	ASN1::Set_Construct(ASN1* asn1)
{
	Constructed.push_back(asn1);
}

//==============================================================
//		値を設定
//--------------------------------------------------------------
//	●引数
//			ASN1* asn1		memberとなるobject
//	●返値
//			無し
//==============================================================
void	ASN1::Set_ExternalDataSize(unsigned int iSize)
{
	szAddValue = iSize;
}
//==============================================================
//		エラー処理
//--------------------------------------------------------------
//	●引数
//				unsigned int iEer	エラーコード
//	●返値
//				無し
//==============================================================
void	ASN1::error(unsigned int iEer)
{
	static	const	char*	const	msg_err[2]={
		"Context include ASN.1 and Binary.",					//0x00: Contextに、ASN.1とBIN両方がある。
		"Part of the constructed data include external data."	//0x01: 構造化データの途中に、外部データがある。
	};
	errPrint("ASN.1 BER Encode Error :", msg_err[iEer]);
}

//==============================================================
//			タグ・サイズを、ＢＥＲ符号化
//--------------------------------------------------------------
//	●引数
//		unsigned	char	cClass	クラス
//					bool	fStruct	構造化フラグ
//		unsigned	int		iTag	タグNo.
//		unsigned	int		iSize	データサイズ
//	●返値
//			無し
//==============================================================
void	ASN1::encodeBER_TAG(unsigned char cClass, bool fStruct,unsigned int iTag, unsigned int iSize)
{
	unsigned	char	cTag = ((fStruct&0x01)<<5) | (cClass<<6);

	if(iTag <= 30){
		strBER.assign(1,cTag | iTag);
	} else {
		strBER.assign(1,cTag | 31);
		encodeBER_variable(iTag);
	}
	encodeBER_size(iSize);
}
//==============================================================
//			サイズを、ＢＥＲ符号化
//--------------------------------------------------------------
//	●引数
//			iSize		値	（※32bit値までのみ対応）
//	●返値
//			無し
//==============================================================
void	ASN1::encodeBER_size(unsigned int iSize)
{
	if(iSize < (1<<7)){			//0～127
		strBER.append(1,iSize & 0x7F);
	} else if(iSize < (1<<8)) {	//128～256
		strBER.append(1,0x81);
		strBER.append(1,iSize & 0xFF);
	} else if(iSize < (1<<16)) {	//256～65535,	
		strBER.append(1,0x82);
		strBER.append(1,((iSize>>8) & 0xFF));
		strBER.append(1,(iSize & 0xFF));
	} else if(iSize < (1<<24)) {	//
		strBER.append(1,0x83);
		strBER.append(1,((iSize>>16) & 0xFF));
		strBER.append(1,((iSize>>8) & 0xFF));
		strBER.append(1,(iSize & 0xFF));
	} else {
		strBER.append(1,0x84);
		strBER.append(1,((iSize>>24) & 0xFF));
		strBER.append(1,((iSize>>16) & 0xFF));
		strBER.append(1,((iSize>>8) & 0xFF));
		strBER.append(1,(iSize & 0xFF));
	}
}
//==============================================================
//			整数値をＢＥＲ符号化
//--------------------------------------------------------------
//	●引数
//			_i		値	（※32bit値までのみ対応）
//	●返値
//			無し
//==============================================================
void	ASN1::encodeBER_int(int _i)
{
	if((_i < 64) && (_i >= -64)){		//-64～63
		strBER.append(1,_i & 0x7F);
	} else if((_i < 128) && (_i >= -128)) {	//-128～127
		strBER.append(1,_i & 0xFF);
	} else if((_i < 32768) && (_i >= -32768)) {	//128～32767,	
		strBER.append(1,(_i>> 8) & 0xFF);
		strBER.append(1,_i & 0xFF);
	} else if((_i < 8388608) && (_i >= -8388608)) {
		strBER.append(1,(_i>>16) & 0xFF);
		strBER.append(1,(_i>> 8) & 0xFF);
		strBER.append(1,_i & 0xFF);
	} else {
		strBER.append(1,(_i>>24) & 0xFF);
		strBER.append(1,(_i>>16) & 0xFF);
		strBER.append(1,(_i>> 8) & 0xFF);
		strBER.append(1,_i & 0xFF);
	}
}
//==============================================================
//			可変長値にＢＥＲ符号化
//--------------------------------------------------------------
//	●引数
//			_i		値	（※32bit値までのみ対応）
//	●返値
//			無し
//==============================================================
void	ASN1::encodeBER_variable(unsigned int _i)
{
	unsigned	int		count=0;		//読み込み回数カウント用
				char	cData[9];

	//----------------------------------
	//■可変長エンコード
	do{
		cData[count] = _i & 0x7F;
		_i>>=7;
		count++;
	} while((count<9) && (_i > 0));

	//■可変長出力
	do{
		count--;
		strBER.append(1,cData[count] | ((count==0)? 0 : 0x80));
	} while(count > 0);
}
//==============================================================
//		ＢＥＲ符号化
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
void	ASN1::encodeBER_Constructed(unsigned char cClass, unsigned int iTag)
{
	unsigned	int		i=0;
	string				strSEQ;

	while(i < Constructed.size()){
		Constructed[i]->encodeBER();
		szAddValue += Constructed[i]->Get_ExternalDataSize();	//追加データが有るか？
		strSEQ.append(Constructed[i]->Get_BERcode(), Constructed[i]->Get_BERsize());
		i++;
		//■■■ to do 途中に外部データが来ても大丈夫なような設計へ。 	
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
//		ＢＥＲ符号化
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
void	ASN1::encodeBER()
{
	encodeBER_TAG(BER_Class_General, false, BER_TAG_NULL, 0);
}
//==============================================================
//			整数値のASN.1 BER用サイズを取得
//--------------------------------------------------------------
//	●引数
//			_i
//	●返値
//			無し
//==============================================================
unsigned int ASN1::Get_szInt_for_BER(int _i){

	unsigned int	iResult;

	if((_i < 128) && (_i >= -128)) {	//-128～127
		iResult = 1;
	} else if((_i < 32768) && (_i >= -32768)) {	//128～32767,	
		iResult = 2;
	} else if((_i < 8388608) && (_i >= -8388608)) {
		iResult = 3;
	} else {
		iResult = 4;
	}

	return(iResult);
}
//==============================================================
//			サイズ値のASN.1 BER用サイズを取得
//--------------------------------------------------------------
//	●引数
//			iSize
//	●返値
//			無し
//==============================================================
unsigned int ASN1::Get_szSize_for_BER(unsigned int iSize){

	unsigned int	szSize;

	if(iSize < (1<<7)){			//～127
		szSize = 1;
	} else if(iSize < (1<<8)) {	//～255
		szSize = 2;
	} else if(iSize < (1<<16)) {	//～65535,	
		szSize = 3;
	} else if(iSize < (1<<24)) {
		szSize = 4;
	} else {
		szSize = 5;
	}

	return(szSize);
}
//==============================================================
//		BERコードの取得
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//			const	char*	BERコード
//==============================================================
const	char*	ASN1::Get_BERcode(void){
	return(strBER.c_str());
};
//==============================================================
//		BERコードのサイズ取得
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//			const	char*	BERコード
//==============================================================
unsigned	int	ASN1::Get_BERsize(void){
	return(strBER.size());
};
