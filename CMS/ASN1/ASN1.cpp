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
	szAddValue(0),
	mode(_EXPLICIT)
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
	Clear_Construct();
}
//==============================================================
//		ASN.1オブジェクトの追加
//--------------------------------------------------------------
//	●引数
//			ASN1* asn1		追加するASN.1オブジェクト
//	●返値
//			無し
//==============================================================
void	ASN1::Set_Construct(ASN1* asn1)
{
	Constructed.push_back(asn1);
}

//==============================================================
//		ASN.1オブジェクトの全削除
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
void	ASN1::Clear_Construct()
{
	Constructed.clear();
}

//==============================================================
//		外部データサイズの設定
//--------------------------------------------------------------
//	●引数
//			unsigned int	iSize	外部データのサイズ
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
//			【ＢＥＲエンコード】タグ＆サイズ
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
	const	unsigned	char	cTag = ((fStruct&0x01)<<5) | (cClass<<6);

	if(mode != _IMPLICIT){
		if(iTag <= 30){
			strBER.assign(1,cTag | iTag);
		} else {
			strBER.assign(1,cTag | 31);
			encodeBER_variable(iTag);
		}
		encodeBER_size(iSize);
	}
}
//==============================================================
//			【ＢＥＲエンコード】サイズ
//--------------------------------------------------------------
//	●引数
//		unsigned int iSize		値	（※32bit値までのみ対応）
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
//			【ＢＥＲエンコード】整数値
//--------------------------------------------------------------
//	●引数
//		int		_i		値	（※32bit値までのみ対応）
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
//			【ＢＥＲエンコード】可変長値
//--------------------------------------------------------------
//	●引数
//		unsigned int	_i		値	（※32bit値までのみ対応）
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
//			【ＢＥＲエンコード】メンバー ANS.1オブジェクト
//--------------------------------------------------------------
//	●引数
//		unsigned char	cClass		クラス
//		unsigned int	iTag		タグ
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
//			【ＢＥＲエンコード】
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
//			《ＢＥＲエンコード》符号化後の整数値のサイズを取得
//--------------------------------------------------------------
//	●引数
//						int	_i		整数値
//	●返値
//			unsigned	int			BER符号化された整数値のサイズ
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
//			《ＢＥＲエンコード》符号化後のサイズ値のサイズを取得
//--------------------------------------------------------------
//	●引数
//			unsigned	int	iSize	サイズ値
//	●返値
//			unsigned	int			BER符号化されたサイズ値のサイズ
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
//							無し
//	●返値
//		const	char*		BERコード
//==============================================================
const	char*	ASN1::Get_BERcode(void){
	return(strBER.c_str());
};
//==============================================================
//		BERコードのサイズ取得
//--------------------------------------------------------------
//	●引数
//							無し
//	●返値
//		unsigned	int		BERコードのサイズ
//==============================================================
unsigned	int	ASN1::Get_BERsize(void){
	return(strBER.size());
};
