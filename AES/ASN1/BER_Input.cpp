#include "StdAfx.h"
#include "BER_Input.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
BER_Input::BER_Input(const char*	strFileName):
	FileInput(strFileName)
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
BER_Input::~BER_Input(void)
{
}

//==============================================================
//		エラー処理
//--------------------------------------------------------------
//	●引数
//				unsigned int iEer	エラーコード
//	●返値
//				無し
//==============================================================
void	BER_Input::DecodeError(unsigned int iEer)
{
	static	const	char*	const	msg_err[2]={
		"Different Struct.",		//0x00: 構造が違う。
	};

	errPrint("ASN.1 BER Decode Error :", msg_err[iEer]);
}

//==============================================================
//		整数値読み込み
//--------------------------------------------------------------
//	●引数
//			unsigned int	iSize	整数値のサイズ[Byte]
//	●返値
//			unsigned int			数値
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
//		整数値読み込み
//--------------------------------------------------------------
//	●引数
//			unsigned int	iSize	整数値のサイズ[Byte]
//	●返値
//			unsigned int			数値
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
//		可変長値読み込み
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				unsigned int	数値
//==============================================================
unsigned int	BER_Input::read_variable(void)
{
	//----------------------------------
	//■Local 変数
	unsigned	int			iData=0;		//読み込んだ可変長数値
	unsigned	int			count=9;		//読み込み回数カウント用
	unsigned	char		cData;			//読み込み用変数

	//----------------------------------
	//■デルタタイム読み込み
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
//	●引数
//				*cClass		戻り値用のポインタ	クラス
//				*fStruct	戻り値用のポインタ	構造化フラグ
//				*iTag		戻り値用のポインタ	タグ
//	●返値
//				無し
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
//		タグ読み込み
//--------------------------------------------------------------
//	●引数		（チェック用）
//				cClass		クラス
//				fStruct		構造化フラグ
//				iTag		タグ
//	●返値
//				サイズ
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
//	●引数
//			無し
//	●返値
//			読み込んだ数値
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
//	●引数
//			ObjectIdentifier*	oid		読み込んだoidを入れるobjectのポインタ
//	●返値
//			unsigned int		サイズ
//==============================================================
unsigned int	BER_Input::read_Object_Identifier(ObjectIdentifier* oid)
{
		const		int		iSize	= read_TAG_with_Check(BER_Class_General, false, BER_TAG_OBJECT_IDENTIFIER);
		const		int		ptPos	= iSize + tellg();
		const		int		n		= read_variable();
	vector<unsigned int>	iData;

	//OID読み込み
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
//	●引数
//			ObjectIdentifier*	oid		読み込んだoidを入れるobjectのポインタ
//			unsigned	int		iData[]	照合するoidの実体
//			unsigned	int		szData	照合するoidのサイズ
//	●返値
//			unsigned int		サイズ
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
//	●引数
//			無し
//	●返値
//			unsigned int	サイズ
//==============================================================
unsigned int	BER_Input::read_Octet_Strings(void)
{
	return(read_TAG_with_Check(BER_Class_General, false, BER_TAG_OCTET_STRING));
}
