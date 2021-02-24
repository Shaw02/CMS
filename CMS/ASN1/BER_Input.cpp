#include "StdAfx.h"
#include "BER_Input.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//		const	char*	BER符号化されたデータファイル
//	●返値
//						無し
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
//		【ＢＥＲデコード】符号付き整数値
//--------------------------------------------------------------
//	●引数
//					size_t	iSize	整数値のサイズ[Byte]
//	●返値
//			unsigned int			数値
//==============================================================
__int64	BER_Input::read_int(size_t iSize)
{
	__int64		iResult	= cRead();

	if(iResult & 0x80){			//負？
		iResult |= 0xFFFFFFFFFFFFFF00;
	}

	iSize--;
	while(iSize>0){
		iResult <<= 8;
		iResult |= cRead();
		iSize--;
	};

	return(iResult);
}
//==============================================================
//		【ＢＥＲデコード】符号無し整数値
//--------------------------------------------------------------
//	●引数
//					size_t	iSize	整数値のサイズ[Byte]
//	●返値
//			unsigned int			数値
//==============================================================
unsigned __int64	BER_Input::read_uint(size_t iSize)
{
	unsigned __int64	iResult = 0;

	do{
		iResult <<= 8;
		iResult |= cRead();
		iSize--;
	} while (iSize>0);

	return(iResult);
}
//==============================================================
//		【ＢＥＲデコード】符号無し整数値
//--------------------------------------------------------------
//	●引数
//					size_t	iSize	整数値のサイズ[Byte]
//	●返値
//					size_t			数値
//==============================================================
size_t	BER_Input::read_size_t(size_t iSize)
{
	size_t	iResult = 0;

	do{
		iResult <<= 8;
		iResult |= cRead();
		iSize--;
	} while (iSize>0);

	return(iResult);
}
//==============================================================
//		【ＢＥＲデコード】可変長値
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
//		【ＢＥＲデコード】タグ読み込み
//--------------------------------------------------------------
//	●引数
//				*cClass		戻り値用のポインタ	クラス
//				*fStruct	戻り値用のポインタ	構造化フラグ
//				*iTag		戻り値用のポインタ	タグ
//	●返値
//				無し（引数で渡されたポインターが示すアドレスに、格納する）
//==============================================================
size_t	BER_Input::read_TAG(unsigned char* cClass, bool* fStruct, unsigned int* iTag)
{
	unsigned	char	cTag = cRead();
				size_t	iSize;

	*cClass		= cTag>>6;
	*fStruct	= (cTag & (0x01<<5))? true : false;
	
	cTag &= 0x1F;

	*iTag = ((cTag <= 30)? cTag : read_variable());

	iSize = cRead();
	if(iSize >= 0x81){
		iSize = read_size_t(iSize & 0x7F);
	}

	return(iSize);
}
//==============================================================
//		【ＢＥＲデコード】タグ読み込み（エラー処理付き）
//--------------------------------------------------------------
//	●引数
//		unsigned	char	cClass		クラス
//		bool				fStruct		構造化フラグ
//		unsigned	int		iTag		タグ
//	●返値
//		unsigned	int		サイズ
//	●処理
//		デコード後、引数で指定された内容と差異があったら、エラー
//==============================================================
size_t	BER_Input::read_TAG_with_Check(unsigned char cClass, bool fStruct, unsigned int iTag)
{
	unsigned	int		read_tag;
	unsigned	char	read_class;
				bool	read_fStruct;
				size_t	iSize;

	iSize = read_TAG(&read_class, &read_fStruct, &read_tag);

	if((read_class != cClass)||(read_tag != iTag)||(fStruct != read_fStruct)){
		DecodeError(0);
	}

	return(iSize);
}
//==============================================================
//			【ＢＥＲデコード】Integer
//--------------------------------------------------------------
//	●引数
//			Integer*	i		整数値を格納するInteger型のASN.1オブジェクトのポインタ
//	●返値
//						size_t	BER符号のサイズ
//==============================================================
size_t	BER_Input::read_Integer(Integer* i)
{
	const	size_t	iSize	= read_TAG_with_Check(BER_Class_General, false, BER_TAG_INTEGER);

	i->Set(read_int(iSize));

	return(iSize);
}
//==============================================================
//			【ＢＥＲデコード】Object Identifier
//--------------------------------------------------------------
//	●引数
//			ObjectIdentifier*	oid		oidを格納するObjectIdentifier型のASN.1オブジェクトのポインタ
//	●返値
//						size_t			BER符号のサイズ
//==============================================================
size_t	BER_Input::read_Object_Identifier(ObjectIdentifier* oid)
{
		const		size_t	iSize	= read_TAG_with_Check(BER_Class_General, false, BER_TAG_OBJECT_IDENTIFIER);
		const		size_t	ptPos	= iSize + tellg();
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
//			【ＢＥＲデコード】Object Identifier（oidチェック付き）
//--------------------------------------------------------------
//	●引数
//			ObjectIdentifier*	oid		oidを格納するObjectIdentifier型のASN.1オブジェクトのポインタ
//			unsigned	int		iData[]	照合するoidの実体
//			unsigned	int		szData	照合するoidのサイズ
//	●返値
//						size_t			BER符号のサイズ
//==============================================================
size_t	BER_Input::read_Object_Identifier_with_Check(
					ObjectIdentifier*	oid,
					unsigned	int		iData[],
								size_t	szData
				)
{
		const	size_t	iSize	= read_Object_Identifier(oid);
				size_t	i		= 0;

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
//			【ＢＥＲデコード】Octet_Strings
//--------------------------------------------------------------
//	●引数
//		OctetString*	_str	Stringsを格納するOctetString型のASN.1オブジェクトのポインタ
//	●返値
//					size_t		BER符号のサイズ
//==============================================================
size_t	BER_Input::read_Octet_Strings(OctetString* _str)
{
	const		size_t	iSize	= read_TAG_with_Check(BER_Class_General, false, BER_TAG_OCTET_STRING);
	
	unsigned	char*	data	= new unsigned char[iSize];

	read((char *)data, iSize);
	_str->Set((char *)data,iSize);
	
	delete	data;

	return(iSize);
}
