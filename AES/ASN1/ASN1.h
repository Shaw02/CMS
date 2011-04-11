#pragma once

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
//Class
#define	BER_Class_General			0
#define	BER_Class_Application		1
#define	BER_Class_Context			2
#define	BER_Class_Private			3

//TAG
#define	BER_TAG_EOC					0x00
#define	BER_TAG_BOOLEAN				0x01
#define	BER_TAG_INTEGER				0x02
#define	BER_TAG_BIT_STRING			0x03
#define	BER_TAG_OCTET_STRING		0x04
#define	BER_TAG_NULL				0x05
#define	BER_TAG_OBJECT_IDENTIFIER	0x06
#define	BER_TAG_ObjectDescriptor	0x07
#define	BER_TAG_EXTERNAL			0x08
#define	BER_TAG_REAL				0x09
#define	BER_TAG_ENUMERATED			0x0A
#define	BER_TAG_EMBEDDED_PDV		0x0B
#define	BER_TAG_UTF8String			0x0C
#define	BER_TAG_RELATIVE_OID		0x0D
//0x0E
//0x0F
#define	BER_TAG_SEQUENCE			0x10
#define	BER_TAG_SET					0x11
#define	BER_TAG_NumericString		0x12
#define	BER_TAG_PrintableString		0x13
#define	BER_TAG_TeletexString		0x14
#define	BER_TAG_VideotexString		0x15
#define	BER_TAG_IA5String			0x16
#define	BER_TAG_UTCTime				0x17
#define	BER_TAG_GeneralizedTime		0x18
#define	BER_TAG_GraphicString		0x19
#define	BER_TAG_VisibleString		0x1A
#define	BER_TAG_GeneralString		0x1B
#define	BER_TAG_UniversalString		0x1C
#define	BER_TAG_CharacterString		0x1D
#define	BER_TAG_BMPString			0x1E
//0x1F

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class ASN1
{
public:
//--------------
//変数
	const		char*	strName;		//OBJECTの名前
				string	strBER;			//BER用のバッファ

	vector<ASN1*>		Constructed;	//構造化する場合
	unsigned	int		szAddValue;

//--------------
//関数

						ASN1(const char _strName[]="");
						~ASN1(void);


						void	Set_Construct(ASN1* asn1);
						void	Set_ExternalDataSize(unsigned int iSize);
						int		Get_ExternalDataSize(void){return(szAddValue);}	//

						//BER Encode用
						void	error(unsigned int iEer);

						void	encodeBER_TAG(	unsigned	char	cClass,
															bool	fStruct,
												unsigned	int		iTag,
												unsigned	int		iSize);
						void	encodeBER_size(unsigned int iSize);
						void	encodeBER_int(int _i);
						void	encodeBER_variable(unsigned int _i);
						void	encodeBER_Constructed(unsigned char cClass, unsigned int iTag);
	virtual				void	encodeBER();					//BERコード生成

	virtual	const		char*	Get_BERcode(void);				//BERコード取得
	virtual	unsigned	int		Get_BERsize(void);				//BERサイズ取得
			unsigned	int		Get_szInt_for_BER(int _i);	
			unsigned	int		Get_szSize_for_BER(unsigned int iSize);

};
