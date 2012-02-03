#include "StdAfx.h"
#include "PKCS7_Input.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
PKCS7_Input::PKCS7_Input(const char*	strFileName,const char _strName[]):
	BER_Input(strFileName),
	PKCS7(_strName)
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
PKCS7_Input::~PKCS7_Input(void)
{
}
//==============================================================
//		ヘッダー構造チェック
//--------------------------------------------------------------
//	●引数
//			unsigned	char	cType	コンテンツタイプ
//	●返値
//			unsigned	int				コンテンツのサイズ
//==============================================================
unsigned int	PKCS7_Input::read_ContentInfo(unsigned int type)
{
	static	unsigned	int		oid_pkcs7[]	=	{1,2,840,113549,1,7,type};

	//SEQUENCE
	read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);

		//OID
		read_Object_Identifier_with_Check(&contentType, oid_pkcs7, sizeof(oid_pkcs7)/sizeof(int));

		//Content Info
		szAddValue = read_TAG_with_Check(BER_Class_Context, true, 0);

	return(szAddValue);
}
//==============================================================
//		【ファイル読み込み】EnvelopedData
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			unsigned	int					暗号文のポインタ
//==============================================================
unsigned	int	PKCS7_Input::read_EnvelopedData(EnvelopedData* _envelopedData)
{
	unsigned	int	ptEncryptedContent;

	//EnvelopedData
	read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);

		//version
		read_Integer(&_envelopedData->version);
		if(_envelopedData->version.iValue != 3){
			error(0);	//未対応のVersion
		}
		_envelopedData->Set_Construct(&_envelopedData->version);

		//originatorInfo
		

		//recipientInfos
		read_RecipientInfos(&_envelopedData->recipientInfos);

		//encryptedContentInfo
		ptEncryptedContent = read_EncryptedContentInfo(&_envelopedData->encryptedContentInfo);
		//暗号モジュールのポインタを取得しておく。
	//	cCE = _envelopedData->encryptedContentInfo.contentEncryptionAlgorithm;

	//------
	//処理
	context.Set_Construct(_envelopedData);		//ContentInfoクラスのmember

	return(ptEncryptedContent);
}
//==============================================================
//		ヘッダー構造チェック
//--------------------------------------------------------------
//	●引数
//			
//	●返値
//			unsigned	int					暗号文のポインタ
//==============================================================
unsigned	int	PKCS7_Input::read_EncryptedData(EncryptedData* _encryptedData)
{
	unsigned	int	ptEncryptedContent;

	//EncryptedData
	read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);

		//version
		read_Integer(&_encryptedData->version);
		if(_encryptedData->version.iValue != 0){
			error(0);	//未対応のVersion
		}
		_encryptedData->Set_Construct(&_encryptedData->version);

		//encryptedContentInfo
		ptEncryptedContent = read_EncryptedContentInfo(&_encryptedData->encryptedContentInfo);
		//暗号モジュールのポインタを取得しておく。
	//	cCE = _encryptedData->encryptedContentInfo.contentEncryptionAlgorithm;

	//------
	//処理
	context.Set_Construct(_encryptedData);		//ContentInfoクラスのmember

	return(ptEncryptedContent);
}
//==============================================================
//		【ファイル読み込み】RecipientInfos
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
void	PKCS7_Input::read_RecipientInfos(RecipientInfos* _recipientInfos)
{
	unsigned	int		ptTemp;				//ファイルポインタ一次保存用

	unsigned	int		read_tag;			//ASN.1 タグ
	unsigned	char	read_class;			//ASN.1 クラス
				bool	read_fStruct;		//ASN.1 構造化
	unsigned	int		iSize;				//ASN.1 サイズ

	//----------
	//"SET RecipientInfo"でなくなるまで繰り返す。
	while(1){
		//現在のファイルポインタを取得
		ptTemp = tellg();

		//RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
		iSize = read_TAG(&read_class, &read_fStruct, &read_tag);
		//SETでなかったら、ポインターを戻して終了
		if((read_class != BER_Class_General)||(read_tag != BER_TAG_SET)||(read_fStruct != true)){
			StreamPointerMove(ptTemp);
			break;
		}
		
		//RecipientInfo ::= CHOICE {
		iSize = read_TAG(&read_class, &read_fStruct, &read_tag);
		switch(read_class){
			//[SEQUENCE]	ktri KeyTransRecipientInfo
			case(BER_Class_General):
			//	Get_KeyTransRecipientInfo();
				StreamPointerAdd(iSize);
				break;
			//[CONTEXT]		
			case(BER_Class_Context):
				switch(read_tag){
					//pwri [3] PasswordRecipientinfo
					case(3):
						read_PasswordRecipientInfo(&_recipientInfos->cPassword);
						break;
					default:
						StreamPointerAdd(iSize);
						break;
				}
				break;
			default:
				errPrint("RecipientInfos",": 未対応");
				break;
		}
	}
}

//==============================================================
//		【ファイル読み込み】PasswordRecipientinfo
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
void	PKCS7_Input::read_PasswordRecipientInfo(PasswordRecipientInfo* _passwordRecipientInfo)
{
	KeyDerivation*			_keyDerivation;
	Encryption*				_keyEncryption;

	//version CMSVersion,   -- Always set to 0
	read_Integer(&_passwordRecipientInfo->version);
	if(_passwordRecipientInfo->version.iValue != 0){
		errPrint("PasswordRecipientinfo",": 未対応のVersion");
	}

	//keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier OPTIONAL,
	_keyDerivation = read_KeyDerivationAlgorithm();

	//keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
	read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);

		//■ to do

	_passwordRecipientInfo->SetInfo(_keyDerivation, _keyEncryption);

	//encryptedKey EncryptedKey }
	read_Octet_Strings(&_passwordRecipientInfo->EncryptedKey);
}

//==============================================================
//		【ファイル読み込み】EncryptedContentInfo
//--------------------------------------------------------------
//	●引数
//			EncryptedContentInfo*	ECinfo	読み込み内容を格納するオブジェクトのポインタ
//	●返値
//			unsigned	int					暗号文のポインタ
//==============================================================
unsigned	int		PKCS7_Input::read_EncryptedContentInfo(EncryptedContentInfo*	ECinfo)
{
	//contentType ContentType,
	ObjectIdentifier		contentType;					//暗号文のType
	Encryption*				cCE;
	unsigned	int			szEncryptedContent;

	//encryptedContentInfo
	read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);

		//contentType 
		read_Object_Identifier(&contentType);

		//contentEncryptionAlgorithm
		cCE = read_ContentEncryptionAlgorithm();

		//ここに入っているのが、暗号文実体のサイズ
		szEncryptedContent	= read_TAG_with_Check(BER_Class_Context, false, 0);

	//EncryptedContentInfoを設定
	ECinfo->Set(&contentType, cCE, szEncryptedContent);
	return(tellg());
}
//==============================================================
//		【ファイル読み込み】コンテンツ用暗号モジュールの取得
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			Encryption*				暗号モジュールのポインタ
//==============================================================
Encryption*	PKCS7_Input::read_ContentEncryptionAlgorithm()
{
	//contentType ContentType,
	ObjectIdentifier		oid_algCE;

	OctetString		_IV;
	__m128i			IV;

	Encryption*	cCE;

	//EncryptionAlgorithm
	//SEQUENCE
	read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);
		//algorithm OBJECT IDENTIFIER
		read_Object_Identifier(&oid_algCE);
		//暗号利用モード, 初期化ベクタIV を、設定
		//追加の暗号アルゴリズムがある場合は、ここに追加。
		if(cDES_CBC.Check_OID(&oid_algCE) != -1){
			read_Octet_Strings(&_IV);
			memcpy(&IV, _IV.strValue.c_str(), sizeof(__int64));
			cDES_CBC.Set_DES(IV.m128i_i64[0]);
			cCE = &cDES_CBC;
		} else if(cTDES_CBC.Check_OID(&oid_algCE) != -1){
			read_Octet_Strings(&_IV);
			memcpy(&IV, _IV.strValue.c_str(), sizeof(__int64));
			cTDES_CBC.Set_DES(IV.m128i_i64[0]);
			cCE = &cTDES_CBC;
		} else if(cAES_CBC128.Check_OID(&oid_algCE) != -1){
			read_Octet_Strings(&_IV);
			memcpy(&IV, _IV.strValue.c_str(), sizeof(__m128i));
			cAES_CBC128.Set_AES(IV);
			cCE = &cAES_CBC128;
		} else if(cAES_CBC192.Check_OID(&oid_algCE) != -1){
			read_Octet_Strings(&_IV);
			memcpy(&IV, _IV.strValue.c_str(), sizeof(__m128i));
			cAES_CBC192.Set_AES(IV);
			cCE = &cAES_CBC192;
		} else if(cAES_CBC256.Check_OID(&oid_algCE) != -1){
			read_Octet_Strings(&_IV);
			memcpy(&IV, _IV.strValue.c_str(), sizeof(__m128i));
			cAES_CBC256.Set_AES(IV);
			cCE = &cAES_CBC256;
		} else {
			errPrint("contentEncryptionAlgorithm",": Unknown encryption algorithm.");
		}

		if(cCE->szBlock != _IV.strValue.size()){
			errPrint("contentEncryptionAlgorithm",": Different Parameter size.");
		}

	return(cCE);
}
//==============================================================
//		【ファイル読み込み】ハッシュ関数の取得
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			HMAC*				ハッシュ関数のポインタ
//==============================================================
HMAC*	PKCS7_Input::read_HmacAlgorithm()
{
	//contentType ContentType,
	ObjectIdentifier		_oid;

	HMAC*					cHMAC;

	//HMAC Algorithm
	//SEQUENCE
	read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);
		//algorithm OBJECT IDENTIFIER
		read_Object_Identifier(&_oid);
		if(cHMAC_SHA1.Check_OID(&_oid) != -1){
			cHMAC = &cHMAC_SHA1;
			read_TAG_with_Check(BER_Class_General, false, BER_TAG_NULL);
		} else if(cHMAC_SHA224.Check_OID(&_oid) != -1){
			cHMAC = &cHMAC_SHA224;
			read_TAG_with_Check(BER_Class_General, false, BER_TAG_NULL);
		} else if(cHMAC_SHA256.Check_OID(&_oid) != -1){
			cHMAC = &cHMAC_SHA256;
			read_TAG_with_Check(BER_Class_General, false, BER_TAG_NULL);
		} else {
			errPrint("HmacAlgorithm",": Unknown HMAC algorithm.");
		}

	return(cHMAC);
}
//==============================================================
//		【ファイル読み込み】鍵導出関数の取得
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			HMAC*				鍵導出関数のポインタ
//==============================================================
KeyDerivation*		PKCS7_Input::read_KeyDerivationAlgorithm()
{
	unsigned	int		ptTemp;				//ファイルポインタ一次保存用

	unsigned	int		read_tag;			//ASN.1 タグ
	unsigned	char	read_class;			//ASN.1 クラス
				bool	read_fStruct;		//ASN.1 構造化
	unsigned	int		iSize;				//ASN.1 サイズ

	static	PBKDF2	_pbkdf2	=	PBKDF2(&cHMAC_SHA256);
	PBKDF2*					_pbkdf;
	HMAC*					cHMAC;

	//contentType ContentType,
	ObjectIdentifier		_oid;

	//※keyDerivationは、クラス"PasswordRecipientInfo"でメモリ開放を行う。
	KeyDerivation*			_keyDerivation;

	OctetString	_Salt;
	Integer		_Count;
	Integer		_dkLen;

	read_TAG_with_Check(BER_Class_Context, true, 0);
		//algorithm OBJECT IDENTIFIER
		read_Object_Identifier(&_oid);
		if(_pbkdf2.Check_OID(&_oid) != -1){
			//PBKDF2-params ::= SEQUENCE {
			read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);
				//salt	pecified OCTET STRING
				read_Octet_Strings(&_Salt);
				//iterationCount INTEGER (1..MAX)
				read_Integer(&_Count);
				//keyLength INTEGER (1..MAX) OPTIONAL
				ptTemp = tellg();
				iSize = read_TAG(&read_class, &read_fStruct, &read_tag);
				StreamPointerMove(ptTemp);
				if((read_class == BER_Class_General)&&(read_tag == BER_TAG_INTEGER)&&(read_fStruct == false)){
					read_Integer(&_dkLen);
				} else {
					_dkLen.Set(0);
				}
				//prf AlgorithmIdentifier {{PBKDF2-PRFs}}
				ptTemp = tellg();
				iSize = read_TAG(&read_class, &read_fStruct, &read_tag);
				StreamPointerMove(ptTemp);
				if((read_class != BER_Class_General)||(read_tag != BER_TAG_SEQUENCE)||(read_fStruct != true)){
					//DEFAULT algid-hmacWithSHA1
					cHMAC = &cHMAC_SHA1;
				} else {
					cHMAC = read_HmacAlgorithm();
				}
			_pbkdf = new PBKDF2(cHMAC);
			//■ to do 鍵長が不明な場合も考慮する。
			_pbkdf->Set_PBKDF2((void *)_Salt.strValue.c_str(), _Salt.strValue.size(), _Count.iValue, _dkLen.iValue);
		} else {
			errPrint("KeyDerivationAlgorithm",": Unknown KeyDerivationAlgorithm algorithm.");
		}
	return(_keyDerivation);
}
