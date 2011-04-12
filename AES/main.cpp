// AES.cpp : �R���\�[�� �A�v���P�[�V�����̃G���g�� �|�C���g���`���܂��B
//

#include "stdafx.h"

//�Í������p�o�b�t�@
#define	AES_Buff_Block	(2048/AES_BlockSize)		//128*16 = 2048

//==============================================================
//			16�i�� ���l�\��
//--------------------------------------------------------------
//	������
//			int		n		�\��Byte��
//			void	*Data	�\������z��[Byte�P��]
//	���Ԓl
//			����
//==============================================================
void	errPrint(const char *strFile, const char *strMSG)
{
	cout	<<	strFile	<<	strMSG	<<	endl;
	exit(EXIT_FAILURE);
}
//==============================================================
//			16�i�� ���l�\��
//--------------------------------------------------------------
//	������
//			int		n		�\��Byte��
//			void	*Data	�\������z��[Byte�P��]
//	���Ԓl
//			����
//==============================================================
void	dataPrint(int n, void *Data)
{
	unsigned	char*	cData	= (unsigned char*)Data;
				int		i		= 0;

	cout	<<	setfill('0')	<<	hex;
	while(i<n){
		cout	<<	setw(2)	<<	(int)cData[i]	<<	" ";
		i++;
	}
	cout	<<	dec	<<	endl;
}
//==============================================================
//			16�i�� ���l�\��
//--------------------------------------------------------------
//	������
//			int		n		�\��DWORD��
//			void	*Data	�\������z��[DWORD�P��]
//	���Ԓl
//			����
//==============================================================
void	dataPrint32(int n, void *Data)
{
	unsigned	int*	cData	= (unsigned int*)Data;
				int		i		= 0;

	cout	<<	setfill('0')	<<	hex;
	while(i<n){
		cout	<<	setw(8)	<<	cData[i]	<<	" ";
		i++;
	}
	cout	<<	dec	<<	endl;

}
//==============================================================
//			get process
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			__int64		�v���Z�X����
//==============================================================
__int64	ReadTSC()
{
	__asm{
		cpuid
		rdtsc
	}
}
//==============================================================
//			�Í��������[�`��
//--------------------------------------------------------------
//	������
//			OPSW* cOpsw	�I�v�V�����X�C�b�`
//	���Ԓl
//			����
//==============================================================
void	encrypt(OPSW* cOpsw)
{
	//PKCS#7 �̍\����`
	static	const	unsigned	int		oid_PKCS7_1[]	= {1,2,840,113549,1,7,1};
	ObjectIdentifier*					_contentType	= new ObjectIdentifier((unsigned int*)oid_PKCS7_1, sizeof(oid_PKCS7_1)/sizeof(unsigned int));

	//�ϐ�
	unsigned	__int64	cycles = ReadTSC();		//�v���O�����N�����̃N���b�N��

	unsigned	int		i,n;					//�J�E���g�p
	unsigned	int		ptPadding;
	unsigned	char	cPadData;
	unsigned	char	cntPadData;

				int		cAESmode;				//�Í����p���[�h
	__m128i				IV;						//init vector


//�Í���
union {
		unsigned	char	c[32];
					__m128i	xmm[2];
} __declspec(align(16)) Key;					//�Í���

//�����̎�
union {
	unsigned	int		i[4];
	unsigned	__int64	i64[2];
} __declspec(align(16)) randSeed;				//�����̎�

union {
	unsigned	char	c[	(AES_BlockSize*AES_Buff_Block)];
				__m128i	xmm[(AES_BlockSize*AES_Buff_Block/sizeof(__m128i))];
} static __declspec(align(16)) cBuff;

		SHA256*				cSHA	= new	SHA256();				//SHA�n�b�V��
		MT_SHA*				cMT;									//MT����
static	AES					cAES;									//AES�Í�����
		FileInput*			f_IN	= new FileInput(cOpsw->strBINname.c_str());				//�t�@�C�����͗p
		PKCS7_6_Output*		f_OUT	= new PKCS7_6_Output(cOpsw->strAESname.c_str());		//�t�@�C���o�͗p

union{
		PKCS8_Input*		i;		//����
		PKCS8_Output*		o;		//�o��	
} f_KEY;

	//==========================
	//�����J�n
	cout	<<	"Now enciphering..."	<<	endl;

	//------------------
	//������������
	//�i�t�@�C���ǂݍ��݂ɂ����������Ԃ��A�����̎�j
	randSeed.i64[0] = cycles;
	randSeed.i64[1] = ReadTSC();
	cMT	= new MT_SHA((unsigned long *)randSeed.i, sizeof(randSeed)/sizeof(int), cSHA);		//MT��������

	//------------------
	//��������AIV(Init vector)�𐶐�
	IV	= cMT->get__m128i();		//128bit���A�����x�N�g��IV�ɂ���

	//------------------
	//���̏���
	cAESmode = cOpsw->iMode;

	if(cAESmode == -1){
		//���t�@�C���w��H
		f_KEY.i = new PKCS8_Input(cOpsw->strKEYname.c_str());
		f_KEY.i->Get_PrivateKeyInfo();
		cAESmode = cAES.Check_OID(&f_KEY.i->Algorithm);
		cAES.Set_AES(cAESmode, IV);			//�Í����p���[�h, �������x�N�^IV ���A�ݒ�	
		f_KEY.i->Get_PrivateKey(Key.c, cAES.Nk*4);
		f_KEY.i->close();
		delete f_KEY.i;
	} else {
		cAES.Set_AES(cAESmode, IV);			//�Í����p���[�h, �������x�N�^IV ���A�ݒ�
		if(cOpsw->strKeyWord.empty()==true){
			//���͗�����莩������
			cMT->get256(&Key.c);
			f_KEY.o = new PKCS8_Output(cOpsw->strKEYname.c_str());
			f_KEY.o->Set(&cAES, (char *)Key.c, (cAES.Nk*4));
			f_KEY.o->encodeBER_to_File();
			f_KEY.o->close();
			delete f_KEY.o;
		} else {
			//�L�[���[�h������ꍇ�B
			//������̃n�b�V���l���A�Í����p�̔z��ϐ��ɓ����B
			cSHA->CalcHash(Key.c, (void *)cOpsw->strKeyWord.c_str(), cOpsw->strKeyWord.length());
		}
	}

	//�����́A�����g��Ȃ��B
	delete	cMT;
	delete	cSHA;

	//------------------
	//�Í�����ݒ�
	cAES.Set_Key(Key.c);				//�Í�����ݒ�
	Key.xmm[0] = _mm_setzero_si128();	//�Z�L�����e�B�[�΍�
	Key.xmm[1] = _mm_setzero_si128();	//�N���X���Í����ŏ�����������A�Í������O�N���A

	//------------------
	//PKCS#7-6 �̍\�����t�@�C���o��
	i = f_IN->GetSize();			//�����̃t�@�C���T�C�Y
	f_OUT->Set_EncryptedData(_contentType, &cAES, (i & -16) + 16);
	f_OUT->write_header();

	delete	_contentType;		//�t�@�C���ɏo�͂����̂ŁA��������Ȃ��B

	//------------------
	//�ϊ�
	do{
		//�������ׁ̈A������x�ǂݍ���ŁA��C�ɈÍ�����������B
		f_IN->read((char *)cBuff.c, AES_BlockSize * AES_Buff_Block);

		if(i > AES_BlockSize * AES_Buff_Block){
			n = 0;
			while(n < AES_Buff_Block){
				cAES.encrypt(&cBuff.xmm[n]);
				n++;
			}
			f_OUT->write((char *)cBuff.c, AES_BlockSize * AES_Buff_Block);
			i -= AES_BlockSize * AES_Buff_Block;

		} else {
			n = 0;
			while(i >= AES_BlockSize){
				cAES.encrypt(&cBuff.xmm[n]);
				n++;
				i -= AES_BlockSize;
			}

			//Padding����(PKCS#7)�����{
			if(n >= AES_Buff_Block){
				f_OUT->write((char *)cBuff.c, AES_BlockSize * AES_Buff_Block);			
				n = 0;
				f_IN->read((char *)cBuff.c, AES_BlockSize * 1);
			}
	
			ptPadding	= i;
			cPadData	= AES_BlockSize - i;
			cntPadData	= cPadData;
			do{
				cBuff.c[n * AES_BlockSize + ptPadding] = cPadData;
				ptPadding++;
				cntPadData--;
			} while(cntPadData>0);
			if(i == AES_BlockSize){
				cAES.encrypt(&cBuff.xmm[n]);
				n++;
			}
			cAES.encrypt(&cBuff.xmm[n]);
			n++;
			f_OUT->write((char *)&cBuff.xmm[0], n * AES_BlockSize);
			break;
		}

	} while(1);

	f_IN->close();
	f_OUT->close();

	delete	f_IN;
	delete	f_OUT;
	
}
//==============================================================
//			�����������[�`��
//--------------------------------------------------------------
//	������
//			OPSW* cOpsw	�I�v�V�����X�C�b�`
//	���Ԓl
//			����
//==============================================================
void	decrypt(OPSW* cOpsw)
{

	unsigned	int		i,n;					//�J�E���g�p
	unsigned	int		ptPadding;
	unsigned	char	cPadData;
	unsigned	char	cntPadData;

				int		cAESmode;				//�Í����p���[�h
	__m128i				IV;						//init vector

//�Í���
union {
		unsigned	char	c[32];
					__m128i	xmm[2];
} __declspec(align(16)) Key;					//�Í���

//�Í������p�o�b�t�@
union {
	unsigned	char	c[	(AES_BlockSize*AES_Buff_Block)];
				__m128i	xmm[(AES_BlockSize*AES_Buff_Block/sizeof(__m128i))];
} static __declspec(align(16)) cBuff;

		SHA256*	cSHA	= new	SHA256();				//SHA�n�b�V��
static	AES		cAES;									//AES�Í�����

	PKCS7_6_Input*		f_IN	= new PKCS7_6_Input(cOpsw->strAESname.c_str());		//�t�@�C�����͗p
	FileOutput*			f_OUT	= new FileOutput(cOpsw->strBINname.c_str());		//�t�@�C���o�͗p

union{
	PKCS8_Input*		i;		//����
	PKCS8_Output*		o;		//�o��	
} f_KEY;

	//==========================
	//�����J�n
	cout	<<	"Now deciphering..."	<<	endl;

	//------------------
	//�Í��t�@�C����ASN.1�\������

	//�Í����R���e���c�̃T�C�Y�擾
	f_IN->Get_EncryptedData();

	//�Í��A���S���Y���E�p�����[�^�̎擾
	cAESmode = cAES.Check_OID(&f_IN->Algorithm);
	if(cAESmode == -1){
		errPrint(cOpsw->strAESname.c_str(),": Unknown encryption algorithm.");
	}
	f_IN->StreamPointerMove_AlgorithmPara();
	if(sizeof(IV) != f_IN->read_TAG_with_Check(BER_Class_General, false, BER_TAG_OCTET_STRING)){
		errPrint(cOpsw->strAESname.c_str(),": Initialize Vector(IV) is not found.");
	};
	f_IN->read((char *)&IV, sizeof(IV));

	cAES.Set_AES(cAESmode, IV);			//�Í����p���[�h, �������x�N�^IV ���A�ݒ�

	//------------------
	//�Í����̏���

	//���t�@�C��
	if(cOpsw->strKeyWord.empty()==true){
		f_KEY.i = new PKCS8_Input(cOpsw->strKEYname.c_str());
		f_KEY.i->Get_PrivateKey_with_check(&cAES, Key.c, cAES.Nk*4);
		f_KEY.i->close();
		delete f_KEY.i;
	//������̃n�b�V���l
	} else {
		cSHA->CalcHash(Key.c, (void *)cOpsw->strKeyWord.c_str(), cOpsw->strKeyWord.length());
	}

	//�����g��Ȃ��B
	delete	cSHA;

	//------------------
	//�ϊ�
	f_IN->StreamPointerMove_EncryptedContent();
	cAES.Set_Key(Key.c);				//�Í�����ݒ�
	Key.xmm[0] = _mm_setzero_si128();	//�Z�L�����e�B�[�΍�
	Key.xmm[1] = _mm_setzero_si128();	//�N���X���Í����ŏ�����������A�Í������O�N���A

	i = f_IN->szEncryptedContent;
	do {
		//�������ׁ̈A������x�ǂݍ���ŁA��C�ɈÍ�����������B
		f_IN->read((char *)cBuff.c, AES_BlockSize * AES_Buff_Block);

		if(i > AES_BlockSize * AES_Buff_Block){
			n = 0;
			while(n < AES_Buff_Block){
				cAES.decrypt(&cBuff.xmm[n]);
				n++;
			}
			f_OUT->write((char *)cBuff.c, AES_BlockSize * AES_Buff_Block);
			i -= AES_BlockSize * AES_Buff_Block;

		} else {
			n = 0;
			while(i > 0){
				cAES.decrypt(&cBuff.xmm[n]);
				n++;
				i -= AES_BlockSize;
			}

			//�Ō��Block�́APadding���܂ށB
			ptPadding	= n * AES_BlockSize - 1;
			cPadData	= cBuff.c[ptPadding];
			cntPadData	= cPadData;
			//Padding�̃`�F�b�N
			do{
				if(cBuff.c[ptPadding] != cPadData){
					errPrint(cOpsw->strAESname.c_str(),": Decryption error. Key may be different.");
				}
				ptPadding--;
				cntPadData--;
			} while(cntPadData>0);
			//Padding�f�[�^�Ɋ�Â��ăt�@�C���o��
			f_OUT->write((char *)cBuff.c, n * AES_BlockSize - cPadData);
			break;
		}
	} while(1);

	//�t�@�C�������
	f_IN->close();
	f_OUT->close();

	delete	f_IN;
	delete	f_OUT;
}
//==============================================================
//			main routine
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//==============================================================
int __cdecl _tmain(int argc, _TCHAR* argv[])
{

	unsigned	__int64	cycles = ReadTSC();		//�v���O�����N�����̃N���b�N��

	OPSW*	cOpsw	= new OPSW(argc, argv);

	//----------------------------------------------------
	//�����J�n

	if(cOpsw->cDecipher == 0){
		encrypt(cOpsw);		//�Í�
	} else {
		decrypt(cOpsw);		//����	
	}

	delete	cOpsw;

	cout	<<	"Success.\n"
				"Process cycles = "	<<	ReadTSC() - cycles	<<	endl;

	return 0;
}
