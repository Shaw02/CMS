// AES.cpp : �R���\�[�� �A�v���P�[�V�����̃G���g�� �|�C���g���`���܂��B
//

#include "stdafx.h"

/****************************************************************/
/*			�萔��`											*/
/****************************************************************/
//�Í������p�o�b�t�@
//#define	Encrypt_Buff	(65536/AES_BlockSize)		//4096*16 = 65536
#define	Encrypt_Buff		65536

/****************************************************************/
/*			�O���[�o�X�ϐ��i�N���X�j							*/
/****************************************************************/
		OPSW*			cOpsw;			//�I�v�V�����X�C�b�`

		//�^���������W���[��
		MT_SHA*			cRandom;		//Mersenne Twister with SHA-256

/****************************************************************/
/*			�֐�												*/
/****************************************************************/
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
extern "C"	void	dataPrint(int n, void *Data)
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
extern "C"	void	dataPrint32(int n, void *Data)
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
//			�Í��������[�`��
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//==============================================================
void	encrypt()
{
	//PKCS#7 �̍\����`
	static	const	unsigned	int		oid_PKCS7_1[]	= {1,2,840,113549,1,7,1};
	static	ObjectIdentifier			contentType	= ObjectIdentifier((unsigned int*)oid_PKCS7_1, sizeof(oid_PKCS7_1)/sizeof(unsigned int));

	//�ϐ�
	static	FileInput*			f_IN	= new FileInput(cOpsw->strBINname.c_str());				//�t�@�C�����͗p

	union{
		PKCS7_3_Output*	t3;
		PKCS7_6_Output*	t6;
	} f_OUT;

	union{
		PKCS8_Input*	i;
		PKCS8_Output*	o;
	} f_KEY;

	//==========================
	//�����J�n
	cout	<<	"Now enciphering..."	<<	endl;

	//------------------
	//�Í������Í��t�@�C���̍쐬
	switch(cOpsw->iType){
		//------------------
		//Enveloped Data Type
		case(3):
			// �Í��t�@�C���E�I�u�W�F�N�g�̍쐬
			f_OUT.t3 = new PKCS7_3_Output(cOpsw->strAESname.c_str());
			// (1) �Í����W���[�� �� �Z�b�V�������i�����j�̏���
			f_OUT.t3->MakeEncryption(cOpsw->iMode);
			// (2) ��M�ҏ��̃Z�b�g�i����́A�����o�i�p�X���[�h�j�̂ݑΉ��j
			f_OUT.t3->AddRecipient(&cOpsw->strKeyWord, cOpsw->iCount, cOpsw->iMode);
			// (3) �Í����i�t�@�C���o�͍��݁j
			f_OUT.t3->encrypt(f_IN, &contentType);
			// �Í��t�@�C���E�I�u�W�F�N�g�̊J��
			delete f_OUT.t3;
			break;

		//------------------
		//Encrypted Data Type
		case(6):
			// �Í��t�@�C���E�I�u�W�F�N�g�̍쐬
			f_OUT.t6 = new PKCS7_6_Output(cOpsw->strAESname.c_str());
			if(cOpsw->iMode == -1){
					//----------
					//�Í����t�@�C���ŁA�g�p����Í����W���[�����Í�����ݒ肷��
					f_KEY.i = new PKCS8_Input(cOpsw->strKEYname.c_str());
					f_OUT.t6->Set_Encryption(f_KEY.i);
					delete f_KEY.i;
			} else {
				if(cOpsw->strKeyWord.empty()==true){
					//----------
					//�������Í����ɂ��āA���t�@�C���ɕۑ�����B
					f_KEY.o = new PKCS8_Output(cOpsw->strKEYname.c_str());
					f_OUT.t6->Set_Encryption(f_KEY.o, cOpsw->iMode);
					delete f_KEY.o;
				} else {
					//----------
					//�p�X���[�h��SHA-256�n�b�V���l���A�Í����𐶐�����B
					f_OUT.t6->Set_Encryption(&cOpsw->strKeyWord, cOpsw->iMode);
				}
			}
			// �Í����i�t�@�C���o�͍��݁j
			f_OUT.t6->encrypt(f_IN, &contentType);
			// �Í��t�@�C���E�I�u�W�F�N�g�̊J��
			delete f_OUT.t6;
			break;
		//------------------
		//���̑�
		default:
			errPrint("","undefined type.");
			break;
	}

	//------------------
	//�I��
	delete	f_IN;

}
//==============================================================
//			�����������[�`��
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//==============================================================
void	decrypt()
{
	//�ϐ�
//	unsigned	int	iType	= 6;		//PKCS#7�̃^�C�v

	static	FileOutput*			f_OUT	= new FileOutput(cOpsw->strBINname.c_str());		//�t�@�C���o�͗p

	union{
		PKCS7_3_Input*	t3;
		PKCS7_6_Input*	t6;
	} f_IN;

	PKCS8_Input*	f_KEY;

	//==========================
	//�����J�n
	cout	<<	"Now deciphering..."	<<	endl;

	//------------------
	//�^�C�v�ɉ����ĕ���

	//�� to do	PKCS#7���ǂ��� �� �^�C�v�̃`�F�b�N

	switch(cOpsw->iType){
		//------------------
		//Enveloped Data Type
		case(3):
			//�Í��t�@�C���̓ǂݍ��� �� ASN.1�\������
			f_IN.t3	= new PKCS7_3_Input(cOpsw->strAESname.c_str());
			f_IN.t3->Get_EnvelopedData();
			// ��M�ҏ��̏ƍ�
			f_IN.t3->Receipt(&cOpsw->strKeyWord);
			// �Í����i�t�@�C���o�͍��݁j
			f_IN.t3->decrypt(f_OUT);
			// �Í��t�@�C���E�I�u�W�F�N�g�̊J��
			delete f_IN.t3;
			break;
		//------------------
		//Encrypted Data Type
		case(6):
			//�Í��t�@�C���̓ǂݍ��� �� ASN.1�\������
			f_IN.t6	= new PKCS7_6_Input(cOpsw->strAESname.c_str());
			f_IN.t6->Get_EncryptedData();
			if(cOpsw->strKeyWord.empty()==true){
				//----------
				//�Í����t�@�C���ŁA�Í�����ݒ肷��
				f_KEY = new PKCS8_Input(cOpsw->strKEYname.c_str());
				f_IN.t6->Set_Encryption(f_KEY);
				delete f_KEY;
			} else {
				//----------
				//�p�X���[�h��SHA-256�n�b�V���l���A�Í����𐶐�����B
				f_IN.t6->Set_Encryption(&cOpsw->strKeyWord);
			}
			// �Í����i�t�@�C���o�͍��݁j
			f_IN.t6->decrypt(f_OUT);
			// �Í��t�@�C���E�I�u�W�F�N�g�̊J��
			delete f_IN.t6;
			break;
		//------------------
		//���̑�
		default:
			errPrint("","undefined type.");
			break;
	}

	//------------------
	//�I��
	delete	f_OUT;

}
//==============================================================
//			main routine
//--------------------------------------------------------------
//	������
//		int			argc		�R�}���h���C���@�I�v�V������
//		_TCHAR*		argv[]		�R�}���h���C���@������
//	���Ԓl
//			����
//==============================================================
int __cdecl _tmain(int argc, _TCHAR* argv[])
{

	unsigned	__int64	cycles = __rdtsc();		//�v���O�����N�����̃N���b�N��

#ifdef	_DEBUG

	static	const	char	iKey128[]={	0x2b, 0x7e, 0x15, 0x16, 
										0x28, 0xae, 0xd2, 0xa6, 
										0xab, 0xf7, 0x15, 0x88, 
										0x09, 0xcf, 0x4f, 0x3c};

	static	const	char	iKey192[]={	0x8e, 0x73, 0xb0, 0xf7, 
										0xda, 0x0e, 0x64, 0x52, 
										0xc8, 0x10, 0xf3, 0x2b, 
										0x80, 0x90, 0x79, 0xe5, 
										0x62, 0xf8, 0xea, 0xd2, 
										0x52, 0x2c, 0x6b, 0x7b};

	static	const	char	iKey256[]={	0x60, 0x3d, 0xeb, 0x10,
										0x15, 0xca, 0x71, 0xbe,
										0x2b, 0x73, 0xae, 0xf0,
										0x85, 0x7d, 0x77, 0x81,
										0x1f, 0x35, 0x2c, 0x07,
										0x3b, 0x61, 0x08, 0xd7,
										0x2d, 0x98, 0x10, 0xa3,
										0x09, 0x14, 0xdf, 0xf4};

	AES_CBC128	cENC128;
	AES_CBC192	cENC192;
	AES_CBC256	cENC256;

	printf("----------------\n");
	printf("KeyExp 128\n");
	cENC128.Set_Key((void*)iKey128);

	printf("----------------\n");
	printf("KeyExp 192\n");
	cENC192.Set_Key((void*)iKey192);

	printf("----------------\n");
	printf("KeyExp 256\n");
	cENC256.Set_Key((void*)iKey256);

#else
	
	//�����̎�p
	union {
		unsigned	int		i[4];
		unsigned	__int64	i64[2];
	} __declspec(align(16)) randSeed;

	//------------------
	//�����쐬
	time((time_t*)&randSeed.i64[0]);	//1970�N����́A�o�ߕb��
	randSeed.i64[1] = cycles;			//�d��on����́A�N���b�N��
	cRandom	= new MT_SHA((unsigned long *)randSeed.i, sizeof(randSeed)/sizeof(int));		//MT��������

	//------------------
	//�I�v�V��������
	cOpsw	= new OPSW(argc, argv);


	//------------------
	//�����J�n
	if(cOpsw->cDecipher == 0){
		encrypt();		//�Í�
	} else {
		decrypt();		//����	
	}

	delete	cOpsw;
	delete	cRandom;


#endif

	cout	<<	"Success.\n"
				"Process cycles = "	<<	__rdtsc() - cycles	<<	endl;

	return 0;
}
