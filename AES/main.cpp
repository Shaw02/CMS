// AES.cpp : �R���\�[�� �A�v���P�[�V�����̃G���g�� �|�C���g���`���܂��B
//

#include "stdafx.h"

//==============================================================
//			16�i�� ���l�\��
//--------------------------------------------------------------
//	������
//			int		n		�\��Byte��
//			void	*Data	�\������z��[Byte�P��]
//	���Ԓl
//			����
//==============================================================
void	errPrint(const char *strFile, const char *strMSG){

	printf(strFile);
	printf(strMSG);
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
void	dataPrint(int n, void *Data){

	unsigned char* cData = (unsigned char*)Data;
	int	i=0;
	while(i<n){
		if(((i & 0x0F)==0x00) && (i != 0)){
			printf("\n		 ");
		}
		printf("%02x ",cData[i]);
		i++;
	}
	printf("\n");
}

//==============================================================
//			get process
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//==============================================================
__int64	ReadTSC()
{
	__asm{
		cpuid
		rdtsc
	}
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

#define	strAES	0x00534541

	__declspec(align(16))	unsigned	char	text[16];	//�����p
union {
	__declspec(align(16))	unsigned	char	c[32];
	__declspec(align(16))	unsigned	int		i[8];
} Key;														//�Í���

struct Header{
	unsigned	int		Name;					//�w�b�_�[
	unsigned	int		iKeySize;				//�Í����̃T�C�Y(128,192,256)
	unsigned	int		Null;					//
	unsigned	int		iSize;					//�t�@�C���T�C�Y
	union{
		unsigned	char	c[16];
		unsigned	int		i[4];
		__m128i				xmm;
	} IV;										//CBC���[�h �����l
} __declspec(align(16)) header;					//�w�b�_�[

union {
	unsigned	__int64	i64[2];
	unsigned	long	i[4];
} randSeed;										//���������p

union {
	unsigned	__int64 i64;
	unsigned	int		i[2];
} cycles;										//�T�C�N�����J�E���g�p

	unsigned	int		i;						//�J�E���g�p
	unsigned	int		n;						//�J�E���g�p

		OPSW*	cOpsw	= new	OPSW(argc, argv);		//�I�v�V�����X�C�b�`����
		MT*		cMT;									//MT����
static	AES		cAES;									//AES�Í�����

	FileInput*			f_IN	= new FileInput();		//�t�@�C�����͗p
	FileOutput*			f_OUT	= new FileOutput();		//�t�@�C���o�͗p
union{
	FileInput*			i;		//����
	FileOutput*			o;		//�o��	
} f_KEY;

	//----------------------------------------------------
	//�����J�n
	cycles.i64 = ReadTSC();				//�v���p �� �����̎�
//	header = new Header;

	//----------------------------------------------------
	//���Í�
	if(cOpsw->cDecode == 0){

		//------------------
		//�t�@�C�����J���i�t�@�C���ǂݍ��ݎ��Ԃ��A�����������Ԃɂ���j
		f_IN->fileopen(cOpsw->strBINname.c_str());
		f_OUT->fileopen(cOpsw->strAESname.c_str());

		//------------------
		//�w�b�_�[�쐬(1)
		header.Name		= strAES;
		header.iSize	= f_IN->GetSize();
		header.iKeySize	= cOpsw->iKey;

		//���������i�t�@�C���ǂݍ��݂ɂ����������Ԃ��A�����̎�j
		randSeed.i64[0] = cycles.i64;
		randSeed.i64[1] = ReadTSC();
		cMT	=	new MT(randSeed.i, 4);					//MT��������

		header.IV.i[0] = cMT->genrand_int32();
		header.IV.i[1] = cMT->genrand_int32();
		header.IV.i[2] = cMT->genrand_int32();
		header.IV.i[3] = cMT->genrand_int32();

		//------------------
		//���̏���
		//���t�@�C���L��
		if(header.iKeySize == 0){
			f_KEY.i = new FileInput();
			f_KEY.i->fileopen(cOpsw->strKEYname.c_str());
			header.iKeySize = f_KEY.i->GetSize()<<3;	//�Í����̃T�C�Y���w�b�_�[�ɃZ�b�g
			if((header.iKeySize!=128)&&(header.iKeySize!=192)&&(header.iKeySize!=256)){
				errPrint(cOpsw->strKEYname.c_str(), ": Not chiper-key file.");
			}
			f_KEY.i->read((char *)Key.c, sizeof(Key.c));
			f_KEY.i->close();
			delete f_KEY.i;
		//���͎�������
		} else {
			f_KEY.o = new FileOutput();
			f_KEY.o->fileopen(cOpsw->strKEYname.c_str());
			i =  header.iKeySize>>5;
			do{
				i--;
				Key.i[i] = cMT->genrand_int32();		//�����ňÍ����𐶐�
			} while(i>0);
			f_KEY.o->write((char *)Key.c, header.iKeySize>>3);
			f_KEY.o->close();
			delete f_KEY.o;
		}

		delete	cMT;

		//------------------
		//�ϊ�
		cAES.KeyExpansion(header.iKeySize>>5,Key.c);
		cAES.SetIV(header.IV.xmm);
		f_OUT->write((char *)&header, sizeof(Header));
		i = header.iSize;
		while(i>0){
			n = ((i>16)?16:i);
			f_IN->read((char *)text, 16);
			cAES.CBC_Cipher(text);
			f_OUT->write((char *)text, 16);
			i -= n;
		}

	//----------------------------------------------------
	//������	
	} else {

		//------------------
		//�t�@�C�����J��
		f_IN->fileopen(cOpsw->strAESname.c_str());
		f_OUT->fileopen(cOpsw->strBINname.c_str());

		//------------------
		//�w�b�_�[�ǂݍ��� �� �`�F�b�N
		f_IN->read((char *)&header, sizeof(Header));
		if(header.Name != strAES){
			errPrint(cOpsw->strAESname.c_str(), ": Not chiper-text file.");
		}

		//------------------
		//�Í����̏���
		f_KEY.i = new FileInput();
		f_KEY.i->fileopen(cOpsw->strKEYname.c_str());
		if((f_KEY.i->GetSize()) != header.iKeySize>>3){
			errPrint(cOpsw->strKEYname.c_str(), ": Not chiper-key file.");
		}
		f_KEY.i->read((char *)Key.c, header.iKeySize>>3);
		f_KEY.i->close();
		delete f_KEY.i;

		//------------------
		//�ϊ�
		cAES.KeyExpansion(header.iKeySize>>5,Key.c);
		cAES.SetIV(header.IV.xmm);
		i = header.iSize;
		while(i>0){
			n = ((i>16)?16:i);
			f_IN->read((char *)text, 16);
			cAES.CBC_InvCipher(text);
			f_OUT->write((char *)text, n);
			i -= n;
		}

	}

	//�t�@�C�������
	f_IN->close();
	f_OUT->close();

	delete	f_IN;
	delete	f_OUT;
	delete	cOpsw;

	printf("%u:%u �T�C�N���v���܂����B\n", ReadTSC() - cycles.i64);

	return 0;
}


