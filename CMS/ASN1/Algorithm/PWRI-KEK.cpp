#include "StdAfx.h"
#include "PWRI-KEK.h"

unsigned	int		PWRI_KEK::oid[] = {1,2,840,113549,1,9,16,3,9};

	DES_CBC			PWRI_KEK::ke_DES_CBC;
	DES_EDE3_CBC	PWRI_KEK::ke_TDES_CBC;
	AES_CBC128		PWRI_KEK::ke_AES_CBC128;		//SIMD���g���֌W�ŁA
	AES_CBC192		PWRI_KEK::ke_AES_CBC192;		//static�ɒu���K�v����B
	AES_CBC256		PWRI_KEK::ke_AES_CBC256;		//(__declspec(align(16)))

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
PWRI_KEK::PWRI_KEK(const char _strName[]):
	Encryption(_strName)
{
	Set_oid(oid,sizeof(oid)/sizeof(int));
}
//==============================================================
//		�f�X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
PWRI_KEK::~PWRI_KEK(void)
{
}
//==============================================================
//			Key Zero
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//==============================================================
void	PWRI_KEK::Clear_Key()
{
	unsigned	i;

	EncryptionAlgorithm->Clear_Key();

	i = strKey.size();
	while(i > 0){
		i--;
		strKey[i] = 0;
	}

	i = strEncrptedKey.size();
	while(i > 0){
		i--;
		strKey[i] = 0;
	}

}
//==============================================================
//			Key Set
//--------------------------------------------------------------
//	������
//			void	*key	DES Key (8Byte (7bit * 8 = 56bit))
//	���Ԓl
//			����
//==============================================================
void	PWRI_KEK::Set_Key(void *key)
{
	EncryptionAlgorithm->Set_Key(key);
}
//==============================================================
//			Key Wrap
//--------------------------------------------------------------
//	������
//			void*			data	CEK�̃|�C���^
//			unsigned int	iSize	CEK�̃T�C�Y
//			void*			random	�����l�̃|�C���^
//	���Ԓl
//			int						���b�v���ꂽCEK�̃T�C�Y
//==============================================================
int	PWRI_KEK::KeyWrap(void *CEK,unsigned int szCEK)
{
	unsigned	char*	cCEK	= (unsigned char*)CEK;

	unsigned	int		szECEK	= szCEK + 4;
	unsigned	int		szKEB	= EncryptionAlgorithm->szBlock;

	unsigned	int	i,j;

				char*	cBuff0;		//�Í����p�̃o�b�t�@
				char*	cBuff;		//�Í����p�̃o�b�t�@�i�A���C�����g�j

	//���b�v���ꂽ�R���e���c�p�Í���"CEK"�̃T�C�Y
	szECEK  += szKEB - (szECEK % szKEB) - ((szECEK % szKEB)?0:szKEB);

	//�Í��p�̃o�b�t�@���m�ہB�A���C�����g���l������B
	cBuff0	= new char [szECEK + szKEB];
	cBuff	= cBuff0 + szKEB - ((int)cBuff0 % szKEB) - (((int)cBuff0 % szKEB)?0:szKEB);

	//�R���e���c�p�Í���"CEK"��Size
	cBuff[0] = szCEK & 0xFF;

	//Check
	cBuff[1] = 0xFF ^ cCEK[0];
	cBuff[2] = 0xFF ^ cCEK[1];
	cBuff[3] = 0xFF ^ cCEK[2];

	//CEK
	i = 0;
	while(i < szCEK){
		cBuff[4+i] = cCEK[i];
		i++;
	}
	i += 4;

	//Random Padding
	j = 0;
	while(i < szECEK){
		cBuff[i] = cRandom->get_int();
		j++;
		i++;
	}

	//Key Wrap
	EncryptionAlgorithm->init();
	EncryptionAlgorithm->encipher(cBuff, szECEK);
	EncryptionAlgorithm->encipher(cBuff, szECEK);

	strEncrptedKey.resize(szECEK);
	strEncrptedKey.assign(cBuff, szECEK);

	delete	cBuff0;

	return(szECEK);
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	������
//			void*			data	���b�v���ꂽCEK�̃|�C���^
//			unsigned int	iSize	���b�v���ꂽCEK�̃T�C�Y
//	���Ԓl
//			int						CEK�̃T�C�Y
//==============================================================
int	PWRI_KEK::KeyUnWrap(void *data,unsigned int szData)
{
	unsigned	char*	cData	= (unsigned char*)data;

	unsigned	int		szKEK;
	unsigned	int		szCEK	= EncryptionAlgorithm->szBlock;

	unsigned	int		i;
	unsigned	int		n		= szData / szCEK;		//�u���b�N��
	unsigned	int		ptData	= szData - (szCEK*2);

	//Using the n-1'th ciphertext block as the IV,
	EncryptionAlgorithm->SetIV(&cData[ptData]);

	//decrypt the n'th ciphertext block.
	ptData += szCEK;
	EncryptionAlgorithm->decrypt(&cData[ptData]);

	//Using the decrypted n'th ciphertext block as the IV,
	EncryptionAlgorithm->SetIV(&cData[ptData]);

	//decrypt the 1st ... n-1'th ciphertext blocks.
	EncryptionAlgorithm->decipher(data, szData-szCEK);

	//Decrypt the inner layer of encryption using the KEK.
	EncryptionAlgorithm->init();
	EncryptionAlgorithm->decipher(data, szData);

	//Check
	if(	((cData[1] ^ 0xFF) == cData[4])
	 &&	((cData[2] ^ 0xFF) == cData[5])
	 &&	((cData[3] ^ 0xFF) == cData[6])){
		szKEK = cData[0];
		strKey.resize(szKEK);
		i = 0;
		while(i < szKEK){
			strKey[i] = cData[4 + i];
			i++;
		}
	} else {
		szKEK = -1;
	}

	return(szKEK);
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	������
//			__m128i		_xmm_IV		�������x�N�^IV
//	���Ԓl
//			����
//==============================================================
void	PWRI_KEK::Set_PWRI_KEK(unsigned int mode, __m128i IV)
{
	//ASN.1�̒�`
	Set();			//oid
//	EncryptionAlgorithm = _algorithm;
	EncryptionAlgorithm	= Get_Encryption(mode,IV);
	Set_Construct(EncryptionAlgorithm);
}
//==============================================================
//				�Í����W���[���̎擾
//--------------------------------------------------------------
//	������
//			unsigned int mode	���p����Í�
//	���Ԓl
//			Encryption*			�Í����W���[���̃|�C���^
//	������
//			�O���f�[�^�̌��ɂ�BER�G���R�[�h���ꂽ�f�[�^������ƃ_���B
//==============================================================
Encryption*	PWRI_KEK::Get_Encryption(unsigned int mode, __m128i IV)
{

	Encryption*	cKE;

	//�Í��A���S���Y�������p���[�h�̐ݒ�
	switch(mode){
		//�ǉ��̈Í��A���S���Y��������ꍇ�́A�����ɒǉ��B
		//DES-CBC
		case(1):
			ke_DES_CBC.Set_DES(IV.m128i_i64[0]);
			cKE = &ke_DES_CBC;
			break;
		//DES-EDE3-CBC
		case(2):
			ke_TDES_CBC.Set_DES(IV.m128i_i64[0]);
			cKE = &ke_TDES_CBC;
			break;
		//AES-CBC-128
		case(3):
			ke_AES_CBC128.Set_AES(IV);
			cKE = &ke_AES_CBC128;
			break;
		//AES-CBC-192
		case(4):
			ke_AES_CBC192.Set_AES(IV);
			cKE = &ke_AES_CBC192;
			break;
		//AES-CBC-256
		default:
			ke_AES_CBC256.Set_AES(IV);
			cKE = &ke_AES_CBC256;
			break;
	}
	return(cKE);
}
