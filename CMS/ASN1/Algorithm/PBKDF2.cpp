#include "StdAfx.h"
#include "PBKDF2.h"

unsigned	int		PBKDF2::oid[] = {1,2,840,113549,1,5,12};

//==============================================================
//			�R���X�g���N�^
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//==============================================================
PBKDF2::PBKDF2(HMAC* _cHMAC, const char _strName[]):
	KeyDerivation(_strName),
	cHMAC(_cHMAC)
{
	Set_oid(oid,sizeof(oid)/sizeof(int));

	//�J��Ԃ��v�Z�p�o�b�t�@
	hLen		= cHMAC->cHash->szHash;
	U_			= (unsigned	char*)_aligned_malloc(hLen, sizeof(__m128i));

	//�r���I�_���a���i�[����o�b�t�@
	__m128_hLen	= (hLen/sizeof(__m128i)) + 1;
	__m128_U	= (__m128i*)_aligned_malloc(__m128_hLen * sizeof(__m128i), sizeof(__m128i));
}
//==============================================================
//			�f�X�g���N�^
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//==============================================================
PBKDF2::~PBKDF2(void)
{
	_aligned_free(__m128_U);
	_aligned_free(U_);
}
//==============================================================
//			�ݒ�
//--------------------------------------------------------------
//	������
//		void*				_S		�\���g
//		unsigned	int		_szS	�\���g�̃T�C�Y
//		unsigned	int		_c		�J��Ԃ���
//		unsigned	int		_dkLen	���o���錮�̃T�C�Y
//	���Ԓl
//			����
//==============================================================
void	PBKDF2::Set_PBKDF2(void* _S, unsigned int _szS, unsigned int _c, unsigned int _dkLen)
{
	static	const	unsigned	int		HMAC_SHA1_oid[]		= {1,2,840,113549,2,7};	//RFC 2898 PKCS#5 ver 2.0 
	static	const	unsigned	int		HMAC_SHA1_oid2[]	= {1,3,6,1,5,5,8,1,2};	//RFC 3370 CMS Algorithm

	static	ObjectIdentifier	oid1_HMAC_SHA1	= ObjectIdentifier((unsigned int*)HMAC_SHA1_oid, sizeof(HMAC_SHA1_oid) / sizeof(unsigned int));
	static	ObjectIdentifier	oid2_HMAC_SHA1	= ObjectIdentifier((unsigned int*)HMAC_SHA1_oid2, sizeof(HMAC_SHA1_oid2) / sizeof(unsigned int));

	//ASN.1�̒�`
	Set();

	//salt specified OCTET STRING,
	US	= (unsigned	char*)_aligned_malloc(_szS + sizeof(int), sizeof(__m128i));
	memcpy(US, _S, _szS);
	S.assign((char *)_S, _szS);
	salt.Set((char *)_S, _szS);
	parameters.Set_Construct(&salt);

	//iterationCount INTEGER (1..MAX),
	c		= _c;
	iterationCount.Set(_c);
	parameters.Set_Construct(&iterationCount);

	//keyLength INTEGER (1..MAX) OPTIONAL,
	dkLen	= _dkLen;
	keyLength.Set(_dkLen);
	parameters.Set_Construct(&keyLength);

	//prf AlgorithmIdentifier
	if ((cHMAC->Check_OID(&oid1_HMAC_SHA1) != 0) && (cHMAC->Check_OID(&oid2_HMAC_SHA1) != 0)){
		//HMAC_SHA1�łȂ��ꍇ�́AHMAC��oid���p�����[�^�Ɋ܂�
		parameters.Set_Construct(cHMAC);
	}

	//PBKDF2-params ::= SEQUENCE
	Set_Construct(&parameters);
}
//==============================================================
//			�v�Z
//--------------------------------------------------------------
//	������
//		void*				T	�v�Z���ʂ��i�[����|�C���^
//		unsigned	int		szT	�i�[�T�C�Y
//		unsigned	int		n	
//	���Ԓl
//			����
//==============================================================
void	PBKDF2::F(void* T, unsigned int szT, unsigned int n)
{
	unsigned	int		cnt			= c;				//�J��Ԃ���
	unsigned	int		_m128_hLen	= __m128_hLen;		//__m128i�ł̃n�b�V���l��
			__m128i*	_m128_U		= __m128_U;			//�r���I�_���a�v�Z�p
	unsigned	char*	_U_			= U_;				//���ԃo�b�t�@

	//------
	//1 times
	{
		unsigned	int		sLen		= S.size();
		unsigned	int*	USi			= (unsigned int *)&US[sLen];	//

		USi[0] = ((n>>24) & 0xFF) | ((n>>8) & 0xFF00) | ((n & 0xFF00)<<8) | ((n & 0xFF)<<24);
		cHMAC->calc(_U_, US, sLen+4);
		for(unsigned int i = 0; i < _m128_hLen; i++){
			_m128_U[i] = _mm_load_si128((__m128i*)&_U_[i * sizeof(__m128i)]);
		}
		cnt--;
	}

	//------
	//2 times -
	{
		unsigned	int		_hLen		= hLen;

		while(cnt--){
			cHMAC->calc(_U_, _U_, _hLen);
			for(unsigned int i = 0; i < _m128_hLen; i++){
				_m128_U[i] = _mm_xor_si128(_m128_U[i] ,_mm_load_si128((__m128i*)&_U_[i * sizeof(__m128i)]));
			}
		}
	}

	//------
	//�v�Z���ʊi�[
	{
		unsigned	char*	U	=	(unsigned	char*)T;			//�߂�l���i�[����|�C���^
		unsigned	int		i	=	0;

		while((i + sizeof(__m128i)) <= szT){
			_mm_storeu_si128((__m128i*)&U[i], _m128_U[i / sizeof(__m128i)]);
			i += sizeof(__m128i);
		}
		memcpy(&U[i], &_m128_U[i / sizeof(__m128i)], szT - i);
	}
}
//==============================================================
//			�v�Z
//--------------------------------------------------------------
//	������
//				void*	DK		�����i�[����|�C���^
//				void*	P		�p�X���[�h������̃|�C���^
//		unsigned int	szP		�p�X���[�h�̃T�C�Y
//	���Ԓl
//			����
//==============================================================
void	PBKDF2::calc(void* DK, void* P, unsigned int szP)
{
	//��ɁAHMAC�֐��̌���ݒ肷��B
	cHMAC->SetKey(P, szP);

	//�v�Z
	{
		unsigned	int		i		= 0;
		unsigned	int		_hLen	= hLen;				//�n�b�V���l�̒���
		unsigned	int		l		= dkLen / _hLen;	//DK�̃u���b�N��(�����؎̂�)
		unsigned	int		r		= dkLen % _hLen;	//DK�̃u���b�N���@�[��
		unsigned	char*	T		= (unsigned	char*)DK;

		while(l--){
			i++;
			F(T, _hLen, i);	//���ʂ𒼐ړ����B
			T += _hLen;
		}
		if(r > 0){
			i++;
			F(T, r, i);
		}
	}
}
