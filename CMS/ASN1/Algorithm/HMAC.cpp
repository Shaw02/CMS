#include "StdAfx.h"
#include "HMAC.h"

//==============================================================
//			�R���X�g���N�^
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//==============================================================
HMAC::HMAC(Digest* _cHash, const char _strName[]):
	AlgorithmIdentifier(_strName),
	cHash(_cHash)
{
	//�v�Z�p�̃o�b�t�@�m��
	Kipad		= new char[cHash->szBlock];
	Kopad		= new char[cHash->szBlock + cHash->szHash];
}
//==============================================================
//			�f�X�g���N�^
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//==============================================================
HMAC::~HMAC(void)
{
	//�v�Z�p�̃o�b�t�@�J��
	delete	Kipad;
	delete	Kopad;
}
//==============================================================
//			���̃Z�b�g
//--------------------------------------------------------------
//	������
//		void*				Key		��
//		size_t				szKey	���̃T�C�Y
//	���Ԓl
//			����
//	�����l
//			PBKDF2���ŁA�������������������͖̂��ʂ̈�
//==============================================================
void	HMAC::SetKey(void* Key, size_t szKey)
{
	//�p�x�ɃA�N�Z�X����̂ŁA���W�X�^�ɓ����B
			Digest*	_cHash	=	cHash;				//�n�b�V���֐��̃|�C���^
	const	size_t	szBlock =	_cHash->szBlock;	//�n�b�V���֐��̓��̓u���b�N��
	const	size_t	szHash	=	_cHash->szHash;		//�n�b�V���֐��̏o�͒�
			char*	_Kipad	=	Kipad;				//�œK���Ń��W�X�^�ɓ���ĖႤ�B
			char*	_Kopad	=	Kopad;				//

	//------------
	//����0x00Padding
	{
		//�ϐ���`
		const	char*	cKey	= (char *)Key;

		//Padding���{
		if(szKey > szBlock){
			_cHash->CalcHash(_Kipad, Key, szKey);
			szKey = szHash;
			memcpy((char*)_Kopad,(char*)_Kipad,szKey);
		} else {
			memcpy(_Kipad,Key,szKey);
			memcpy(_Kopad,Key,szKey);
		}
		memset(&_Kipad[szKey],0x00,szBlock - szKey);
		memset(&_Kopad[szKey],0x00,szBlock - szKey);
	}

	//------------
	//ipad �� opad �Ŕr���I�_���a���������쐬
	{
		//�ϐ���`
						size_t	i		=	0;
		static	const	_mm_i32	_mm_36	= {0x36363636,0x36363636,0x36363636,0x36363636};
		static	const	_mm_i32	_mm_5C	= {0x5C5C5C5C,0x5C5C5C5C,0x5C5C5C5C,0x5C5C5C5C};
						__m128i _mm_temp;	

		//�r���I�_���a�����{
		while((i + sizeof(__m128i)) < szBlock){
			_mm_storeu_si128((__m128i*)_Kipad, _mm_xor_si128(_mm_loadu_si128((__m128i*)_Kipad) ,_mm_36.m128i));
			_mm_storeu_si128((__m128i*)_Kopad, _mm_xor_si128(_mm_loadu_si128((__m128i*)_Kopad) ,_mm_5C.m128i));
			_Kipad += sizeof(__m128i);
			_Kopad += sizeof(__m128i);
			i += sizeof(__m128i);
		}
		i = szBlock - i;
		_mm_temp	= _mm_xor_si128(_mm_loadu_si128((__m128i*)_Kipad) ,_mm_36.m128i);
		memcpy(_Kipad, &_mm_temp, i);
		_mm_temp	= _mm_xor_si128(_mm_loadu_si128((__m128i*)_Kopad) ,_mm_5C.m128i);
		memcpy(_Kopad, &_mm_temp, i);
	}
}
//==============================================================
//			�v�Z
//--------------------------------------------------------------
//	������
//		void*				result	
//		void*				data	���b�Z�[�W
//		size_t				szData	���b�Z�[�W�̃T�C�Y
//	���Ԓl
//			����
//==============================================================
void	HMAC::calc(void* result, void* data, size_t szData)
{
			size_t	i		=	szData;

	//�p�x�ɃA�N�Z�X����̂ŁA���W�X�^�ɓ����B
			Digest*	_cHash	=	cHash;				//�n�b�V���֐��̃|�C���^
	const	size_t	szBlock =	_cHash->szBlock;	//�n�b�V���֐��̓��̓u���b�N��
	const	size_t	szHash	=	_cHash->szHash;		//�n�b�V���֐��̏o�͒�

	//------------
	//�v�Z
	{
		//�ϐ���`
		char*	cData	= (char *)data;

		//1st PASS
		_cHash->init();
		_cHash->add(Kipad);
		while(i>0){
			if(i>=szBlock){
				_cHash->add(cData);
				cData += szBlock;
				i -= szBlock;
			} else {
				_cHash->final(cData,i);
				break;
			}
		}
		_cHash->getHash(&Kopad[szBlock]);

		//2nd PASS
		_cHash->CalcHash(result, Kopad, szBlock + szHash);
	}
}
