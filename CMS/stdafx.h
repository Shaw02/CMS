// stdafx.h : �W���̃V�X�e�� �C���N���[�h �t�@�C���̃C���N���[�h �t�@�C���A�܂���
// �Q�Ɖ񐔂������A�����܂�ύX����Ȃ��A�v���W�F�N�g��p�̃C���N���[�h �t�@�C��
// ���L�q���܂��B
//

#pragma once

#include "targetver.h"

//#include <stdio.h>
#include <time.h>
#include <tchar.h>
#include <nmmintrin.h>
#include <wmmintrin.h>

#include <iomanip>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <set>


// TODO: �v���O�����ɕK�v�Ȓǉ��w�b�_�[�������ŎQ�Ƃ��Ă��������B

using namespace std;

#include "option.h"						//�I�v�V��������

//�t�@�C�������p
#include "FileInput.h"					//
#include "FileOutput.h"					//

//ASN.1	��{�N���X
#include "ASN1\ASN1.h"					//ASN.1�p ���N���X
#include "ASN1\Integer.h"				//0x02
#include "ASN1\OctetString.h"			//0x04
#include "ASN1\ObjectIdentifier.h"		//0x06
#include "ASN1\Sequence.h"				//0x10
#include "ASN1\Set.h"					//0x11
#include "ASN1\Context.h"				//

#include "ASN1\BER_Output.h"			//
#include "ASN1\BER_Input.h"				//

//ASN.1	�A���S���Y��
#include "ASN1\Algorithm\AlgorithmIdentifier.h"	//RFC 3370	Algorithm for CMS

//�Í��֐�(Crypt)
#include "ASN1\Algorithm\Encryption.h"			//			Encryption
#include "ASN1\Algorithm\DES.h"					//fips 46	DES
#include "ASN1\Algorithm\DES_CBC.h"				//
#include "ASN1\Algorithm\DES_EDE3.h"			//
#include "ASN1\Algorithm\DES_EDE3_CBC.h"		//
#include "ASN1\Algorithm\AES.h"					//RFC 3565	AES
#include "ASN1\Algorithm\AES_CBC.h"				//
#include "ASN1\Algorithm\AES_CBC128.h"			//
#include "ASN1\Algorithm\AES_CBC192.h"			//
#include "ASN1\Algorithm\AES_CBC256.h"			//
#include "ASN1\Algorithm\PWRI-KEK.h"			//RFC 3211	Password-based Encryption for CMS

//�n�b�V���֐�(Digest)
#include "ASN1\Algorithm\Digest.h"				//			Digest
#include "ASN1\Algorithm\SHA.h"					//RFC 4634	SHA�@�@�@�n�b�V�����N���X
#include "ASN1\Algorithm\SHA-1.h"				//RFC 3174	SHA-1�@�@�n�b�V��
#include "ASN1\Algorithm\SHA-224.h"				//RFC 3874	SHA-224�@�n�b�V��
#include "ASN1\Algorithm\SHA-256.h"				//RFC 5754	SHA-256�@�n�b�V��

//�[�������֐�(PRF)
#include "ASN1\Algorithm\HMAC.h"				//RFC 2104  HMAC
#include "ASN1\Algorithm\HMAC-SHA-1.h"			//RFC 2898	HMAC-SHA-1
#include "ASN1\Algorithm\HMAC-SHA-224.h"		//RFC 4231	HMAC-SHA-224
#include "ASN1\Algorithm\HMAC-SHA-256.h"		//RFC 4231	HMAC-SHA-256

#include "ASN1\Algorithm\MT.h"					//MT
#include "ASN1\Algorithm\MT_SHA.h"				//MT with SHA

//�����o�֐�(KDF)
#include "ASN1\Algorithm\KeyDerivation.h"
#include "ASN1\Algorithm\PBKDF2.h"				//RFC 2898	PBKDF2

//ASN.1	PKCS#8�i�Í����\���j
#include "ASN1\PKCS8\PrivateKeyInfo.h"			//
#include "ASN1\PKCS8\PKCS8.h"					//
#include "ASN1\PKCS8\PKCS8_Input.h"				//
#include "ASN1\PKCS8\PKCS8_Output.h"			//

//ASN.1	PKCS#7�i�W���Í����b�Z�[�W�\���j
#include "ASN1\PKCS7\PasswordRecipientinfo.h"	//RFC 3211	Password-based Encryption for CMS
#include "ASN1\PKCS7\RecipientInfos.h"			//
#include "ASN1\PKCS7\EncryptedContentInfo.h"	//
#include "ASN1\PKCS7\EncryptedData.h"			//
#include "ASN1\PKCS7\EnvelopedData.h"			//
#include "ASN1\PKCS7\ContentInfo.h"				//

#include "ASN1\PKCS7\PKCS7.h"					//
#include "ASN1\PKCS7\PKCS7_Input.h"				//
#include "ASN1\PKCS7\PKCS7_3_Input.h"			//
#include "ASN1\PKCS7\PKCS7_6_Input.h"			//

#include "ASN1\PKCS7\PKCS7_Output.h"			//
#include "ASN1\PKCS7\PKCS7_3_Output.h"			//
#include "ASN1\PKCS7\PKCS7_6_Output.h"			//

/****************************************************************/
/*			�O���錾											*/
/****************************************************************/

extern	MT_SHA*	cRandom;

/****************************************************************/
/*			�v���g�^�C�v										*/
/****************************************************************/
extern "C"	void		dataPrint(int n, void *Data);
extern "C"	void		dataPrint32(int n, void *Data);
void		errPrint(const char *strFile, const char *strMSG);
__int64		ReadTSC();
int			ChkSIMD();
