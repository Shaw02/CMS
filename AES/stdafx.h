// stdafx.h : �W���̃V�X�e�� �C���N���[�h �t�@�C���̃C���N���[�h �t�@�C���A�܂���
// �Q�Ɖ񐔂������A�����܂�ύX����Ȃ��A�v���W�F�N�g��p�̃C���N���[�h �t�@�C��
// ���L�q���܂��B
//

#pragma once

#include "targetver.h"

//#include <stdio.h>
#include <tchar.h>
#include <nmmintrin.h>

#include <iomanip>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <map>


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
#include "ASN1\Context.h"				//

#include "ASN1\BER_Output.h"			//
#include "ASN1\BER_Input.h"				//

//ASN.1	�A���S���Y��
#include "ASN1\Algorithm\AlgorithmIdentifier.h"
#include "ASN1\Algorithm\AES.h"			//AES�Í�
#include "ASN1\Algorithm\SHA.h"			//SHA�@�@�@�n�b�V�����N���X
#include "ASN1\Algorithm\SHA-1.h"		//SHA-1�@�@�n�b�V��
#include "ASN1\Algorithm\SHA-224.h"		//SHA-224�@�n�b�V��
#include "ASN1\Algorithm\SHA-256.h"		//SHA-256�@�n�b�V��
#include "ASN1\Algorithm\MT.h"			//MT����
#include "ASN1\Algorithm\MT_SHA.h"		//MT���� with SHA

//ASN.1	PKCS#7�i�W���Í����b�Z�[�W�\���j
#include "ASN1\PKCS7\EncryptedContentInfo.h"	//
#include "ASN1\PKCS7\EncryptedData.h"			//
#include "ASN1\PKCS7\ContentInfo.h"				//

#include "ASN1\PKCS7\PKCS7_Input.h"			//
#include "ASN1\PKCS7\PKCS7_6_Input.h"		//
#include "ASN1\PKCS7\PKCS7_Output.h"		//
#include "ASN1\PKCS7\PKCS7_6_Output.h"		//

#include "ASN1\PKCS8\PrivateKeyInfo.h"		//
#include "ASN1\PKCS8\PKCS8_Input.h"			//
#include "ASN1\PKCS8\PKCS8_Output.h"		//

void	dataPrint(int n, void *Data);
void	errPrint(const char *strFile, const char *strMSG);