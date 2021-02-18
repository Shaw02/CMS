#pragma once
#include "AlgorithmIdentifier.h"

//======================================================================
//					Digest Algorithm Identifier
//======================================================================
//	Reference:
//	RFC 5652		Cryptographic Message Syntax (CMS)
//	RFC 3370		Cryptographic Message Syntax (CMS) Algorithms
//======================================================================
//
//	�{�v���O�����́A�n�b�V�����Z�o���邽�߂̊��N���X�ł��B
//
//						Copyright (c) A.Watanabe (2011)
//
//----------------------------------------------------------------------
//	Revision
//		2011. 1.17	����
//======================================================================
/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class Digest :
	public AlgorithmIdentifier
{
public:
				size_t	iCountBlock;		//Block���̃J�E���g
				size_t	szBlock;
				size_t	szHash;

	unsigned	char*	M;					//Padding�p


	Digest(const char _strName[]="Digest");
	~Digest(void);

			void	CalcHash(void *result, void *data, size_t iSize);

	virtual	void	init(void){};
			void	add(void *data);
	virtual	void	final(void *data, size_t iSize);	//�֐��ɂ��Padding���قȂ邩������Ȃ��B
	virtual	void	getHash(void *result){};

	virtual	void	calc(void *data){};
};
