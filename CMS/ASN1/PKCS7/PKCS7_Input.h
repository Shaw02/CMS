#pragma once
#include "../BER_Input.h"
#include "PKCS7.h"

/****************************************************************/
/*			ƒNƒ‰ƒX’è‹`											*/
/****************************************************************/
class PKCS7_Input :
	public BER_Input,
	public PKCS7
{
public:
		PKCS7_Input(const char*	strFileName,const char _strName[]="PKCS#7");
		~PKCS7_Input(void);

unsigned	int			read_ContentInfo(unsigned int type);
unsigned	int			read_EnvelopedData(EnvelopedData* _envelopedData);
unsigned	int			read_EncryptedData(EncryptedData* _encryptedData);

			void		read_RecipientInfos(RecipientInfos* _recipientInfos);
			void		read_PasswordRecipientInfo(PasswordRecipientInfo* _passwordRecipientInfo);
unsigned	int			read_EncryptedContentInfo(EncryptedContentInfo*	ECinfo);
		Encryption*		read_ContentEncryptionAlgorithm();
		HMAC*			read_HmacAlgorithm();
		KeyDerivation*	read_KeyDerivationAlgorithm();
};
