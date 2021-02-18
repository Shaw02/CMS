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

			size_t		read_ContentInfo(unsigned int type);
			size_t		read_EnvelopedData(EnvelopedData* _envelopedData);
			size_t		read_EncryptedData(EncryptedData* _encryptedData);
			size_t		read_EncryptedContentInfo(EncryptedContentInfo*	ECinfo);

			void		read_RecipientInfos(RecipientInfos* _recipientInfos);
			void		read_PasswordRecipientInfo(PasswordRecipientInfo* _passwordRecipientInfo);
		HMAC*			read_HmacAlgorithm();
		Encryption*		read_ContentEncryptionAlgorithm();
		Encryption*		read_KeyWrapAlgorithm(PWRI_KEK* _pwri_kek);
		Encryption*		read_keyEncryptionAlgorithm();
		KeyDerivation*	read_KeyDerivationAlgorithm();
};
