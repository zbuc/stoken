/*
 * Adapted from libtomcrypt 1.17
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

#ifndef _CRYPTO_INTERNAL_H_
#define _CRYPTO_INTERNAL_H_

#include "crypto.h"

#define LTC_RIJNDAEL
#define LTC_DEVRANDOM
#define TRY_URANDOM_FIRST
#define LTC_ARGCHK(x) do { } while(0)

#define byte(x, n) (((x) >> (8 * (n))) & 255)

#define ROL(x, y) ( (((unsigned long)(x)<<(unsigned long)((y)&31)) | (((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define ROR(x, y) ( ((((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)((y)&31)) | ((unsigned long)(x)<<(unsigned long)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define ROLc(x, y) ( (((unsigned long)(x)<<(unsigned long)((y)&31)) | (((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define RORc(x, y) ( ((((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)((y)&31)) | ((unsigned long)(x)<<(unsigned long)(32-((y)&31)))) & 0xFFFFFFFFUL)

#define STORE32L(x, y)                                                                     \
     { (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); }

#define LOAD32L(x, y)                            \
     { x = ((unsigned long)((y)[3] & 255)<<24) | \
           ((unsigned long)((y)[2] & 255)<<16) | \
           ((unsigned long)((y)[1] & 255)<<8)  | \
           ((unsigned long)((y)[0] & 255)); }

#define STORE64L(x, y)                                                                     \
     { (y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255);   \
       (y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255);   \
       (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); }

#define LOAD64L(x, y)                                                       \
     { x = (((ulong64)((y)[7] & 255))<<56)|(((ulong64)((y)[6] & 255))<<48)| \
           (((ulong64)((y)[5] & 255))<<40)|(((ulong64)((y)[4] & 255))<<32)| \
           (((ulong64)((y)[3] & 255))<<24)|(((ulong64)((y)[2] & 255))<<16)| \
           (((ulong64)((y)[1] & 255))<<8)|(((ulong64)((y)[0] & 255))); }

#define STORE32H(x, y)                                                                     \
     { (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255);   \
       (y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255); }

#define LOAD32H(x, y)                            \
     { x = ((unsigned long)((y)[0] & 255)<<24) | \
           ((unsigned long)((y)[1] & 255)<<16) | \
           ((unsigned long)((y)[2] & 255)<<8)  | \
           ((unsigned long)((y)[3] & 255)); }

#define STORE64H(x, y)                                                                     \
   { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255);     \
     (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255);     \
     (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255);     \
     (y)[6] = (unsigned char)(((x)>>8)&255); (y)[7] = (unsigned char)((x)&255); }

#define LOAD64H(x, y)                                                      \
   { x = (((ulong64)((y)[0] & 255))<<56)|(((ulong64)((y)[1] & 255))<<48) | \
         (((ulong64)((y)[2] & 255))<<40)|(((ulong64)((y)[3] & 255))<<32) | \
         (((ulong64)((y)[4] & 255))<<24)|(((ulong64)((y)[5] & 255))<<16) | \
         (((ulong64)((y)[6] & 255))<<8)|(((ulong64)((y)[7] & 255))); }

extern struct ltc_cipher_descriptor {
   /** name of cipher */
   char *name;
   /** internal ID */
   unsigned char ID;
   /** min keysize (octets) */
   int  min_key_length, 
   /** max keysize (octets) */
        max_key_length, 
   /** block size (octets) */
        block_length, 
   /** default number of rounds */
        default_rounds;
   /** Setup the cipher 
      @param key         The input symmetric key
      @param keylen      The length of the input key (octets)
      @param num_rounds  The requested number of rounds (0==default)
      @param skey        [out] The destination of the scheduled key
      @return CRYPT_OK if successful
   */
   int  (*setup)(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
   /** Encrypt a block
      @param pt      The plaintext
      @param ct      [out] The ciphertext
      @param skey    The scheduled key
      @return CRYPT_OK if successful
   */
   int (*ecb_encrypt)(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
   /** Decrypt a block
      @param ct      The ciphertext
      @param pt      [out] The plaintext
      @param skey    The scheduled key
      @return CRYPT_OK if successful
   */
   int (*ecb_decrypt)(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
   /** Test the block cipher
       @return CRYPT_OK if successful, CRYPT_NOP if self-testing has been disabled
   */
   int (*test)(void);

   /** Terminate the context 
      @param skey    The scheduled key
   */
   void (*done)(symmetric_key *skey);      

   /** Determine a key size
       @param keysize    [in/out] The size of the key desired and the suggested size
       @return CRYPT_OK if successful
   */
   int  (*keysize)(int *keysize);

/** Accelerators **/
   /** Accelerated ECB encryption 
       @param pt      Plaintext
       @param ct      Ciphertext
       @param blocks  The number of complete blocks to process
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   int (*accel_ecb_encrypt)(const unsigned char *pt, unsigned char *ct, unsigned long blocks, symmetric_key *skey);

   /** Accelerated ECB decryption 
       @param pt      Plaintext
       @param ct      Ciphertext
       @param blocks  The number of complete blocks to process
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   int (*accel_ecb_decrypt)(const unsigned char *ct, unsigned char *pt, unsigned long blocks, symmetric_key *skey);

   /** Accelerated CBC encryption 
       @param pt      Plaintext
       @param ct      Ciphertext
       @param blocks  The number of complete blocks to process
       @param IV      The initial value (input/output)
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   int (*accel_cbc_encrypt)(const unsigned char *pt, unsigned char *ct, unsigned long blocks, unsigned char *IV, symmetric_key *skey);

   /** Accelerated CBC decryption 
       @param pt      Plaintext
       @param ct      Ciphertext
       @param blocks  The number of complete blocks to process
       @param IV      The initial value (input/output)
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   int (*accel_cbc_decrypt)(const unsigned char *ct, unsigned char *pt, unsigned long blocks, unsigned char *IV, symmetric_key *skey);

   /** Accelerated CTR encryption 
       @param pt      Plaintext
       @param ct      Ciphertext
       @param blocks  The number of complete blocks to process
       @param IV      The initial value (input/output)
       @param mode    little or big endian counter (mode=0 or mode=1)
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   int (*accel_ctr_encrypt)(const unsigned char *pt, unsigned char *ct, unsigned long blocks, unsigned char *IV, int mode, symmetric_key *skey);

   /** Accelerated LRW 
       @param pt      Plaintext
       @param ct      Ciphertext
       @param blocks  The number of complete blocks to process
       @param IV      The initial value (input/output)
       @param tweak   The LRW tweak
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   int (*accel_lrw_encrypt)(const unsigned char *pt, unsigned char *ct, unsigned long blocks, unsigned char *IV, const unsigned char *tweak, symmetric_key *skey);

   /** Accelerated LRW 
       @param ct      Ciphertext
       @param pt      Plaintext
       @param blocks  The number of complete blocks to process
       @param IV      The initial value (input/output)
       @param tweak   The LRW tweak
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   int (*accel_lrw_decrypt)(const unsigned char *ct, unsigned char *pt, unsigned long blocks, unsigned char *IV, const unsigned char *tweak, symmetric_key *skey);

   /** Accelerated CCM packet (one-shot)
       @param key        The secret key to use
       @param keylen     The length of the secret key (octets)
       @param uskey      A previously scheduled key [optional can be NULL]
       @param nonce      The session nonce [use once]
       @param noncelen   The length of the nonce
       @param header     The header for the session
       @param headerlen  The length of the header (octets)
       @param pt         [out] The plaintext
       @param ptlen      The length of the plaintext (octets)
       @param ct         [out] The ciphertext
       @param tag        [out] The destination tag
       @param taglen     [in/out] The max size and resulting size of the authentication tag
       @param direction  Encrypt or Decrypt direction (0 or 1)
       @return CRYPT_OK if successful
   */
   int (*accel_ccm_memory)(
       const unsigned char *key,    unsigned long keylen,
       symmetric_key       *uskey,
       const unsigned char *nonce,  unsigned long noncelen,
       const unsigned char *header, unsigned long headerlen,
             unsigned char *pt,     unsigned long ptlen,
             unsigned char *ct,
             unsigned char *tag,    unsigned long *taglen,
                       int  direction);

   /** Accelerated GCM packet (one shot)
       @param key        The secret key
       @param keylen     The length of the secret key
       @param IV         The initial vector 
       @param IVlen      The length of the initial vector
       @param adata      The additional authentication data (header)
       @param adatalen   The length of the adata
       @param pt         The plaintext
       @param ptlen      The length of the plaintext (ciphertext length is the same)
       @param ct         The ciphertext
       @param tag        [out] The MAC tag
       @param taglen     [in/out] The MAC tag length
       @param direction  Encrypt or Decrypt mode (GCM_ENCRYPT or GCM_DECRYPT)
       @return CRYPT_OK on success
   */
   int (*accel_gcm_memory)(
       const unsigned char *key,    unsigned long keylen,
       const unsigned char *IV,     unsigned long IVlen,
       const unsigned char *adata,  unsigned long adatalen,
             unsigned char *pt,     unsigned long ptlen,
             unsigned char *ct, 
             unsigned char *tag,    unsigned long *taglen,
                       int direction);

   /** Accelerated one shot LTC_OMAC 
       @param key            The secret key
       @param keylen         The key length (octets) 
       @param in             The message 
       @param inlen          Length of message (octets)
       @param out            [out] Destination for tag
       @param outlen         [in/out] Initial and final size of out
       @return CRYPT_OK on success
   */
   int (*omac_memory)(
       const unsigned char *key, unsigned long keylen,
       const unsigned char *in,  unsigned long inlen,
             unsigned char *out, unsigned long *outlen);

   /** Accelerated one shot XCBC 
       @param key            The secret key
       @param keylen         The key length (octets) 
       @param in             The message 
       @param inlen          Length of message (octets)
       @param out            [out] Destination for tag
       @param outlen         [in/out] Initial and final size of out
       @return CRYPT_OK on success
   */
   int (*xcbc_memory)(
       const unsigned char *key, unsigned long keylen,
       const unsigned char *in,  unsigned long inlen,
             unsigned char *out, unsigned long *outlen);

   /** Accelerated one shot F9 
       @param key            The secret key
       @param keylen         The key length (octets) 
       @param in             The message 
       @param inlen          Length of message (octets)
       @param out            [out] Destination for tag
       @param outlen         [in/out] Initial and final size of out
       @return CRYPT_OK on success
       @remark Requires manual padding
   */
   int (*f9_memory)(
       const unsigned char *key, unsigned long keylen,
       const unsigned char *in,  unsigned long inlen,
             unsigned char *out, unsigned long *outlen);
} cipher_descriptor[];

#endif /* _CRYPTO_INTERNAL_H_ */
