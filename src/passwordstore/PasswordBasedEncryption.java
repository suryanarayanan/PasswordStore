
package passwordstore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.security.Key;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.axis.encoding.Base64;

/**
 *
 * @author Surya
 */
public class PasswordBasedEncryption {
    private final String keyAlgorithm = "PBKDF2WithHmacSHA1";
    private final String MDAlgorithm = "SHA-1";
    private final String AESKeyAlgorithm = "AES";
    private final int iterations = 1000;
    private final int keySize = 128;
    private final int ivLen = 16;
    private final String secureRandAlgorithm ="SHA1PRNG";
    private final String cipherAlgorithm ="AES/CBC/PKCS5Padding";

    /*dummy constructor */
    public PasswordBasedEncryption(){}
    /* generate SecretKey from a user supplied masterpassword */
    private SecretKey generateKey(String key) {
        SecretKey secretKey = null;
        try {
            /* get a SecretKeyFactory  object for the specified algorithm. PBKDF2
            applies a Pseudo random function to a combination of the masterkey
            and a salt and repeates the process "iterations" times */
            SecretKeyFactory pbeSecretkeyfactory
                    = SecretKeyFactory.getInstance(keyAlgorithm);
     
            /* compute salt from the masterkey */
            byte[] salt = digest(key);
      
            /* PBEKeySpec is a wrapper for password based keys*/
            KeySpec ks = new PBEKeySpec(key.toCharArray(), salt, iterations, keySize);
           
            /* generate a secrte key object from the provided key material */
            PBEKey pbeKey = (PBEKey)pbeSecretkeyfactory.generateSecret(ks);
            /* return the key in its primary encoding format */
            byte[] keyData = pbeKey.getEncoded();
            /* create an AES key using the key material generated from PBKDF2 */
            secretKey = new SecretKeySpec(keyData, AESKeyAlgorithm);
        
        } catch (Exception e) {
           System.out.println("\bInvalid MasterKey !");
        }
        return secretKey;
    }

    private byte[] digest(String key){
        MessageDigest md = null;
        try{
            md = MessageDigest.getInstance(MDAlgorithm);
            md.update(key.getBytes());
        }catch(Exception e){
           System.out.println("\bInvalid MasterKey !");
        }
        return md.digest();
    }

     /* encrypt */
    public String encrypt(String textToEncrypt, String masterkey) {
        SecretKey key = generateKey(masterkey);
        byte[] ciphertext = null;
        byte[] iv = new byte[ivLen];
        int outputLenUpdate,outputLenFinal,outputLenTotal;

        try {
            /* SecureRandom provides a cryptographically strong pseudo-random
            number generator (PRNG) */
            SecureRandom secureRandom
                    = SecureRandom.getInstance(secureRandAlgorithm);
            /* generate 16 bytes of initialization vector */
            secureRandom.nextBytes(iv);
            /* obtain a cipher for the specified algorithm */
            Cipher encryptionCipher = Cipher.getInstance(cipherAlgorithm);
            /* IvParameterSpec specifies an initialization vector */
            IvParameterSpec ivParamSpec = new IvParameterSpec(iv);
            /* initialize the Cipher with a key and a source of randomness */
            encryptionCipher.init(Cipher.ENCRYPT_MODE, key, ivParamSpec);
            /* return buffer size required to hold the result of a
            update/doFinal operation */
            int cipherTextLen
                    = encryptionCipher.getOutputSize(textToEncrypt.length());
            /* create the buffer to hold the encrypted content */
            ciphertext = new byte[cipherTextLen];
    
            /*  Encrypt the data.  The call to update() will encrypt as much
            data as possible.  If there are not enough bytes to fill a
            whole block, the extra bytes will be kept for the next call to
            update(), or a call to doFinal() */
            outputLenUpdate =
                    encryptionCipher.update(textToEncrypt.getBytes(), 0,
                    textToEncrypt.length(), ciphertext, 0);
            /* finish the encryption by calling doFinal() which will apply any
            necessary padding to the input data */
            outputLenFinal = encryptionCipher.doFinal(ciphertext, outputLenUpdate);
            outputLenTotal = outputLenUpdate + outputLenFinal;

            /* Adjust the size of the cipher text array if fewer bytes were used
            than expected */
            if (outputLenTotal != ciphertext.length) {
                byte[] cipherTextCorrectLen = new byte[outputLenTotal];
                System.arraycopy(ciphertext, 0, cipherTextCorrectLen, 0,outputLenTotal);
                ciphertext = cipherTextCorrectLen;
            }
        } catch (Exception e) {
           System.out.println("\bInvalid Masterkey !");
        }
       return Base64.encode(iv) + Base64.encode(ciphertext);
    }

    /* decrypt */
    public String decrypt(String textToDecrypt, String masterkey) {
        Key key = generateKey(masterkey);
        byte[] iv = new byte[ivLen];
        byte[] plaintext = null;

        try {
            /* obtain a cipher for the specified algorithm */
            Cipher decryptionCipher = Cipher.getInstance(cipherAlgorithm);
            /* extract ciphertext in bytes. Required to extract the first 16
            bytes iv */
            byte[] ivAndCipherArr = Base64.decode(textToDecrypt);
            /* allocate exactly 16 bytes of iv array */
            byte[] cipherArr = new byte[ivAndCipherArr.length - ivLen];
            /* copy over iv bytes */
            System.arraycopy(ivAndCipherArr, 0, iv, 0, ivLen);
            /* copy over ciphertext bytes */
            System.arraycopy(ivAndCipherArr, ivLen, cipherArr,
                    0, ivAndCipherArr.length - ivLen);
            /* IvParameterSpec specifies an initialization vector  */
            IvParameterSpec ivParamSpec = new IvParameterSpec(iv);
            /* initialize the Cipher with a key and a source of randomness */
            decryptionCipher.init(Cipher.DECRYPT_MODE, key, ivParamSpec);
            /* return buffer size required to hold the result of a
            update/doFinal operation */
            int plainTextLen
                    = decryptionCipher.getOutputSize(cipherArr.length);
            /* allocate buffer */
            plaintext = new byte[plainTextLen];
            /*  decrypt the data.  The call to update() will decrypt as much
            data as is possible.  If there are not enough bytes to fill a
            whole block, the extra bytes will be kept for the next call to
            update(), or a call to doFinal() */
            int outputLenUpdate = decryptionCipher.update(
                    cipherArr, 0, cipherArr.length, plaintext, 0);
             
            /* finish the decryption by calling doFinal() which will apply any
            necessary padding to the input data */
             
            int outputLenFinal = decryptionCipher.doFinal(plaintext, outputLenUpdate);
            int outputLenTotal = outputLenUpdate + outputLenFinal;

            /* Adjust the size of the plain text array if fewer bytes were used
            than expected */
            if (outputLenTotal != cipherArr.length) {
                byte[] plaintextCorrectLen = new byte[outputLenTotal];
                System.arraycopy(plaintext, 0, plaintextCorrectLen, 0,
                        outputLenTotal);
                plaintext = plaintextCorrectLen;
            }
        } catch (Exception e) {
            System.out.println("\bInvalid MasterKey !");
            /* decryption done only during agent run: stop further processing */
            System.exit(1);
        }
        return convert(plaintext);
    }
    
    private static String convert(byte[] plaintext){
        StringBuffer stringBuffer = new StringBuffer();
        for (int i = 0; i < plaintext.length; i++) {
            stringBuffer.append((char) plaintext[i]);
        }
        return stringBuffer.toString();
    }
}
