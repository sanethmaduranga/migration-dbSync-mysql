/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.migration.dbsync;

import org.apache.axiom.om.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import javax.crypto.Cipher;

public class CryptoUtil {

    private static final String RSA_ENCRYPTION_ALGORITHM = "RSA";
    private static final String BC_CRYPTO_PROVIDER = "BC";
    private static final String KEYSTORE_TYPE_JAVA = "JKS";

    public static String encrypt(String plaintext, KeyStore keyStore, String keyAlias) throws Exception {

        String encryptedText = null;
        try {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
            Certificate[] certs = keyStore.getCertificateChain(keyAlias);
            Cipher cipher = Cipher.getInstance(RSA_ENCRYPTION_ALGORITHM, BC_CRYPTO_PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, certs[0].getPublicKey());
            encryptedText = Base64.encode(cipher.doFinal(plaintext.getBytes()));
        } catch (Exception e) {
            throw new Exception("Error occurred during encryption", e);
        }
        return encryptedText;
    }

    public static String decrypt(String encryptedText, KeyStore keyStore, String keyAlias, String keyPassword)
            throws Exception {

        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        byte[] cipherText = Base64.decode(encryptedText);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias,
                keyPassword.toCharArray());

        Cipher cipher = Cipher.getInstance(RSA_ENCRYPTION_ALGORITHM, BC_CRYPTO_PROVIDER);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] cipherbyte = cipher.doFinal(cipherText);
        return new String(cipherbyte);
    }

    public static KeyStore getKeyStore(String filePath, String keyStorePassword) throws Exception {

        String file = filePath;
        KeyStore keyStore = null;
        try (FileInputStream in = new FileInputStream(file)) {
            keyStore = KeyStore.getInstance(KEYSTORE_TYPE_JAVA);
            keyStore.load(in, keyStorePassword.toCharArray());
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new Exception("Error occurred while reading the keystore", e);
        }
        return keyStore;
    }
}
