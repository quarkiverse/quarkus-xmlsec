/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package io.quarkiverse.xmlsec.it;

import java.security.Key;
import java.security.PublicKey;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.xml.security.Init;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Some utility methods for encrypting/decrypting documents
 * <p>
 * Adapted form <a href=
 * "https://github.com/coheigea/testcases/blob/master/apache/santuario/santuario-xml-encryption/src/test/java/org/apache/coheigea/santuario/xmlencryption/EncryptionUtils.java">https://github.com/coheigea/testcases/blob/master/apache/santuario/santuario-xml-encryption/src/test/java/org/apache/coheigea/santuario/xmlencryption/EncryptionUtils.java</a>
 * by <a href="https://github.com/coheigea">Colm O hEigeartaigh</a>
 */
public final class EncryptionUtils {

    static {
        Init.init();
    }

    private EncryptionUtils() {
        // complete
    }

    /**
     * Encrypt the document using the DOM API of Apache Santuario - XML Security for Java.
     * It encrypts a list of QNames that it finds in the Document via XPath. If a wrappingKey
     * is supplied, this is used to encrypt the encryptingKey + place it in an EncryptedKey
     * structure.
     */
    public static void encryptUsingDOM(
            Document document,
            List<QName> namesToEncrypt,
            String algorithm,
            Key encryptingKey,
            String keyTransportAlgorithm,
            PublicKey wrappingKey,
            boolean content) throws Exception {
        XMLCipher cipher = XMLCipher.getInstance(algorithm);
        cipher.init(XMLCipher.ENCRYPT_MODE, encryptingKey);

        if (wrappingKey != null) {
            XMLCipher newCipher = XMLCipher.getInstance(keyTransportAlgorithm);
            newCipher.init(XMLCipher.WRAP_MODE, wrappingKey);

            EncryptedKey encryptedKey = newCipher.encryptKey(document, encryptingKey);
            // Create a KeyInfo for the EncryptedKey
            KeyInfo encryptedKeyKeyInfo = encryptedKey.getKeyInfo();
            if (encryptedKeyKeyInfo == null) {
                encryptedKeyKeyInfo = new KeyInfo(document);
                encryptedKeyKeyInfo.getElement().setAttributeNS(
                        "http://www.w3.org/2000/xmlns/", "xmlns:dsig", "http://www.w3.org/2000/09/xmldsig#");
                encryptedKey.setKeyInfo(encryptedKeyKeyInfo);
            }
            encryptedKeyKeyInfo.add(wrappingKey);

            // Create a KeyInfo for the EncryptedData
            EncryptedData builder = cipher.getEncryptedData();
            KeyInfo builderKeyInfo = builder.getKeyInfo();
            if (builderKeyInfo == null) {
                builderKeyInfo = new KeyInfo(document);
                builderKeyInfo.getElement().setAttributeNS(
                        "http://www.w3.org/2000/xmlns/", "xmlns:dsig", "http://www.w3.org/2000/09/xmldsig#");
                builder.setKeyInfo(builderKeyInfo);
            }

            builderKeyInfo.add(encryptedKey);
        }

        for (QName nameToEncrypt : namesToEncrypt) {
            NodeList elementsToEncrypt = document.getElementsByTagName(nameToEncrypt.getLocalPart());
            for (int i = 0; i < elementsToEncrypt.getLength(); i++) {
                Element elementToEncrypt = (Element) elementsToEncrypt.item(i);
                document = cipher.doFinal(document, elementToEncrypt, content);
            }
        }
    }

    /**
     * Decrypt the document using the DOM API of Apache Santuario - XML Security for Java.
     */
    public static void decryptUsingDOM(
            Document document,
            String algorithm,
            Key privateKey) throws Exception {
        XMLCipher cipher = XMLCipher.getInstance(algorithm);
        cipher.init(XMLCipher.DECRYPT_MODE, null);
        cipher.setKEK(privateKey);

        NodeList nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart());

        for (int i = 0; i < nodeList.getLength(); i++) {
            Element ee = (Element) nodeList.item(i);
            cipher.doFinal(document, ee);
        }
    }

}
