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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;

import org.apache.xml.security.Init;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.XMLUtils;
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
public enum EnvelopedSigning {
    dom() {

        /**
         * Encrypt the document using the DOM API of Apache Santuario - XML Security for Java.
         * It encrypts a list of QNames that it finds in the Document via XPath. If a wrappingKey
         * is supplied, this is used to encrypt the encryptingKey + place it in an EncryptedKey
         * structure.
         */
        @Override
        public byte[] sign(byte[] plaintext, Key key, X509Certificate cert) {
            try (ByteArrayInputStream in = new ByteArrayInputStream(plaintext)) {
                Document document = Encryption.createDocumentBuilder(false, false).parse(in);

                XMLSignature sig = new XMLSignature(document, "", "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                        "http://www.w3.org/2001/10/xml-exc-c14n#");
                Element root = document.getDocumentElement();
                root.appendChild(sig.getElement());

                Transforms transforms = new Transforms(document);
                transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
                transforms.addTransform("http://www.w3.org/2001/10/xml-exc-c14n#");

                sig.addDocument("", transforms, "http://www.w3.org/2000/09/xmldsig#sha1");

                sig.sign(key);

                if (cert != null) {
                    sig.addKeyInfo(cert);
                }

                try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                    XMLUtils.outputDOM(document, baos);
                    return baos.toByteArray();
                }

            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        }

        /**
         * Decrypt the document using the DOM API of Apache Santuario - XML Security for Java.
         */
        @Override
        public void verify(byte[] encrypted, Key privateKey, X509Certificate cert) {
            try (ByteArrayInputStream in = new ByteArrayInputStream(encrypted)) {
                DocumentBuilder builder = Encryption.createDocumentBuilder(false, false);
                Document document = builder.parse(in);

                // Verify using DOM
                List<QName> namesToSign = new ArrayList<QName>();
                namesToSign.add(new QName("urn:example:po", "PurchaseOrder"));
                NodeList sigs = document.getDocumentElement().getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#",
                        "Signature");
                if (sigs.getLength() == 0) {
                    throw new IllegalStateException(
                            "No Signature element found in " + new String(encrypted, StandardCharsets.UTF_8));
                }
                Element sigElement = (Element) sigs.item(0);

                XMLSignature signature = new XMLSignature(sigElement, "");

                // Check we have a KeyInfo
                if (signature.getKeyInfo() == null) {
                    throw new IllegalStateException("Invalid signature: no key info");
                }
                if (!signature.checkSignatureValue(cert)) {
                    throw new IllegalStateException("Invalid signature");
                }

            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    };

    static {
        Init.init();
    }

    public abstract byte[] sign(byte[] plaintext, Key key, X509Certificate cert);

    public abstract void verify(byte[] encrypted, Key privateKey, X509Certificate cert);

}
