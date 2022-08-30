/*
* Licensed to the Apache Software Foundation (ASF) under one or more
* contributor license agreements.  See the NOTICE file distributed with
* this work for additional information regarding copyright ownership.
* The ASF licenses this file to You under the Apache License, Version 2.0
* (the "License"); you may not use this file except in compliance with
* the License.  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package io.quarkiverse.xmlsec.it;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.xml.namespace.QName;

@Path("/xmlsec")
@ApplicationScoped
public class XmlsecResource {

    private final KeyStore keyStore;

    public XmlsecResource() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        // Set up the Key
        keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("servicestore.jks").openStream(),
                "sspass".toCharArray());
    }

    /**
     * Adapted form <a href=
     * "https://github.com/coheigea/testcases/blob/master/apache/santuario/santuario-xml-encryption/src/test/java/org/apache/coheigea/santuario/xmlencryption/EncryptionDOMTest.java">https://github.com/coheigea/testcases/blob/master/apache/santuario/santuario-xml-encryption/src/test/java/org/apache/coheigea/santuario/xmlencryption/EncryptionDOMTest.java</a>
     * by <a href="https://github.com/coheigea">Colm O hEigeartaigh</a>
     *
     * @param plaintext
     * @return
     * @throws Exception
     */
    @POST
    @Path("/{encryption}/encrypt")
    public byte[] encrypt(byte[] plaintext, @PathParam("encryption") Encryption encryption) throws Exception {
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("myservicekey");

        // Set up the secret Key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey secretKey = keygen.generateKey();

        // Encrypt using DOM
        List<QName> namesToEncrypt = new ArrayList<QName>();
        namesToEncrypt.add(new QName("urn:example:po", "PaymentInfo"));
        return encryption.encrypt(plaintext, namesToEncrypt, "http://www.w3.org/2001/04/xmlenc#aes128-cbc", secretKey,
                "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", cert.getPublicKey(), false);
    }

    /**
     * Adapted form <a href=
     * "https://github.com/coheigea/testcases/blob/master/apache/santuario/santuario-xml-encryption/src/test/java/org/apache/coheigea/santuario/xmlencryption/EncryptionDOMTest.java">https://github.com/coheigea/testcases/blob/master/apache/santuario/santuario-xml-encryption/src/test/java/org/apache/coheigea/santuario/xmlencryption/EncryptionDOMTest.java</a>
     * by <a href="https://github.com/coheigea">Colm O hEigeartaigh</a>
     *
     * @param encrypted
     * @return
     * @throws Exception
     */
    @POST
    @Path("/{encryption}/decrypt")
    public byte[] decrypt(byte[] encrypted, @PathParam("encryption") Encryption encryption) throws Exception {
        Key privateKey = keyStore.getKey("myservicekey", "skpass".toCharArray());
        return encryption.decrypt(encrypted, "http://www.w3.org/2001/04/xmlenc#aes128-cbc", privateKey);
    }

}
