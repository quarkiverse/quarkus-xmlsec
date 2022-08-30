package io.quarkiverse.xmlsec.it;

import static io.restassured.RestAssured.given;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
public class XmlsecResourceTest {

    @Test
    public void encryptDecryptDom() throws IOException, ParserConfigurationException, SAXException, XPathExpressionException {
        try (InputStream plaintext = getClass().getClassLoader().getResourceAsStream("plaintext.xml");
                ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            IOUtils.copy(plaintext, baos);
            byte[] plainBytes = baos.toByteArray();
            byte[] encrypted = given()
                    .body(plainBytes)
                    .when()
                    .post("/xmlsec/dom/encrypt")
                    .then()
                    .statusCode(200)
                    .extract().body().asByteArray();
            try (ByteArrayInputStream in = new ByteArrayInputStream(encrypted)) {

                DocumentBuilder builder = XmlsecResource.createDocumentBuilder(false, true);
                Document encryptedDoc = builder.parse(in);

                XPathFactory xpf = XPathFactory.newInstance();
                XPath xpath = xpf.newXPath();
                xpath.setNamespaceContext(new DSNamespaceContext());
                String expression = "//xenc:EncryptedData[1]";
                Element encElement = (Element) xpath.evaluate(expression, encryptedDoc, XPathConstants.NODE);
                Assertions.assertNotNull(encElement);

                // Check the CreditCard encrypted ok
                NodeList nodeList = encryptedDoc.getElementsByTagNameNS("urn:example:po", "CreditCard");
                Assertions.assertEquals(nodeList.getLength(), 0);

            }

            /* Decrypt */
            byte[] decrypted = given()
                    .body(encrypted)
                    .when()
                    .post("/xmlsec/dom/decrypt")
                    .then()
                    .statusCode(200)
                    .extract().body().asByteArray();
            try (ByteArrayInputStream in = new ByteArrayInputStream(decrypted)) {

                DocumentBuilder builder = XmlsecResource.createDocumentBuilder(false, true);
                Document decryptedDoc = builder.parse(in);
                // Check the CreditCard decrypted ok
                NodeList nodeList = decryptedDoc.getElementsByTagNameNS("urn:example:po", "CreditCard");
                Assertions.assertEquals(nodeList.getLength(), 1);
            }

        }

    }
}
