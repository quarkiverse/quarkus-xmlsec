package io.quarkiverse.quarkus.xmlsec.it;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
public class XmlsecResourceTest {

    @Test
    public void testHelloEndpoint() {
        given()
                .when().get("/xmlsec")
                .then()
                .statusCode(200)
                .body(is("Hello xmlsec"));
    }
}
