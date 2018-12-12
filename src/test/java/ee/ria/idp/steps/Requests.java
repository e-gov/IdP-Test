package ee.ria.idp.steps;

import com.sun.org.apache.xerces.internal.dom.DOMInputImpl;
import ee.ria.idp.model.EidasFlow;
import ee.ria.idp.utils.AllureRestAssuredFormParam;
import io.qameta.allure.Step;
import io.qameta.allure.restassured.AllureRestAssured;
import io.restassured.RestAssured;
import io.restassured.config.XmlConfig;
import io.restassured.path.xml.XmlPath;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;

import java.io.InputStream;

import static io.restassured.RestAssured.config;
import static io.restassured.RestAssured.given;
import static io.restassured.config.EncoderConfig.encoderConfig;
import static io.restassured.internal.matcher.xml.XmlXsdMatcher.matchesXsdInClasspath;

public class Requests {
    @Step("Open authentication page")
    public static void getAuthenticationPage(EidasFlow flow, String samlRequest) {
        given()
                .filter(flow.getCookieFilter()).relaxedHTTPSValidation()
                .filter(new AllureRestAssuredFormParam())
                .formParam("SAMLRequest", samlRequest)
                .formParam("messageFormat", "eidas")
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .when()
                .post(flow.getTestProperties().getIdpUrl() + flow.getTestProperties().getIdpStartUrl())
                .then()
                .statusCode(200)
                .extract().response();
    }

    @Step("Get metadata")
    public static String getMetadataBody(EidasFlow flow) {
        return given()
                .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .filter(new AllureRestAssured())
                .when()
                .get(flow.getTestProperties().getIdpUrl() + flow.getTestProperties().getIdpMetadataUrl())
                .then()
                .statusCode(200)
                .extract().body().asString();
    }

    public static XmlPath getMetadataBodyXML(EidasFlow flow) {
        String metadataResponse = getMetadataBody(flow);
        XmlPath metadataXml = new XmlPath(metadataResponse);
        return metadataXml;
    }

    @Step("Get and validate metadata schema")
    public static Boolean validateMetadataSchema(EidasFlow flow) {
        given()
                .config(config().xmlConfig(XmlConfig.xmlConfig().disableLoadingOfExternalDtd()))
                .when()
                .filter(new AllureRestAssured())
                .get(flow.getTestProperties().getIdpUrl() + flow.getTestProperties().getIdpMetadataUrl())
                .then().log().ifError()
                .statusCode(200)
                .body(matchesXsdInClasspath("SPschema.xsd").using(new ClasspathResourceResolver()));
        return true;
    }

    public static class ClasspathResourceResolver implements LSResourceResolver {
        @Override
        public LSInput resolveResource(String type, String namespaceURI, String publicId, String systemId, String baseURI) {
            InputStream resource = ClassLoader.getSystemResourceAsStream(systemId);
            return new DOMInputImpl(publicId, systemId, baseURI, resource, null);
        }
    }
}
