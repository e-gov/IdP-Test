package ee.ria.idp.steps;


import ee.ria.idp.config.OpenSAMLConfiguration;
import ee.ria.idp.model.EidasFlow;
import ee.ria.idp.utils.AllureRestAssuredFormParam;
import ee.ria.idp.utils.SamlSigantureUtils;
import io.qameta.allure.Step;
import io.restassured.RestAssured;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.joda.time.DateTime;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static io.restassured.RestAssured.given;
import static io.restassured.config.EncoderConfig.encoderConfig;

public class MobileId {
    @Step("Authenticate with Mobile-ID")
    public static org.opensaml.saml.saml2.core.Response authenticateWithMobileID(EidasFlow flow, String samlRequest, String idCode, String mobNo, String language) throws InterruptedException, UnmarshallingException, XMLParserException {
        given()
                .filter(flow.getCookieFilter()).relaxedHTTPSValidation()
                .filter(new AllureRestAssuredFormParam())

                .formParam("SAMLRequest", samlRequest)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .log().all()
                .when()
                .post(flow.getTestProperties().getIdpMidWelcomeUrl())
                .then()
                .log().all()
                .extract().response();

        io.restassured.response.Response response = given()
                .filter(flow.getCookieFilter()).relaxedHTTPSValidation()
                .filter(new AllureRestAssuredFormParam())
                .formParam("SAMLRequest", samlRequest)
                .formParam("personalCode", idCode)
                .formParam("phoneNumber", mobNo)
                .formParam("lang", language)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .when()
                .post(flow.getTestProperties().getIdpMidAuthUrl())
                .then()
                .extract().response();

        String sessionToken = response.getBody().htmlPath().getString("**.findAll { it.@name == 'sessionToken' }[0].@value");

        String samlResponse = pollForAuthentication(flow, sessionToken, 7000);

        String decodedSamlResponse = new String(Base64.getDecoder().decode(samlResponse), StandardCharsets.UTF_8);
        SamlSigantureUtils.validateSamlResponseSignature(decodedSamlResponse);
        org.opensaml.saml.saml2.core.Response samlResponseObj = getSamlResponse(decodedSamlResponse);
        return samlResponseObj;
    }

    @Step("Poll Mobile-ID authentication")
    protected static String pollForAuthentication(EidasFlow flow, String sessionToken, Integer intervalMillis) throws InterruptedException {
        DateTime endTime = new DateTime().plusMillis(intervalMillis * 3 + 200);
        while (new DateTime().isBefore(endTime)) {
            Thread.sleep(intervalMillis);
            io.restassured.response.Response response = given()
                    .filter(flow.getCookieFilter())
                    .filter(new AllureRestAssuredFormParam())
                    .relaxedHTTPSValidation()
                    .redirects().follow(false)
                    .formParam("sessionToken", sessionToken)
                    .log().all()
                    .when()
                    .post(flow.getTestProperties().getIdpMidCheckUrl())
                    .then()
                    .log().all()
                    .extract().response();
            if (response.statusCode() == 200) {
                return response.getBody().htmlPath().getString("**.findAll { it.@name == 'SAMLResponse' }[0].@value");
            }
        }
        throw new RuntimeException("No MID response in: " + (intervalMillis * 3 + 200) + " millis");
    }

    //TODO: utility
    protected static org.opensaml.saml.saml2.core.Response getSamlResponse(String samlResponse) throws XMLParserException, UnmarshallingException {
        return (org.opensaml.saml.saml2.core.Response) XMLObjectSupport.unmarshallFromInputStream(
                OpenSAMLConfiguration.getParserPool(), new ByteArrayInputStream(samlResponse.getBytes(StandardCharsets.UTF_8)));
    }

}