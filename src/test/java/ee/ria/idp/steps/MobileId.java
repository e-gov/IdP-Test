package ee.ria.idp.steps;


import ee.ria.idp.model.EidasFlow;
import ee.ria.idp.utils.AllureRestAssuredFormParam;
import ee.ria.idp.utils.OpenSAMLUtils;
import ee.ria.idp.utils.SamlSigantureUtils;
import io.qameta.allure.Step;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.joda.time.DateTime;
import org.opensaml.core.xml.io.UnmarshallingException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static io.restassured.RestAssured.given;
import static io.restassured.config.EncoderConfig.encoderConfig;

public class MobileId {
    @Step("Authenticate with Mobile-ID")
    public static org.opensaml.saml.saml2.core.Response authenticateWithMobileID(EidasFlow flow, String samlRequest, String idCode, String mobNo, String language) throws InterruptedException, UnmarshallingException, XMLParserException {
        openMidWelcome(flow, samlRequest);

        io.restassured.response.Response response = submitMidLogin(flow, samlRequest, idCode, mobNo, language);

        String sessionToken = response.getBody().htmlPath().getString("**.findAll { it.@name == 'sessionToken' }[0].@value");

        String samlResponse = pollForAuthentication(flow, sessionToken, 5000);

        String decodedSamlResponse = new String(Base64.getDecoder().decode(samlResponse), StandardCharsets.UTF_8);
        SamlSigantureUtils.validateSamlResponseSignature(decodedSamlResponse);
        org.opensaml.saml.saml2.core.Response samlResponseObj = OpenSAMLUtils.getSamlResponse(decodedSamlResponse);
        return samlResponseObj;
    }

    @Step("Authenticate legal person with Mobile-ID")
    public static org.opensaml.saml.saml2.core.Response authenticateLegalPersonWithMobileID(EidasFlow flow, String samlRequest, String idCode, String mobNo, String language, String legalPersonIdentifier) throws InterruptedException, UnmarshallingException, XMLParserException {
        openMidWelcome(flow, samlRequest);

        io.restassured.response.Response response = submitMidLogin(flow, samlRequest, idCode, mobNo, language);

        String sessionToken = response.getBody().htmlPath().getString("**.findAll { it.@name == 'sessionToken' }[0].@value");

        pollLegalPersonForAuthentication(flow, sessionToken, 5000);
        Steps.getLegalList(flow).then().statusCode(200);
        Response loginResponse = Steps.confirmLegalPerson(flow, legalPersonIdentifier);
        String samlResponse = loginResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'SAMLResponse' }[0].@value");
        String decodedSamlResponse = new String(Base64.getDecoder().decode(samlResponse), StandardCharsets.UTF_8);
        SamlSigantureUtils.validateSamlResponseSignature(decodedSamlResponse);
        org.opensaml.saml.saml2.core.Response samlResponseObj = OpenSAMLUtils.getSamlResponse(decodedSamlResponse);
        return samlResponseObj;
    }

    @Step("Authenticate legal person with Mobile-ID")
    public static Response legalPersonListWithMobileID(EidasFlow flow, String samlRequest, String idCode, String mobNo, String language) throws InterruptedException, UnmarshallingException, XMLParserException {
        openMidWelcome(flow, samlRequest);

        io.restassured.response.Response response = submitMidLogin(flow, samlRequest, idCode, mobNo, language);

        String sessionToken = response.getBody().htmlPath().getString("**.findAll { it.@name == 'sessionToken' }[0].@value");

        pollLegalPersonForAuthentication(flow, sessionToken, 5000);
        return Steps.getLegalList(flow);
    }


    @Step("Authenticate with Mobile-ID")
    public static Response authenticateWithMobileIdError(EidasFlow flow, String samlRequest, String idCode, String mobNo, String language) throws InterruptedException, UnmarshallingException, XMLParserException {
        openMidWelcome(flow, samlRequest);
        return submitMidLogin(flow, samlRequest, idCode, mobNo, language);
    }

    @Step("Open MID welcome page")
    public static Response openMidWelcome(EidasFlow flow, String samlRequest) {
        return given()
                .filter(flow.getCookieFilter()).relaxedHTTPSValidation()
                .filter(new AllureRestAssuredFormParam())

                .formParam("SAMLRequest", samlRequest)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .when()
                .post(flow.getTestProperties().getIdpUrl() + flow.getTestProperties().getIdpMidWelcomeUrl())
                .then()
                .extract().response();
    }

    @Step("Submit MID login")
    public static Response submitMidLogin(EidasFlow flow, String samlRequest, String idCode, String mobNo, String language) {
        return given()
                .filter(flow.getCookieFilter()).relaxedHTTPSValidation()
                .filter(new AllureRestAssuredFormParam())
                .formParam("SAMLRequest", samlRequest)
                .formParam("personalCode", idCode)
                .formParam("phoneNumber", mobNo)
                .formParam("lang", language)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .when()
                .post(flow.getTestProperties().getIdpUrl() + flow.getTestProperties().getIdpMidAuthUrl())
                .then()
                .extract().response();
    }

    @Step("Poll Mobile-ID authentication")
    protected static String pollForAuthentication(EidasFlow flow, String sessionToken, Integer intervalMillis) throws InterruptedException {
        DateTime endTime = new DateTime().plusMillis(intervalMillis * 3 + 200);
        int attemptCounter = 1;
        while (new DateTime().isBefore(endTime)) {
            Thread.sleep(intervalMillis);
            io.restassured.response.Response response = pollRequest(flow, sessionToken, attemptCounter);
            attemptCounter++;
            //TODO: handle translations
            if (!response.htmlPath().getList("**.findAll { it.@type == 'submit' }").contains("Uuenda tulemust")) {
                return response.getBody().htmlPath().getString("**.findAll { it.@name == 'SAMLResponse' }[0].@value");
            }
        }
        throw new RuntimeException("No MID response in: " + (intervalMillis * 3 + 200) + " millis");
    }

    @Step("Poll Mobile-ID authentication")
    protected static void pollLegalPersonForAuthentication(EidasFlow flow, String sessionToken, Integer intervalMillis) throws InterruptedException {
        DateTime endTime = new DateTime().plusMillis(intervalMillis * 3 + 200);
        int attemptCounter = 1;
        while (new DateTime().isBefore(endTime)) {
            Thread.sleep(intervalMillis);
            io.restassured.response.Response response = pollRequest(flow, sessionToken, attemptCounter);
            attemptCounter++;
            //TODO: handle translations
            if (!response.htmlPath().getList("**.findAll { it.@type == 'submit' }").contains("Uuenda tulemust")) {
                return;
            }
        }
        throw new RuntimeException("No MID response in: " + (intervalMillis * 3 + 200) + " millis");
    }

    @Step("Poll Mobile-ID authentication")
    protected static Response pollForAuthenticationError(EidasFlow flow, String sessionToken, Integer intervalMillis) throws InterruptedException {
        DateTime endTime = new DateTime().plusMillis(intervalMillis * 3 + 200);
        int attemptCounter = 1;
        while (new DateTime().isBefore(endTime)) {
            Thread.sleep(intervalMillis);
            io.restassured.response.Response response = pollRequest(flow, sessionToken, attemptCounter);
            attemptCounter++;
            if (!response.htmlPath().getList("**.findAll { it.@type == 'submit' }").contains("Uuenda tulemust")) {
                return response;
            }
        }
        throw new RuntimeException("No MID response in: " + (intervalMillis * 3 + 200) + " millis");
    }

    @Step("Poll request {attemptCount}")
    protected static Response pollRequest(EidasFlow flow, String sessionToken, Integer attemptCount) {
        return given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssuredFormParam())
                .relaxedHTTPSValidation()
                .redirects().follow(false)
                .formParam("sessionToken", sessionToken)
                .when()
                .post(flow.getTestProperties().getIdpUrl() + flow.getTestProperties().getIdpMidCheckUrl())
                .then()
                .extract().response();
    }

    @Step("Authenticate with Mobile-ID error")
    public static Response authenticateWithMobileIdPollError(EidasFlow flow, String samlRequest, String idCode, String mobNo, String language) throws InterruptedException, UnmarshallingException, XMLParserException {
        openMidWelcome(flow, samlRequest);

        io.restassured.response.Response response = submitMidLogin(flow, samlRequest, idCode, mobNo, language);

        String sessionToken = response.getBody().htmlPath().getString("**.findAll { it.@name == 'sessionToken' }[0].@value");

        return pollForAuthenticationError(flow, sessionToken, 5000);
    }

    public static String extractError(Response response) {
        return (String) Steps.extractError(response).get(1);
    }

}
