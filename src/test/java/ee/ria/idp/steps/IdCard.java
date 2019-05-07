package ee.ria.idp.steps;


import ee.ria.idp.model.EidasFlow;
import ee.ria.idp.utils.AllureRestAssuredFormParam;
import ee.ria.idp.utils.OpenSAMLUtils;
import ee.ria.idp.utils.SamlSigantureUtils;
import io.qameta.allure.Step;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.http.cookie.Cookie;
import org.opensaml.core.xml.io.UnmarshallingException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static io.restassured.RestAssured.given;
import static io.restassured.config.EncoderConfig.encoderConfig;

public class IdCard {
    @Step("Authenticate legal person with Mobile-ID")
    public static org.opensaml.saml.saml2.core.Response authenticateLegalPersonWithIdCard(EidasFlow flow, String samlRequest, String certificate, String language, String legalPersonIdentifier) throws InterruptedException, UnmarshallingException, XMLParserException {
        openAuth(flow, samlRequest);
        Response response = submitIdCardLogin(flow, samlRequest, certificate, language);
        flow.updateSessionCookie(response.cookie("JSESSIONID"));
        Steps.getLegalList(flow).then().statusCode(200);
        Response loginResponse = Steps.confirmLegalPerson(flow, legalPersonIdentifier);
        String samlResponse = loginResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'SAMLResponse' }[0].@value");
        String decodedSamlResponse = new String(Base64.getDecoder().decode(samlResponse), StandardCharsets.UTF_8);
        SamlSigantureUtils.validateSamlResponseSignature(decodedSamlResponse);
        org.opensaml.saml.saml2.core.Response samlResponseObj = OpenSAMLUtils.getSamlResponse(decodedSamlResponse);
        return samlResponseObj;
    }

    @Step("Open authentication page")
    public static Response openAuth(EidasFlow flow, String samlRequest) {
        return given()
                .filter(flow.getCookieFilter()).relaxedHTTPSValidation()
                .filter(new AllureRestAssuredFormParam())
                .formParam("SAMLRequest", samlRequest)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .when()
                .post(flow.getTestProperties().getIdpUrl() + "/IdP/auth")
                .then()
                .extract().response();
    }

    @Step("Submit ID-Card login")
    public static Response submitIdCardLogin(EidasFlow flow, String samlRequest, String cert, String language) {
        String session = "";
        for (Cookie cookie : flow.getCookieFilter().cookieStore.getCookies()) {
            if (cookie.getName().equalsIgnoreCase("JSESSIONID") && cookie.getPath().equalsIgnoreCase("/")) {
                session = cookie.getValue();
            }
        }
        return given()
                .cookie("JSESSIONID", session).relaxedHTTPSValidation()
                .filter(new AllureRestAssuredFormParam())
                .header("SSL_CLIENT_VERIFY", "SUCCESS")
                .header("SSL_CLIENT_CERT", cert)
                .formParam("SAMLRequest", samlRequest)
                .formParam("lang", language)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .when()
                .post(flow.getTestProperties().getIdpBackEndUrl() + "/IdP/idauth")
                .then()
                .extract().response();
    }
}
