package ee.ria.idp.steps;

import ee.ria.idp.model.EidasFlow;
import ee.ria.idp.utils.AllureRestAssuredFormParam;
import ee.ria.idp.utils.OpenSAMLUtils;
import ee.ria.idp.utils.RequestBuilderUtils;
import ee.ria.idp.utils.SamlSigantureUtils;
import io.qameta.allure.Allure;
import io.qameta.allure.Step;
import io.qameta.allure.restassured.AllureRestAssured;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.w3c.dom.Element;

import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.util.Base64;
import java.util.List;

import static ee.ria.idp.config.EidasTestStrings.LOA_HIGH;
import static io.restassured.RestAssured.given;
import static io.restassured.config.EncoderConfig.encoderConfig;


public class Steps {
    @Step("{message}")
    public static void log(String message) {
    }

    @Step("Saml Response Contents")
    public static void logSamlResponse(EidasFlow flow, org.opensaml.saml.saml2.core.Response response) {
        Allure.addAttachment("SAML Response", "application/xml", parseXml(response.getDOM()), "xml");

        Assertion assertion = SamlSigantureUtils.decryptAssertion(flow, response.getEncryptedAssertions().get(0));
        Allure.addAttachment("Assertion", "application/xml", parseXml(assertion.getDOM()), "xml");
    }

    @Step("Create Natural Person authentication request")
    public static String getAuthnRequest(EidasFlow flow, String providerName, String destination, String consumerServiceUrl, String issuerValue, String loa) {

        AuthnRequest request = new RequestBuilderUtils().buildAuthnRequest(flow.getSignatureCredential(), providerName, destination, consumerServiceUrl, issuerValue, loa);
        String stringResponse = OpenSAMLUtils.getXmlString(request);
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml");

        SamlSigantureUtils.validateSamlReqSignature(stringResponse);
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()));
    }

    @Step("Create Legal Person authentication request")
    public static String getLegalPersonAuthnRequest(EidasFlow flow, String providerName, String destination, String consumerServiceUrl, String issuerValue, String loa) {

        AuthnRequest request = new RequestBuilderUtils().buildLegalAuthnRequest(flow.getSignatureCredential(), providerName, destination, consumerServiceUrl, issuerValue, loa);
        String stringResponse = OpenSAMLUtils.getXmlString(request);
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml");

        SamlSigantureUtils.validateSamlReqSignature(stringResponse);
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()));
    }

    @Step("Get legal person list")
    public static Response getLegalList(EidasFlow flow) {
        return given()
                .filter(flow.getCookieFilter()).relaxedHTTPSValidation()
                .filter(new AllureRestAssured())
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .when()
                .get(flow.getTestProperties().getIdpUrl() + "/IdP/legal_person")
                .then()
                .extract().response();
    }

    @Step("Confirm legal person choice")
    public static Response confirmLegalPerson(EidasFlow flow, String legalPersonIdentifier) {
        return given()
                .filter(flow.getCookieFilter()).relaxedHTTPSValidation()
                .filter(new AllureRestAssuredFormParam())
                .formParam("legalPersonId", legalPersonIdentifier)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .when()
                .post(flow.getTestProperties().getIdpUrl() + "/IdP/confirm_legal_person")
                .then()
                .statusCode(200)
                .extract().response();
    }

    public static String getLegalPersonAuthnRequestWithDefault(EidasFlow flow) {
        return getLegalPersonAuthnRequest(flow, "TestProvider",
                flow.getTestProperties().getIdpUrl() + flow.getTestProperties().getIdpStartUrl(),
                "randomUrl", flow.getTestProperties().getEidasNodeMetadata(), LOA_HIGH);
    }

    public static String getAuthnRequestWithDefault(EidasFlow flow) {
        return getAuthnRequest(flow, "TestProvider",
                flow.getTestProperties().getIdpUrl() + flow.getTestProperties().getIdpStartUrl(),
                "randomUrl", flow.getTestProperties().getEidasNodeMetadata(), LOA_HIGH);
    }


    private static String parseXml(Element xml) {
        TransformerFactory tf = TransformerFactory.newInstance();
        tf.setAttribute("indent-number", new Integer(2));

        StringWriter sw = new StringWriter();
        try {
            Transformer trans = tf.newTransformer();
            trans.setOutputProperty(OutputKeys.INDENT, "yes");
            trans.transform(new DOMSource(xml), new StreamResult(sw));
        } catch (TransformerConfigurationException e) {
            throw new RuntimeException(e);
        } catch (TransformerException e) {
            throw new RuntimeException(e);
        }
        return sw.toString();
    }

    public static List extractError(Response response) {
        /*Sample list:
        0 = "Kasutaja tuvastamine ebaõnnestus."
        1 = "Isikukood on ebakorrektses formaadis."
        2 = "\n                Intsidendi number: \n                AOO6OBRV9N0BYB6L"
        */
        return response.then().extract().response()
                .htmlPath().getList("**.findAll { it.@class=='alert alert-error' }.p");
    }

}
