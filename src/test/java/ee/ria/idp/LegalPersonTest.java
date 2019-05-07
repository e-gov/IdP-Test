package ee.ria.idp;


import ee.ria.idp.config.IntegrationTest;
import ee.ria.idp.config.TestIdpProperties;
import ee.ria.idp.model.EidasFlow;
import ee.ria.idp.model.Representative;
import ee.ria.idp.model.RepresentativeData;
import ee.ria.idp.steps.*;
import io.qameta.allure.Flaky;
import io.restassured.response.Response;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.saml2.core.Assertion;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.Security;
import java.util.stream.Collectors;

import static ee.ria.idp.config.EidasTestStrings.*;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;

@SpringBootTest(classes = LegalPersonTest.class)
@Category(IntegrationTest.class)
public class LegalPersonTest extends TestsBase {

    @Autowired
    private ResourceLoader resourceLoader;
    private static boolean setupComplete = false;
    private EidasFlow flow;
    private static RepresentativeData data;

    @Before
    public void setUp() throws Exception {
        if (!setupComplete) {
            initialize();
            setupComplete = true;
        }
        flow = new EidasFlow();
        setupFlow(flow, testEidasIdpProperties);
    }

    void setupFlow(EidasFlow flow, TestIdpProperties properties) {
        flow.setResourceLoader(resourceLoader);
        flow.setEncryptionCredential(encryptionCredential);
        flow.setDecryptionCredential(decryptionCredential);
        flow.setSignatureCredential(signatureCredential);
        flow.setup(properties);
    }

    public void initialize() throws Exception {
        InitializationService.initialize();
        Security.addProvider(new BouncyCastleProvider());
        Yaml yaml = new Yaml(new Constructor(RepresentativeData.class));
        data = (RepresentativeData) yaml.load(resourceLoader.getResource("testdata.yml").getInputStream());
        try {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            Resource resource = resourceLoader.getResource(testEidasIdpProperties.getKeystore());
            keystore.load(resource.getInputStream(), testEidasIdpProperties.getKeystorePass().toCharArray());
            signatureCredential = getCredential(keystore, testEidasIdpProperties.getRequestSigningKeyId(), testEidasIdpProperties.getRequestSigningKeyPass());
            decryptionCredential = getCredential(keystore, testEidasIdpProperties.getResponseDecryptionKeyId(), testEidasIdpProperties.getResponseDecryptionKeyPass());
            encryptionCredential = getEncryptionCredentialFromMetaData(getMetadataBody());

        } catch (Exception e) {
            throw new RuntimeException("Something went wrong initializing credentials:", e);
        }
    }

    @Test
    @Flaky
    public void legal1_xRoadDevelopmentEnvironment() throws Exception {
        Representative representative = data.map.get("single_response");
        XRoadMock.useAsProxy(flow);
        String samlRequest = Steps.getLegalPersonAuthnRequestWithDefault(flow);
        Requests.getAuthenticationPage(flow, samlRequest);

        org.opensaml.saml.saml2.core.Response samlResponse = IdCard.authenticateLegalPersonWithIdCard(flow, samlRequest, representative.getCertificate(), "", representative.getCompanies().get(0).getCode());

        Assertion assertion = decryptAssertion(samlResponse.getEncryptedAssertions().get(0));
        Steps.logSamlResponse(flow, samlResponse);

        assertEquals("Correct LOA is returned", LOA_HIGH, getLoaValue(assertion));
        assertEquals("Correct family name is returned", representative.getSurname(), getAttributeValue(assertion, FN_REPRESENTATIVE_FAMILY));
        assertEquals("Correct first name is returned", representative.getForename(), getAttributeValue(assertion, FN_REPRESENTATIVE_FIRST));
        assertEquals("Correct id code is returned", representative.getCode(), getAttributeValue(assertion, FN_REPRESENTATIVE_PNO));
        assertEquals("Correct birth date is returned", representative.getDateOfBirth(), getAttributeValue(assertion, FN_REPRESENTATIVE_DATE));
        assertEquals("Correct legal person identifier is returned", representative.getCompanies().get(0).getCode(), getAttributeValue(assertion, FN_LEGAL_PNO));
        assertEquals("Correct legal person name is returned", representative.getCompanies().get(0).getName(), getAttributeValue(assertion, FN_LEGAL_NAME));
    }

    @Test
    public void legal2_singleResponseAuthenticateWithMid() throws Exception {
        XRoadMock.setResponse(flow, getResourceFileAsString(resourceLoader, "60001019906_12345678.xml"));

        String samlRequest = Steps.getLegalPersonAuthnRequestWithDefault(flow);
        Requests.getAuthenticationPage(flow, samlRequest);
        org.opensaml.saml.saml2.core.Response samlResponse = MobileId.authenticateLegalPersonWithMobileID(flow, samlRequest, "60001019906", "00000766", "", "12345678");

        Assertion assertion = decryptAssertion(samlResponse.getEncryptedAssertions().get(0));
        Steps.logSamlResponse(flow, samlResponse);

        assertEquals("Correct LOA is returned", LOA_HIGH, getLoaValue(assertion));
        assertEquals("Correct family name is returned", DEFATTR_FAMILY, getAttributeValue(assertion, FN_REPRESENTATIVE_FAMILY));
        assertEquals("Correct first name is returned", DEFATTR_FIRST, getAttributeValue(assertion, FN_REPRESENTATIVE_FIRST));
        assertEquals("Correct id code is returned", DEFATTR_PNO, getAttributeValue(assertion, FN_REPRESENTATIVE_PNO));
        assertEquals("Correct birth date is returned", DEFATTR_DATE, getAttributeValue(assertion, FN_REPRESENTATIVE_DATE));
        assertEquals("Correct legal person identifier is returned", "12345678", getAttributeValue(assertion, FN_LEGAL_PNO));
        assertEquals("Correct legal person name is returned", "Acme INC OÜ", getAttributeValue(assertion, FN_LEGAL_NAME));
    }

    @Test
    public void legal3_emptyResponse() throws Exception {
        XRoadMock.setResponse(flow, getResourceFileAsString(resourceLoader, "60001019906_empty.xml"));

        String samlRequest = Steps.getLegalPersonAuthnRequestWithDefault(flow);
        Requests.getAuthenticationPage(flow, samlRequest);
        Response legalPersonResponse = MobileId.legalPersonListWithMobileID(flow, samlRequest, "60001019906", "00000766", "");
        legalPersonResponse.then().statusCode(403).body("error", equalTo("No related legal persons found for current user"));
    }

    @Test
    public void legal4_noValidLegalPerson() throws Exception {
        XRoadMock.setResponse(flow, getResourceFileAsString(resourceLoader, "60001019906_none.xml"));

        String samlRequest = Steps.getLegalPersonAuthnRequestWithDefault(flow);
        Requests.getAuthenticationPage(flow, samlRequest);
        Response legalPersonResponse = MobileId.legalPersonListWithMobileID(flow, samlRequest, "60001019906", "00000766", "");
        legalPersonResponse.then().statusCode(403).body("error", equalTo("No related legal persons found for current user"));
    }

    @Test
    public void legal5_multipleChoiceAuthenticateWithMid() throws Exception {
        XRoadMock.setResponse(flow, getResourceFileAsString(resourceLoader, "60001019906_multiple.xml"));

        String samlRequest = Steps.getLegalPersonAuthnRequestWithDefault(flow);
        Requests.getAuthenticationPage(flow, samlRequest);
        org.opensaml.saml.saml2.core.Response samlResponse = MobileId.authenticateLegalPersonWithMobileID(flow, samlRequest, "60001019906", "00000766", "", "00000020");

        Assertion assertion = decryptAssertion(samlResponse.getEncryptedAssertions().get(0));
        Steps.logSamlResponse(flow, samlResponse);

        assertEquals("Correct LOA is returned", LOA_HIGH, getLoaValue(assertion));
        assertEquals("Correct family name is returned", DEFATTR_FAMILY, getAttributeValue(assertion, FN_REPRESENTATIVE_FAMILY));
        assertEquals("Correct first name is returned", DEFATTR_FIRST, getAttributeValue(assertion, FN_REPRESENTATIVE_FIRST));
        assertEquals("Correct id code is returned", DEFATTR_PNO, getAttributeValue(assertion, FN_REPRESENTATIVE_PNO));
        assertEquals("Correct birth date is returned", DEFATTR_DATE, getAttributeValue(assertion, FN_REPRESENTATIVE_DATE));
        assertEquals("Correct legal person identifier is returned", "00000020", getAttributeValue(assertion, FN_LEGAL_PNO));
        assertEquals("Correct legal person name is returned", "Acme INC OÜ 20", getAttributeValue(assertion, FN_LEGAL_NAME));
    }

    public static String getResourceFileAsString(ResourceLoader resourceLoader, String fileName) throws IOException {
        InputStream is = resourceLoader.getResource(fileName).getInputStream();
        if (is != null) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(is));
            return reader.lines().collect(Collectors.joining());
        }
        return null;
    }
    //multiple matches, choose one

}
