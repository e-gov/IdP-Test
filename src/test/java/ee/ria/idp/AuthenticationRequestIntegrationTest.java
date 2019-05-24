package ee.ria.idp;


import ee.ria.idp.config.IntegrationTest;
import ee.ria.idp.config.TestIdpProperties;
import ee.ria.idp.model.EidasFlow;
import ee.ria.idp.model.RepresentativeData;
import ee.ria.idp.steps.IdCard;
import ee.ria.idp.steps.MobileId;
import ee.ria.idp.steps.Requests;
import ee.ria.idp.steps.Steps;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import javax.xml.transform.TransformerException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.Security;
import java.util.stream.Collectors;

import static ee.ria.idp.config.EidasTestStrings.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;

@SpringBootTest(classes = AuthenticationRequestIntegrationTest.class)
@Category(IntegrationTest.class)
public class AuthenticationRequestIntegrationTest extends TestsBase {

    @Autowired
    private ResourceLoader resourceLoader;
    private static boolean setupComplete = false;
    private EidasFlow flow;
    private static RepresentativeData data;


    @Before
    public void setUp() throws InitializationException, IOException {
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

    public void initialize() throws InitializationException, IOException {
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
    public void idp1_authenticateWithMidSuccess() throws InterruptedException, UnmarshallingException, XMLParserException, TransformerException {
        String samlRequest = Steps.getAuthnRequestWithDefault(flow);
        Requests.getAuthenticationPage(flow, samlRequest);
        org.opensaml.saml.saml2.core.Response samlResponse = MobileId.authenticateWithMobileID(flow, samlRequest, "60001019906", "00000766", "");
        Assertion assertion = decryptAssertion(samlResponse.getEncryptedAssertions().get(0));
        Steps.logSamlResponse(flow, samlResponse);

        assertEquals("Correct LOA is returned", LOA_HIGH, getLoaValue(assertion));
        assertEquals("Correct family name is returned", DEFATTR_FAMILY, getAttributeValue(assertion, FN_FAMILY));
        assertEquals("Correct first name is returned", DEFATTR_FIRST, getAttributeValue(assertion, FN_FIRST));
        assertEquals("Correct id code is returned", DEFATTR_PNO, getAttributeValue(assertion, FN_PNO));
        assertEquals("Correct birth date is returned", DEFATTR_DATE, getAttributeValue(assertion, FN_DATE));
    }

    @Test
    public void idp1_authenticateWithIdCardRsa2015Success() throws InterruptedException, UnmarshallingException, XMLParserException, IOException {

        String samlRequest = Steps.getAuthnRequestWithDefault(flow);
        org.opensaml.saml.saml2.core.Response samlResponse = IdCard.authenticateWithIdCard(flow, samlRequest, getResourceFileAsString(resourceLoader, "37101010021.pem"), "");
        Assertion assertion = decryptAssertion(samlResponse.getEncryptedAssertions().get(0));
        Steps.logSamlResponse(flow, samlResponse);

        assertEquals("Correct LOA is returned", LOA_HIGH, getLoaValue(assertion));
        assertEquals("Correct family name is returned", "ŽAIKOVSKI", getAttributeValue(assertion, FN_FAMILY));
        assertEquals("Correct first name is returned", "IGOR", getAttributeValue(assertion, FN_FIRST));
        assertEquals("Correct id code is returned", "37101010021", getAttributeValue(assertion, FN_PNO));
        assertEquals("Correct birth date is returned", "1971-01-01", getAttributeValue(assertion, FN_DATE));
    }

    @Test
    public void idp1_authenticateWithIdCardEcc2015Success() throws InterruptedException, UnmarshallingException, XMLParserException, IOException {


        String samlRequest = Steps.getAuthnRequestWithDefault(flow);
        org.opensaml.saml.saml2.core.Response samlResponse = IdCard.authenticateWithIdCard(flow, samlRequest, getResourceFileAsString(resourceLoader, "47101010033.pem"), "");
        Assertion assertion = decryptAssertion(samlResponse.getEncryptedAssertions().get(0));
        Steps.logSamlResponse(flow, samlResponse);

        assertEquals("Correct LOA is returned", LOA_HIGH, getLoaValue(assertion));
        assertEquals("Correct family name is returned", "MÄNNIK", getAttributeValue(assertion, FN_FAMILY));
        assertEquals("Correct first name is returned", "MARI-LIIS", getAttributeValue(assertion, FN_FIRST));
        assertEquals("Correct id code is returned", "47101010033", getAttributeValue(assertion, FN_PNO));
        assertEquals("Correct birth date is returned", "1971-01-01", getAttributeValue(assertion, FN_DATE));
    }

    @Test
    public void idp1_authenticateWithIdCardEcc2018Success() throws InterruptedException, UnmarshallingException, XMLParserException, IOException {


        String samlRequest = Steps.getAuthnRequestWithDefault(flow);
        org.opensaml.saml.saml2.core.Response samlResponse = IdCard.authenticateWithIdCard(flow, samlRequest, getResourceFileAsString(resourceLoader, "38001085718.pem"), "");
        Assertion assertion = decryptAssertion(samlResponse.getEncryptedAssertions().get(0));
        Steps.logSamlResponse(flow, samlResponse);

        assertEquals("Correct LOA is returned", LOA_HIGH, getLoaValue(assertion));
        assertEquals("Correct family name is returned", "JÕEORG", getAttributeValue(assertion, FN_FAMILY));
        assertEquals("Correct first name is returned", "JAAK-KRISTJAN", getAttributeValue(assertion, FN_FIRST));
        assertEquals("Correct id code is returned", "38001085718", getAttributeValue(assertion, FN_PNO));
        assertEquals("Correct birth date is returned", "1980-01-08", getAttributeValue(assertion, FN_DATE));
    }

    @Test
    public void idp1_authenticateWithMidWithoutIdCode() throws InterruptedException, UnmarshallingException, XMLParserException {
        String samlRequest = Steps.getAuthnRequestWithDefault(flow);
        Requests.getAuthenticationPage(flow, samlRequest);
        org.opensaml.saml.saml2.core.Response samlResponse = MobileId.authenticateWithMobileID(flow, samlRequest, "", "00000766", "");
        Assertion assertion = decryptAssertion(samlResponse.getEncryptedAssertions().get(0));
        Steps.logSamlResponse(flow, samlResponse);

        assertEquals("Correct LOA is returned", LOA_HIGH, getLoaValue(assertion));
        assertEquals("Correct family name is returned", DEFATTR_FAMILY, getAttributeValue(assertion, FN_FAMILY));
        assertEquals("Correct first name is returned", DEFATTR_FIRST, getAttributeValue(assertion, FN_FIRST));
        assertEquals("Correct id code is returned", DEFATTR_PNO, getAttributeValue(assertion, FN_PNO));
        assertEquals("Correct birth date is returned", DEFATTR_DATE, getAttributeValue(assertion, FN_DATE));
    }

    @Test
    public void mob2_mobileIdAuthenticationMidNotActivated() throws InterruptedException, XMLParserException, UnmarshallingException {
        String samlRequest = Steps.getAuthnRequestWithDefault(flow);
        Requests.getAuthenticationPage(flow, samlRequest);
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, samlRequest, "60001019928", "00000366", ""));
        assertThat(errorMessage, startsWith("Mobiil-ID autentimine ebaõnnestus"));
    }

    @Test
    public void mob2_mobileIdAuthenticationUserCertificatesRevoked() throws InterruptedException, XMLParserException, UnmarshallingException {
        String samlRequest = Steps.getAuthnRequestWithDefault(flow);
        Requests.getAuthenticationPage(flow, samlRequest);
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, samlRequest, "60001019939", "00000266", ""));
        assertThat(errorMessage, startsWith("Mobiil-ID autentimine ebaõnnestus"));
    }

    @Test
    public void mob2_mobileIdAuthenticationRequestToPhoneFailed() throws Exception {
        String samlRequest = Steps.getAuthnRequestWithDefault(flow);
        Requests.getAuthenticationPage(flow, samlRequest);
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, samlRequest, "60001019947", "07110066", ""));
        assertThat(errorMessage, startsWith("Mobiil-ID autentimine ebaõnnestus"));
    }

    @Test
    public void mob2_mobileIdAuthenticationTechnicalError() throws Exception {
        String samlRequest = Steps.getAuthnRequestWithDefault(flow);
        Requests.getAuthenticationPage(flow, samlRequest);
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, samlRequest, "60001019961", "00000666", ""));
        assertThat(errorMessage, startsWith("Mobiil-ID autentimine ebaõnnestus"));
    }

    @Test
    public void mob2_mobileIdAuthenticationSimApplicationError() throws Exception {
        String samlRequest = Steps.getAuthnRequestWithDefault(flow);
        Requests.getAuthenticationPage(flow, samlRequest);
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, samlRequest, "60001019972", "01200266", ""));
        assertThat(errorMessage, startsWith("Mobiil-ID autentimine ebaõnnestus"));
    }

    @Test
    public void mob2_mobileIdAuthenticationPhoneNotInNetwork() throws Exception {
        String samlRequest = Steps.getAuthnRequestWithDefault(flow);
        Requests.getAuthenticationPage(flow, samlRequest);
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, samlRequest, "60001019983", "13100266", ""));
        assertThat(errorMessage, startsWith("Mobiil-ID autentimine ebaõnnestus"));
    }

    @Test
    public void mob3_mobileIdAuthenticationUserCancels() throws Exception {
        String samlRequest = Steps.getAuthnRequestWithDefault(flow);
        Requests.getAuthenticationPage(flow, samlRequest);
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, samlRequest, "60001019950", "01100266", ""));
        assertThat(errorMessage, startsWith("Mobiil-ID autentimine ebaõnnestus"));
    }


    /**
     * Verifying that user receives proper error message when user inserts invalid id code
     */
    @Test
    public void mob3_mobileIdAuthenticationInvalidIdCode() throws InterruptedException, XMLParserException, UnmarshallingException {
        String samlRequest = Steps.getAuthnRequestWithDefault(flow);
        Requests.getAuthenticationPage(flow, samlRequest);
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, samlRequest, "66", "00000766", ""));
        assertThat(errorMessage, startsWith("Mobiil-ID autentimine ebaõnnestus"));
    }

    /**
     * Verifying that user receives proper error message when user inserts invalid phone number
     */
    @Test
    public void mob3_mobileIdAuthenticationInvalidPhoneNumber() throws InterruptedException, XMLParserException, UnmarshallingException {
        String samlRequest = Steps.getAuthnRequestWithDefault(flow);
        Requests.getAuthenticationPage(flow, samlRequest);
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, samlRequest, "123456789123", "60001019906", ""));
        assertThat(errorMessage, startsWith("Mobiil-ID autentimine ebaõnnestus"));
    }

    /**
     * Verifying that user receives proper error message when user doesn't insert phone number
     */
    @Test
    public void mob3_mobileIdAuthenticationNoMobileNo() throws InterruptedException, XMLParserException, UnmarshallingException {
        String samlRequest = Steps.getAuthnRequestWithDefault(flow);
        Requests.getAuthenticationPage(flow, samlRequest);
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, samlRequest, "60001019906", "", ""));
        assertThat(errorMessage, startsWith("Mobiil-ID autentimine ebaõnnestus"));
    }

    /**
     * Verifying that user receives proper error message when user doesn't insert id code
     */
    @Test
    @Ignore("Works without id code")
    public void mob3_mobileIdAuthenticationNoIdCode() throws InterruptedException, XMLParserException, UnmarshallingException {
        String samlRequest = Steps.getAuthnRequestWithDefault(flow);
        Requests.getAuthenticationPage(flow, samlRequest);
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, samlRequest, "", "00000766", ""));
        assertThat(errorMessage, startsWith("Mobiil-ID autentimine ebaõnnestus"));
    }

    /**
     * Verifying that user receives proper error message when user doesn't insert any parameters
     */
    @Test
    public void mob3_mobileIdAuthenticationNoParameters() throws InterruptedException, XMLParserException, UnmarshallingException {
        String samlRequest = Steps.getAuthnRequestWithDefault(flow);
        Requests.getAuthenticationPage(flow, samlRequest);
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, samlRequest, "", "", ""));
        assertThat(errorMessage, startsWith("Mobiil-ID autentimine ebaõnnestus"));
    }

    public static String getResourceFileAsString(ResourceLoader resourceLoader, String fileName) throws IOException {
        InputStream is = resourceLoader.getResource(fileName).getInputStream();
        if (is != null) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(is));
            return reader.lines().collect(Collectors.joining());
        }
        return null;
    }
}
