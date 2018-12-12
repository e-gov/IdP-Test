package ee.ria.idp;


import ee.ria.idp.config.IntegrationTest;
import ee.ria.idp.config.TestIdpProperties;
import ee.ria.idp.model.EidasFlow;
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

import javax.xml.transform.TransformerException;
import java.security.KeyStore;
import java.security.Security;

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


    @Before
    public void setUp() throws InitializationException {
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

    public void initialize() throws InitializationException {
        InitializationService.initialize();
        Security.addProvider(new BouncyCastleProvider());
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
    public void idp1_authenticateWithMidWithoutIdCode() throws InterruptedException, UnmarshallingException, XMLParserException, TransformerException {
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
/*
    @Test
    public void mob2_mobileIdAuthenticationRequestToPhoneFailed() throws Exception {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, "07110066", "60001019947", 500));
        assertThat(errorMessage, startsWith("Teie mobiiltelefoni ei saa Mobiil-ID autentimise sõnumeid saata."));
    }

    @Test
    public void mob2_mobileIdAuthenticationTechnicalError() throws Exception {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, "00000666", "60001019961", 3000));
        assertThat(errorMessage, startsWith("Autentimine Mobiil-ID-ga ei õnnestunud. Testi oma Mobiil-ID toimimist DigiDoc3 kliendis: http://www.id.ee/index.php?id=35636"));
    }

    @Test
    public void mob2_mobileIdAuthenticationSimApplicationError() throws Exception {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, "01200266", "60001019972", 1000));
        assertThat(errorMessage, startsWith("Teie mobiiltelefoni SIM kaardiga tekkis tõrge."));
    }

    @Test
    public void mob2_mobileIdAuthenticationPhoneNotInNetwork() throws Exception {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, "13100266", "60001019983", 1000));
        assertThat(errorMessage, startsWith("Teie mobiiltelefon on levialast väljas."));
    }

    @Test
    public void mob3_mobileIdAuthenticationUserCancels() throws Exception {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, "01100266", "60001019950", 1000));
        assertThat(errorMessage, startsWith("Autentimine on katkestatud."));
    }

    */

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
        //String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, "", ""));
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
}
