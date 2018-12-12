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
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.security.Security;
import java.text.ParseException;

import static ee.ria.idp.config.EidasTestStrings.*;
import static io.restassured.RestAssured.baseURI;
import static io.restassured.RestAssured.port;
import static org.junit.Assert.assertEquals;

@SpringBootTest(classes = AuthenticationRequestIntegrationTest.class)
@Category(IntegrationTest.class)
public class AuthenticationRequestIntegrationTest extends TestsBase {

    @Autowired
    private ResourceLoader resourceLoader;
    private static boolean setupComplete = false;
    private EidasFlow flow;


    @Before
    public void setUp() throws InitializationException, IOException, ParseException {
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

    public void initialize() throws InitializationException, MalformedURLException {
        URL url = new URL(testEidasIdpProperties.getIdpUrl());
        port = url.getPort();
        baseURI = url.getProtocol() + "://" + url.getHost();

        Security.addProvider(new BouncyCastleProvider());
        InitializationService.initialize();
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
        String samlRequest = getAuthnRequestWithDefault();
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
}
