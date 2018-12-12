package ee.ria.idp;


import ee.ria.idp.config.IntegrationTest;
import ee.ria.idp.config.TestIdpProperties;
import ee.ria.idp.model.EidasFlow;
import ee.ria.idp.steps.Requests;
import io.restassured.path.xml.XmlPath;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.security.KeyStore;
import java.security.Security;
import java.util.List;

import static io.restassured.path.xml.config.XmlPathConfig.xmlPathConfig;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@SpringBootTest(classes = CommonMetadataIntegrationTest.class)
@Category(IntegrationTest.class)
public class CommonMetadataIntegrationTest extends TestsBase {
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
    public void metap1_hasValidSignature() {
        try {
            validateMetadataSignature(Requests.getMetadataBody(flow));
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Metadata must have valid signature:  " + e.getMessage());
        }
    }

    @Test
    public void metap1_verifySamlMetadataSchema() {
        assertTrue("Metadata must be based on urn:oasis:names:tc:SAML:2.0:metadata schema", Requests.validateMetadataSchema(flow));
    }

    @Test
    public void metap1_verifySamlMetadataIdentifier() {
        String response = Requests.getMetadataBody(flow);
        XmlPath xmlPath = new XmlPath(response).using(xmlPathConfig().namespaceAware(false));
        assertEquals("The namespace should be expected", "urn:oasis:names:tc:SAML:2.0:metadata", xmlPath.getString("EntityDescriptor.@xmlns:md"));
    }

    @Test
    public void metap1_verifyUsedDigestAlgosInSignature() {
        XmlPath xmlPath = Requests.getMetadataBodyXML(flow);

        List<String> digestMethods = xmlPath.getList("EntityDescriptor.Signature.SignedInfo.Reference.DigestMethod.@Algorithm");
        assertThat("One of the accepted digest algorithms must be present", digestMethods,
                anyOf(hasItem("http://www.w3.org/2001/04/xmlenc#sha512"), hasItem("http://www.w3.org/2001/04/xmlenc#sha256")));
    }

    @Ignore("Missing MGF1 on RSA signatures")
    @Test
    public void metap1_verifyUsedSignatureAlgosInSignature() {
        XmlPath xmlPath = Requests.getMetadataBodyXML(flow);

        List<String> signingMethods = xmlPath.getList("EntityDescriptor.Signature.SignedInfo.SignatureMethod.@Algorithm");
        assertThat("One of the accepted signing algorithms must be present", signingMethods,
                anyOf(hasItem("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"), hasItem("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"),
                        hasItem("http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1"), hasItem("http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1")));
    }

    @Ignore("entity ID do not match. Configuration issue?")
    @Test
    public void metap2_mandatoryValuesArePresentInEntityDescriptor() {
        XmlPath xmlPath = getMetadataBodyXML();
        assertThat("The entityID must be the same as entpointUrl", xmlPath.getString("EntityDescriptor.@entityID"), endsWith(testEidasIdpProperties.getIdpMetadataUrl()));
    }

    @Test //TODO: Should the uncommented things be present?
    public void metap2_mandatoryValuesArePresentInIdpssoDescriptor() {
        XmlPath xmlPath = Requests.getMetadataBodyXML(flow);
//        assertEquals("Authentication requests signing must be: true", "true", xmlPath.getString("EntityDescriptor.IDPSSODescriptor.@AuthnRequestsSigned"));
//        assertEquals("Authentication assertions signing must be: true", "true", xmlPath.getString("EntityDescriptor.IDPSSODescriptor.@WantAssertionsSigned"));
        assertEquals("Enumeration must be: SAML 2.0", "urn:oasis:names:tc:SAML:2.0:protocol",
                xmlPath.getString("EntityDescriptor.IDPSSODescriptor.@protocolSupportEnumeration"));
    }

    @Ignore("Encryption certificate configuration seems not to work properly")
    @Test
    public void metap2_certificatesArePresentInSpssoDescriptorBlock() {
        XmlPath xmlPath = Requests.getMetadataBodyXML(flow);
        String signingCertificate = xmlPath.getString("**.findAll {it.@use == 'signing'}.KeyInfo.X509Data.X509Certificate");
        String encryptionCertificate = xmlPath.getString("**.findAll {it.@use == 'encryption'}.KeyInfo.X509Data.X509Certificate");
        assertThat("Signing certificate must be present", signingCertificate, startsWith("MII"));
        assertTrue("Signing certificate must be valid", isCertificateValid(signingCertificate));
        assertThat("Encryption certificate must be present", encryptionCertificate, startsWith("MII"));
        assertTrue("Encryption certificate must be valid", isCertificateValid(encryptionCertificate));
        assertThat("Signing and encryption certificates must be different", signingCertificate, not(equalTo(encryptionCertificate)));
    }

    @Ignore("All three types are presented")
    @Test
    public void metap2_nameIdFormatIsCorrectInIDPSSODescriptor() {
        XmlPath xmlPath = Requests.getMetadataBodyXML(flow);
        assertEquals("Name ID format should be: unspecified", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                xmlPath.getString("EntityDescriptor.IDPSSODescriptor.NameIDFormat"));
    }

    @Test
    public void metap2_mandatoryValuesArePresentInSingleSignOnService() {
        XmlPath xmlPath = Requests.getMetadataBodyXML(flow);
        assertEquals("The binding must be: HTTP-POST", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                xmlPath.getString("EntityDescriptor.IDPSSODescriptor.SingleSignOnService.@Binding"));
        assertThat("The Location should indicate correct return url",
                xmlPath.getString("EntityDescriptor.IDPSSODescriptor.SingleSignOnService.@Location"), endsWith(testEidasIdpProperties.getIdpStartUrl()));
    }
}
