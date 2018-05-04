package ee.ria.idp;

import com.sun.org.apache.xerces.internal.dom.DOMInputImpl;
import ee.ria.idp.config.IntegrationTest;
import ee.ria.idp.config.OpenSAMLConfiguration;
import ee.ria.idp.config.TestConfiguration;
import ee.ria.idp.utils.OpenSAMLUtils;
import ee.ria.idp.utils.SystemPropertyActiveProfileResolver;
import ee.ria.idp.utils.XmlUtils;
import ee.ria.idp.config.TestIdpProperties;
import ee.ria.idp.utils.RequestBuilderUtils;
import io.restassured.RestAssured;
import io.restassured.config.XmlConfig;
import io.restassured.filter.cookie.CookieFilter;
import io.restassured.path.xml.XmlPath;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.security.x509.X509Support;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static ee.ria.idp.config.EidasTestStrings.*;
import static io.restassured.RestAssured.*;
import static io.restassured.config.EncoderConfig.encoderConfig;
import static io.restassured.internal.matcher.xml.XmlXsdMatcher.matchesXsdInClasspath;

@RunWith(SpringRunner.class)
@Category(IntegrationTest.class)
@ContextConfiguration(classes = TestConfiguration.class)
@ActiveProfiles( profiles = {"dev"}, resolver = SystemPropertyActiveProfileResolver.class)
public abstract class TestsBase {

    @Autowired
    private ResourceLoader resourceLoader;

    @Autowired
    protected TestIdpProperties testEidasIdpProperties;

    protected Credential signatureCredential;
    protected Credential encryptionCredential;
    protected CookieFilter cookieFilter;

    @Before
    public void setUp() throws MalformedURLException, InitializationException {
        URL url = new URL(testEidasIdpProperties.getIdpUrl());
        port = url.getPort();
        baseURI = url.getProtocol() + "://" + url.getHost();

        Security.addProvider(new BouncyCastleProvider());
        InitializationService.initialize();
        cookieFilter = new CookieFilter();

        try {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            Resource resource = resourceLoader.getResource(testEidasIdpProperties.getKeystore());
            keystore.load(resource.getInputStream(), testEidasIdpProperties.getKeystorePass().toCharArray());
            signatureCredential = getCredential(keystore, testEidasIdpProperties.getResponseSigningKeyId(), testEidasIdpProperties.getResponseSigningKeyPass() );
            encryptionCredential = getEncryptionCredentialFromMetaData(getMetadataBody());
        } catch (Exception e) {
            throw new RuntimeException("Something went wrong initializing credentials:", e);
        }
    }

    private Credential getCredential(KeyStore keystore, String keyPairId, String privateKeyPass) {
        try {
            Map<String, String> passwordMap = new HashMap<>();
            passwordMap.put(keyPairId, privateKeyPass);
            KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);

            Criterion criterion = new EntityIdCriterion(keyPairId);
            CriteriaSet criteriaSet = new CriteriaSet();
            criteriaSet.add(criterion);

            return resolver.resolveSingle(criteriaSet);
        } catch (ResolverException e) {
            throw new RuntimeException("Something went wrong reading credentials", e);
        }
    }

    protected String getAuthnRequest (String providerName, String destination, String consumerServiceUrl, String issuerValue, String loa) {

        AuthnRequest request = new RequestBuilderUtils().buildAuthnRequest(signatureCredential, providerName, destination, consumerServiceUrl, issuerValue, loa);
        String stringResponse = OpenSAMLUtils.getXmlString(request);
        validateSamlReqSignature(stringResponse);
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()));
    }

    protected String getAuthnRequestWithDefault () {
        return getAuthnRequest("TestProvider", testEidasIdpProperties.getIdpStartUrl(), "randomUrl", testEidasIdpProperties.getEidasNodeMetadata(), LOA_HIGH);
    }

    protected void getAuthenticationPage(String samlRequest) {
           given()
                .filter(cookieFilter).relaxedHTTPSValidation()
                .formParam("SAMLRequest", samlRequest)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
//                .log().all()
                .when()
                .post(testEidasIdpProperties.getIdpStartUrl())
                .then()
                .statusCode(200)
//                .log().all()
                .extract().response();
    }

    protected org.opensaml.saml.saml2.core.Response authenticateWithMobileID(String samlRequest, String mobNo, String language) throws InterruptedException, UnmarshallingException, XMLParserException {
         given()
                .filter(cookieFilter).relaxedHTTPSValidation()
                .formParam("SAMLRequest", samlRequest)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
//                .log().all()
                .when()
                .post(testEidasIdpProperties.getIdpMidWelcomeUrl())
                .then()
//                .log().all()
                .extract().response();

        io.restassured.response.Response response = given()
                .filter(cookieFilter).relaxedHTTPSValidation()
                .formParam("SAMLRequest", samlRequest)
                .formParam("phoneNumber", mobNo)
                .formParam("lang", language)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
//                .log().all()
                .when()
                .post(testEidasIdpProperties.getIdpMidAuthUrl())
                .then()
//                .log().all()
                .extract().response();

        String sessionToken = response.getBody().htmlPath().getString("**.findAll { it.@name == 'sessionToken' }[0].@value");

        String samlResponse = pollForAuthentication(sessionToken, 7000);

        String decodedSamlResponse = new String(Base64.getDecoder().decode(samlResponse), StandardCharsets.UTF_8);
        validateSamlResponseSignature(decodedSamlResponse);
        org.opensaml.saml.saml2.core.Response samlResponseObj = getSamlResponse(decodedSamlResponse);
        return samlResponseObj;
    }

    protected String pollForAuthentication(String sessionToken, Integer intervalMillis) throws InterruptedException {
        DateTime endTime = new DateTime().plusMillis(intervalMillis*3 + 200);
        while(new DateTime().isBefore(endTime)) {
            Thread.sleep(intervalMillis);
            io.restassured.response.Response response = given()
                    .filter(cookieFilter)
                    .relaxedHTTPSValidation()
                    .redirects().follow(false)
                    .formParam("sessionToken", sessionToken)
//                .log().all()
                    .when()
                    .post(testEidasIdpProperties.getIdpMidCheckUrl())
                    .then()
//                .log().all()
                    .extract().response();
            if (response.statusCode() == 200) {
                return response.getBody().htmlPath().getString("**.findAll { it.@name == 'SAMLResponse' }[0].@value");
            }
        }
        throw new RuntimeException("No MID response in: "+ (intervalMillis*3 + 200) +" millis");
    }


    protected String getMetadataBody() {
        return given()
                .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
//                .log().all()
                .when()
                .get(testEidasIdpProperties.getIdpMetadataUrl())
                .then()
//                .log().all()
                .statusCode(200)
                .extract().body().asString();
    }

    protected XmlPath getMetadataBodyXML() {
        String metadataResponse = getMetadataBody();
        XmlPath metadataXml = new XmlPath(metadataResponse);
        return metadataXml;
    }

    protected Boolean validateMetadataSchema() {
        given()
        .config(config().xmlConfig(XmlConfig.xmlConfig().disableLoadingOfExternalDtd()))
                .when()
                .get(testEidasIdpProperties.getIdpMetadataUrl())
                .then().log().ifError()
                .statusCode(200)
                .body(matchesXsdInClasspath("SPschema.xsd").using(new ClasspathResourceResolver()));
        return true;
    }

    protected void validateMetadataSignature(String body) {
        XmlPath metadataXml = new XmlPath(body);
        try {
            java.security.cert.X509Certificate x509 = X509Support.decodeCertificate(metadataXml.getString("EntityDescriptor.Signature.KeyInfo.X509Data.X509Certificate"));
            validateSignature(body,x509);
        } catch (CertificateException e) {
            throw new RuntimeException("Certificate parsing in validateSignature() failed:" + e.getMessage(), e);
        }
    }

    protected void validateSamlReqSignature(String body) {
        XmlPath metadataXml = new XmlPath(body);
        try {
            java.security.cert.X509Certificate x509 = X509Support.decodeCertificate(metadataXml.getString("AuthnRequest.Signature.KeyInfo.X509Data.X509Certificate"));
            validateSignature(body,x509);
        } catch (CertificateException e) {
            throw new RuntimeException("Certificate parsing in validateSignature() failed:" + e.getMessage(), e);
        }
    }

    protected Boolean validateSamlResponseSignature(String body) {
        XmlPath metadataXml = new XmlPath(body);
        try {
            java.security.cert.X509Certificate x509 = X509Support.decodeCertificate(metadataXml.getString("Response.Signature.KeyInfo.X509Data.X509Certificate"));
            validateSignature(body,x509);
            return true;
        } catch (CertificateException e) {
            throw new RuntimeException("Certificate parsing in validateSignature() failed:" + e.getMessage(), e);
        }
    }

    protected void validateSignature(String body, java.security.cert.X509Certificate x509) {
        try {
            x509.checkValidity();
            SignableSAMLObject signableObj = XmlUtils.unmarshallElement(body);
            X509Credential credential = CredentialSupport.getSimpleCredential(x509,null);
            SignatureValidator.validate(signableObj.getSignature(), credential);
        } catch (SignatureException e) {
            throw new RuntimeException("Signature validation in validateSignature() failed: " + e.getMessage(), e);
        } catch (CertificateNotYetValidException e) {
            throw new RuntimeException("Certificate is not yet valid: " + e.getMessage(), e);
        } catch (CertificateExpiredException e) {
            throw new RuntimeException("Certificate is expired: " + e.getMessage(), e);
        }
    }

    protected Boolean isCertificateValid(String certString) {
        try {
            java.security.cert.X509Certificate x509 = X509Support.decodeCertificate(certString);
            isCertificateValidX509(x509);
            x509.checkValidity();
            return true;
        } catch (CertificateExpiredException e) {
            throw new RuntimeException("Certificate is expired: " + e.getMessage(), e);
        } catch (CertificateNotYetValidException e) {
            throw new RuntimeException("Certificate is not yet valid: " + e.getMessage(), e);
        } catch (CertificateException e) {
            throw new RuntimeException("Certificate parsing in isCertificateValid() failed: " + e.getMessage(), e);
        }
    }

    protected void isCertificateValidX509(java.security.cert.X509Certificate x509) {
        try {
            x509.checkValidity();
        } catch (CertificateExpiredException e) {
            throw new RuntimeException("Certificate is expired: " + e.getMessage(), e);
        } catch (CertificateNotYetValidException e) {
            throw new RuntimeException("Certificate is not yet valid: " + e.getMessage(), e);
        }
    }

    protected java.security.cert.X509Certificate getEncryptionCertificate(String body) throws CertificateException {
        XmlPath metadataXml = new XmlPath(body);
        java.security.cert.X509Certificate x509 = X509Support.decodeCertificate(metadataXml.getString("**.findAll {it.@use == 'encryption'}.KeyInfo.X509Data.X509Certificate"));
        return x509;
    }

    protected Credential getEncryptionCredentialFromMetaData (String body) throws CertificateException {
        java.security.cert.X509Certificate x509Certificate = getEncryptionCertificate(body);
        BasicX509Credential encryptionCredential = new BasicX509Credential(x509Certificate);
        return encryptionCredential;
    }

    public class ClasspathResourceResolver implements LSResourceResolver {
        @Override
        public LSInput resolveResource(String type, String namespaceURI, String publicId, String systemId, String baseURI) {
            InputStream resource = ClassLoader.getSystemResourceAsStream(systemId);
            return new DOMInputImpl(publicId, systemId, baseURI, resource, null);
        }
    }

    protected Assertion decryptAssertion(EncryptedAssertion encryptedAssertion) {
        StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(signatureCredential);

        Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
        decrypter.setRootInNewDocument(true);

        try {
            return decrypter.decrypt(encryptedAssertion);
        } catch (DecryptionException e) {
            throw new RuntimeException("Error decrypting assertion", e);
        }
    }

    protected Response getSamlResponse(String samlResponse) throws XMLParserException, UnmarshallingException {
        return (Response) XMLObjectSupport.unmarshallFromInputStream(
                OpenSAMLConfiguration.getParserPool(), new ByteArrayInputStream(samlResponse.getBytes(StandardCharsets.UTF_8)));
    }

    protected String getAttributeValue(Assertion assertion, String friendlyName) {
        for (Attribute attribute : assertion.getAttributeStatements().get(0).getAttributes()) {
            if (attribute.getFriendlyName().equals(friendlyName)) {
                XSAny attributeValue = (XSAny) attribute.getAttributeValues().get(0);
                return attributeValue.getTextContent();
            }
        }
        throw new RuntimeException("No such attribute found: " + friendlyName);
    }

    protected String getLoaValue(Assertion assertion) {
        return assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef();
    }
}
