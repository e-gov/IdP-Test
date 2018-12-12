package ee.ria.idp;

import ee.ria.idp.config.IntegrationTest;
import ee.ria.idp.config.TestConfiguration;
import ee.ria.idp.config.TestIdpProperties;
import ee.ria.idp.utils.SystemPropertyActiveProfileResolver;
import ee.ria.idp.utils.XmlUtils;
import io.restassured.filter.cookie.CookieFilter;
import io.restassured.path.xml.XmlPath;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
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
import org.springframework.core.io.ResourceLoader;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.config;
import static io.restassured.RestAssured.given;
import static io.restassured.config.EncoderConfig.encoderConfig;

@RunWith(SpringRunner.class)
@Category(IntegrationTest.class)
@ContextConfiguration(classes = TestConfiguration.class)
@ActiveProfiles(profiles = {"dev"}, resolver = SystemPropertyActiveProfileResolver.class)
public abstract class TestsBase {

    @Autowired
    private ResourceLoader resourceLoader;

    @Autowired
    protected TestIdpProperties testEidasIdpProperties;

    protected Credential signatureCredential;
    protected Credential encryptionCredential;
    protected Credential decryptionCredential;
    protected CookieFilter cookieFilter;


    protected Credential getCredential(KeyStore keystore, String keyPairId, String privateKeyPass) {
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


    protected String getMetadataBody() {
        return given()
                .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
//                .log().all()
                .when()
                .get(testEidasIdpProperties.getIdpUrl() + testEidasIdpProperties.getIdpMetadataUrl())
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

    protected void validateMetadataSignature(String body) {
        XmlPath metadataXml = new XmlPath(body);
        try {
            java.security.cert.X509Certificate x509 = X509Support.decodeCertificate(metadataXml.getString("EntityDescriptor.Signature.KeyInfo.X509Data.X509Certificate"));
            validateSignature(body, x509);
        } catch (CertificateException e) {
            throw new RuntimeException("Certificate parsing in validateSignature() failed:" + e.getMessage(), e);
        }
    }

    protected void validateSignature(String body, java.security.cert.X509Certificate x509) {
        try {
            x509.checkValidity();
            SignableSAMLObject signableObj = XmlUtils.unmarshallElement(body);
            X509Credential credential = CredentialSupport.getSimpleCredential(x509, null);
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

    protected Credential getEncryptionCredentialFromMetaData(String body) throws CertificateException {
        java.security.cert.X509Certificate x509Certificate = getEncryptionCertificate(body);
        BasicX509Credential encryptionCredential = new BasicX509Credential(x509Certificate);
        return encryptionCredential;
    }

    protected Assertion decryptAssertion(EncryptedAssertion encryptedAssertion) {
        StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(decryptionCredential);

        Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
        decrypter.setRootInNewDocument(true);

        try {
            return decrypter.decrypt(encryptedAssertion);
        } catch (DecryptionException e) {
            throw new RuntimeException("Error decrypting assertion", e);
        }
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
