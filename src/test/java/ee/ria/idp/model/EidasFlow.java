package ee.ria.idp.model;

import ee.ria.idp.config.TestIdpProperties;
import ee.ria.idp.utils.AdvancedCookieFilter;
import lombok.Data;
import org.opensaml.security.credential.Credential;
import org.springframework.core.io.ResourceLoader;

public @Data
class EidasFlow {

    private AdvancedCookieFilter cookieFilter = new AdvancedCookieFilter();
    private ResourceLoader resourceLoader;
    protected Credential signatureCredential;
    protected Credential encryptionCredential;
    protected Credential decryptionCredential;
    private TestIdpProperties testProperties;

    public void setup(TestIdpProperties properties) {
        testProperties = properties;
    }
}
