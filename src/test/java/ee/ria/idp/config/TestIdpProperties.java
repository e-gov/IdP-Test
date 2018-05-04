package ee.ria.idp.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "test.idp")
public class TestIdpProperties {

    private String eidasNodeMetadata;
    private String keystore;
    private String keystorePass;
    private String responseSigningKeyId;
    private String responseSigningKeyPass;
    private String idpUrl;
    private String idpMetadataUrl;
    private String idpStartUrl;
    private String idpMidWelcomeUrl;
    private String idpMidAuthUrl;
    private String idpMidCheckUrl;

    public String getIdpMidWelcomeUrl() {
        return idpMidWelcomeUrl;
    }

    public void setIdpMidWelcomeUrl(String idpMidWelcomeUrl) {
        this.idpMidWelcomeUrl = idpMidWelcomeUrl;
    }

    public String getIdpMidAuthUrl() {
        return idpMidAuthUrl;
    }

    public void setIdpMidAuthUrl(String idpMidAuthUrl) {
        this.idpMidAuthUrl = idpMidAuthUrl;
    }

    public String getIdpMidCheckUrl() {
        return idpMidCheckUrl;
    }

    public void setIdpMidCheckUrl(String idpMidCheckUrl) {
        this.idpMidCheckUrl = idpMidCheckUrl;
    }

    public String getEidasNodeMetadata() {
        return eidasNodeMetadata;
    }

    public void setEidasNodeMetadata(String eidasNodeMetadata) {
        this.eidasNodeMetadata = eidasNodeMetadata;
    }

    public String getKeystore() {
        return keystore;
    }

    public void setKeystore(String keystore) {
        this.keystore = keystore;
    }

    public String getKeystorePass() {
        return keystorePass;
    }

    public void setKeystorePass(String keystorePass) {
        this.keystorePass = keystorePass;
    }

    public String getResponseSigningKeyId() {
        return responseSigningKeyId;
    }

    public void setResponseSigningKeyId(String responseSigningKeyId) {
        this.responseSigningKeyId = responseSigningKeyId;
    }

    public String getResponseSigningKeyPass() {
        return responseSigningKeyPass;
    }

    public void setResponseSigningKeyPass(String responseSigningKeyPass) {
        this.responseSigningKeyPass = responseSigningKeyPass;
    }

    public String getIdpUrl() {
        return idpUrl;
    }

    public void setIdpUrl(String idpUrl) {
        this.idpUrl = idpUrl;
    }

    public String getIdpMetadataUrl() {
        return idpMetadataUrl;
    }

    public void setIdpMetadataUrl(String idpMetadataUrl) {
        this.idpMetadataUrl = idpMetadataUrl;
    }

    public String getIdpStartUrl() {
        return idpStartUrl;
    }

    public void setIdpStartUrl(String idpStartUrl) {
        this.idpStartUrl = idpStartUrl;
    }
}
