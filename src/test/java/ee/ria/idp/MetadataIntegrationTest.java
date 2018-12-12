package ee.ria.idp;


import ee.ria.idp.config.IntegrationTest;
import ee.ria.idp.config.TestIdpProperties;
import ee.ria.idp.model.EidasFlow;
import ee.ria.idp.steps.Requests;
import io.restassured.path.xml.XmlPath;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ResourceLoader;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertEquals;

@SpringBootTest(classes = MetadataIntegrationTest.class)
@Category(IntegrationTest.class)
public class MetadataIntegrationTest extends TestsBase {
    @Autowired
    private ResourceLoader resourceLoader;
    private static boolean setupComplete = false;
    private EidasFlow flow;


    @Before
    public void setUp() {
        if (!setupComplete) {
            initialize();
            setupComplete = true;
        }
        flow = new EidasFlow();
        setupFlow(flow, testEidasIdpProperties);
    }

    void setupFlow(EidasFlow flow, TestIdpProperties properties) {
        flow.setResourceLoader(resourceLoader);
        flow.setup(properties);
    }

    public void initialize() {

    }

    @Ignore("This is optional block")
    @Test
    public void metap2_mandatoryValuesArePresentInExtensions() {
        XmlPath xmlPath = Requests.getMetadataBodyXML(flow);

        List<String> digestMethods = xmlPath.getList("EntityDescriptor.Extensions.DigestMethod.@Algorithm");
        assertThat("One of the accepted digest algorithms must be present", digestMethods,
                anyOf(hasItem("http://www.w3.org/2001/04/xmlenc#sha512"), hasItem("http://www.w3.org/2001/04/xmlenc#sha256")));

        List<String> signingMethods = xmlPath.getList("EntityDescriptor.Extensions.SigningMethod.@Algorithm");
        assertThat("One of the accepted singing algorithms must be present", signingMethods,
                anyOf(hasItem("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"), hasItem("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"),
                        hasItem("http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1"), hasItem("http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1")));
    }

    @Test
    public void metap3_validUntilIsPresentInEntityDescriptor() {
        Instant currentTime = Instant.now();
        XmlPath xmlPath = Requests.getMetadataBodyXML(flow);
        Instant validUntil = Instant.parse(xmlPath.getString("EntityDescriptor.@validUntil"));
        xmlPath = Requests.getMetadataBodyXML(flow);
        Instant validUntil2 = Instant.parse(xmlPath.getString("EntityDescriptor.@validUntil"));
        assertThat("The metadata should be valid for 24h", currentTime.plus(Duration.ofHours(23).plusMinutes(50)), lessThan(validUntil));
        assertThat("The metadata should be valid for 24h", validUntil, allOf(lessThan(currentTime.plus(Duration.ofHours(24).plusMinutes(5))), greaterThan(currentTime.plus(Duration.ofHours(23).plusMinutes(55)))));
        assertThat("Metadata should be generated on each request", validUntil, not(equalTo(validUntil2)));
    }

    @Ignore("This is optional block")
    @Test
    public void metap2_organizationInformationIsCorrect() {
        XmlPath xmlPath = Requests.getMetadataBodyXML(flow);
        assertEquals("Correct Organization name must be present", "DEMO-SP",
                xmlPath.getString("EntityDescriptor.Organization.OrganizationName"));
        assertEquals("Correct Organization display name must be present", "Sample SP",
                xmlPath.getString("EntityDescriptor.Organization.OrganizationDisplayName"));
        assertEquals("Correct Organization url must be present", "https://sp.sample/info",
                xmlPath.getString("EntityDescriptor.Organization.OrganizationURL"));
    }

    @Ignore("This is optional block")
    @Test
    public void metap2_contacInformationIsCorrect() {
        XmlPath xmlPath = Requests.getMetadataBodyXML(flow);
        assertEquals("Correct Organization name must be present", "eIDAS SP Operator",
                xmlPath.getString("**.findAll {it.@contactType == 'support'}.Company"));
        assertEquals("Correct Organization name must be present", "Jean-Michel",
                xmlPath.getString("**.findAll {it.@contactType == 'support'}.GivenName"));
        assertEquals("Correct Organization name must be present", "Folon",
                xmlPath.getString("**.findAll {it.@contactType == 'support'}.SurName"));
        assertEquals("Correct Organization name must be present", "contact.support@sp.eu",
                xmlPath.getString("**.findAll {it.@contactType == 'support'}.EmailAddress"));
        assertEquals("Correct Organization name must be present", "+555 123456",
                xmlPath.getString("**.findAll {it.@contactType == 'support'}.TelephoneNumber"));
    }

    @Ignore("These values are optional")
    @Test
    public void metap2_optionalValuesArePresentInAssertionConsumerService() {
        XmlPath xmlPath = Requests.getMetadataBodyXML(flow);
        assertEquals("The index should be: 0", "0",
                xmlPath.getString("EntityDescriptor.SPSSODescriptor.AssertionConsumerService.@index"));
        assertEquals("The isDefault shoult be: true", "true",
                xmlPath.getString("EntityDescriptor.SPSSODescriptor.AssertionConsumerService.@isDefault"));
    }
}
