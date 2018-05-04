package ee.ria.idp;


import ee.ria.idp.config.IntegrationTest;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.springframework.boot.test.context.SpringBootTest;

import static ee.ria.idp.config.EidasTestStrings.*;
import static org.junit.Assert.assertEquals;

@SpringBootTest(classes = AuthenticationRequestIntegrationTest.class)
@Category(IntegrationTest.class)
public class AuthenticationRequestIntegrationTest extends TestsBase {



    @Test
    public void idp1_authenticateWithMidSuccess() throws InterruptedException, UnmarshallingException, XMLParserException {
        String samlRequest = getAuthnRequestWithDefault();
        getAuthenticationPage(samlRequest);
        org.opensaml.saml.saml2.core.Response samlResponse = authenticateWithMobileID(samlRequest, "00000766", "");
        Assertion assertion = decryptAssertion(samlResponse.getEncryptedAssertions().get(0));

        assertEquals("Correct LOA is returned", LOA_HIGH, getLoaValue(assertion));
        assertEquals("Correct family name is returned", DEFATTR_FAMILY, getAttributeValue(assertion, FN_FAMILY));
        assertEquals("Correct first name is returned", DEFATTR_FIRST, getAttributeValue(assertion, FN_FIRST));
        assertEquals("Correct id code is returned", DEFATTR_PNO, getAttributeValue(assertion, FN_PNO));
        assertEquals("Correct birth date is returned", DEFATTR_DATE, getAttributeValue(assertion, FN_DATE));
    }



}
