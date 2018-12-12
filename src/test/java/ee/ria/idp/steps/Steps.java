package ee.ria.idp.steps;

import ee.ria.idp.model.EidasFlow;
import ee.ria.idp.utils.SamlSigantureUtils;
import io.qameta.allure.Allure;
import io.qameta.allure.Step;
import org.opensaml.saml.saml2.core.Assertion;
import org.w3c.dom.Element;

import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;


public class Steps {
    @Step("{message}")
    public static void log(String message) {
    }

    @Step("Saml Response Contents")
    public static void logSamlResponse(EidasFlow flow, org.opensaml.saml.saml2.core.Response response) {
        Allure.addAttachment("SAML Response", "application/xml", parseXml(response.getDOM()), "xml");

        Assertion assertion = SamlSigantureUtils.decryptAssertion(flow, response.getEncryptedAssertions().get(0));
        Allure.addAttachment("Assertion", "application/xml", parseXml(assertion.getDOM()), "xml");
    }


    private static String parseXml(Element xml) {
        TransformerFactory tf = TransformerFactory.newInstance();
        tf.setAttribute("indent-number", new Integer(2));

        StringWriter sw = new StringWriter();
        try {
            Transformer trans = tf.newTransformer();
            trans.setOutputProperty(OutputKeys.INDENT, "yes");
            trans.transform(new DOMSource(xml), new StreamResult(sw));
        } catch (TransformerConfigurationException e) {
            throw new RuntimeException(e);
        } catch (TransformerException e) {
            throw new RuntimeException(e);
        }
        return sw.toString();
    }

}
