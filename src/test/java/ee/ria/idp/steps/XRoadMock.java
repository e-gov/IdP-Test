package ee.ria.idp.steps;

import ee.ria.idp.model.EidasFlow;
import io.qameta.allure.Allure;
import io.qameta.allure.Step;
import io.qameta.allure.restassured.AllureRestAssured;
import io.restassured.RestAssured;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static io.restassured.config.EncoderConfig.encoderConfig;

public class XRoadMock {
    @Step("Mock response")
    public static void setResponse(EidasFlow flow, String mockresponse) throws IOException {
        Allure.addAttachment("Mock response", "application/xml", mockresponse, "xml");

        Map<String, Object> mockRequest = new HashMap<>();
        Map<String, Object> request = new HashMap<>();
        Map<String, Object> response = new HashMap<>();
        Map<String, Object> responseHeaders = new HashMap<>();


        request.put("method", "POST");
        request.put("url", "/cgi-bin/consumer_proxy");
        mockRequest.put("request", request);

        response.put("status", 200);
        response.put("body", mockresponse);//resourceLoader.getResource(responseBody).getInputStream().());
        responseHeaders.put("Content-Type", "text/xml;charset=utf-8");
        response.put("headers", responseHeaders);
        mockRequest.put("response", response);
        given()
                .filter(flow.getCookieFilter()).relaxedHTTPSValidation()
                .filter(new AllureRestAssured())
                .body(mockRequest)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .when()
                .post(flow.getTestProperties().getxRoadMockUrl() + "/__admin/mappings/new")
                .then()
                .extract().response();
    }


    @Step("Use XRoad Mock as proxy for development XRoad instance")
    public static void useAsProxy(EidasFlow flow) throws IOException {
        Map<String, Object> mockRequest = new HashMap<>();
        Map<String, Object> request = new HashMap<>();
        Map<String, Object> response = new HashMap<>();
        request.put("method", "POST");
        request.put("url", "/cgi-bin/consumer_proxy");
        mockRequest.put("request", request);
        response.put("proxyBaseUrl", flow.getTestProperties().getxRoadUrl());
        mockRequest.put("response", response);

        given()
                .filter(flow.getCookieFilter()).relaxedHTTPSValidation()
                .filter(new AllureRestAssured())
                .body(mockRequest)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .when()
                .post(flow.getTestProperties().getxRoadMockUrl() + "/__admin/mappings/new")
                .then()
                .extract().response();
    }
}
