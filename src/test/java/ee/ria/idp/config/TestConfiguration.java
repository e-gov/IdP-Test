package ee.ria.idp.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties({
        TestIdpProperties.class
})
public class TestConfiguration {
}
