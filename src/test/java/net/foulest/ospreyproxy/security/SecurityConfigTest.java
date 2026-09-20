package net.foulest.ospreyproxy.security;

import net.foulest.ospreyproxy.tenant.TenantService;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.filter.CorsFilter;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityConfigTest {

    @Test
    void registersCorsForOnlyItsPublicEndpoints() throws Exception {
        SecurityConfig config = new SecurityConfig();
        ReflectionTestUtils.setField(config, "checkAllowedOrigin", "https://client.example");
        FilterRegistrationBean<CorsFilter> registration = config.corsFilterRegistration();

        assertThat(registration.getOrder()).isZero();
        assertThat(registration.getFilterName()).isEqualTo("corsFilter");

        assertCorsAllows(registration.getFilter(), "/check", "POST");
        assertCorsAllows(registration.getFilter(), "/result", "GET");
        assertCorsAllows(registration.getFilter(), "/contact/verify", "POST");
    }

    @Test
    void registersSecurityFilterForAllPaths() {
        SecurityConfig config = new SecurityConfig();
        FilterRegistrationBean<SecurityFilter> registration =
                config.securityFilterRegistration(Mockito.mock(TenantService.class));

        assertThat(registration.getFilter()).isInstanceOf(SecurityFilter.class);
        assertThat(registration.getUrlPatterns()).containsExactly("/*");
        assertThat(registration.getOrder()).isEqualTo(1);
        assertThat(registration.getFilterName()).isEqualTo("securityFilter");
    }

    private static void assertCorsAllows(CorsFilter filter, String path, String method) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", path);
        request.addHeader("Origin", "https://client.example");
        request.addHeader("Access-Control-Request-Method", method);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> {
        });
        assertThat(response.getHeader("Access-Control-Allow-Origin")).isEqualTo("https://client.example");
    }
}
