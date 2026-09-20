package net.foulest.ospreyproxy.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.foulest.ospreyproxy.tenant.Tenant;
import net.foulest.ospreyproxy.tenant.TenantService;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.mockito.Mockito.*;

class SecurityFilterTest {

    @Test
    void rejectsDisallowedMethodsMissingLengthsOversizedAndInvalidTypes() throws Exception {
        TenantService tenants = mock(TenantService.class);
        SecurityFilter filter = new SecurityFilter(tenants);

        Invocation put = invocation("PUT", "/provider", -1, null);
        filter.doFilter(put.request, put.response, put.chain);
        verify(put.response).setStatus(405);
        verifyNoInteractions(put.chain);

        Invocation missingLength = invocation("POST", "/submit/acomics", -1, "application/json");
        filter.doFilter(missingLength.request, missingLength.response, missingLength.chain);
        verify(missingLength.response).setStatus(400);

        Invocation oversized = invocation("POST", "/provider", 10_241, "application/json");
        filter.doFilter(oversized.request, oversized.response, oversized.chain);
        verify(oversized.response).setStatus(400);

        Invocation invalidType = invocation("POST", "/submit/acomics", 10, "text/plain");
        filter.doFilter(invalidType.request, invalidType.response, invalidType.chain);
        verify(invalidType.response).setStatus(415);
    }

    @Test
    void permitsBodylessAndLargeSubmissionJsonRequests() throws Exception {
        TenantService tenants = mock(TenantService.class);
        SecurityFilter filter = new SecurityFilter(tenants);

        Invocation get = invocation("GET", "/anything", -1, null);
        filter.doFilter(get.request, get.response, get.chain);
        verify(get.chain).doFilter(get.request, get.response);

        Invocation submit = invocation("POST", "/submit/acomics", 262_144, "Application/Json; charset=utf-8");
        filter.doFilter(submit.request, submit.response, submit.chain);
        verify(submit.chain).doFilter(submit.request, submit.response);
    }

    @Test
    void authenticatesProviderPostsAndRejectsUnknownReservedAndExhaustedTenants() throws Exception {
        TenantService tenants = mock(TenantService.class);
        when(tenants.isEnabled()).thenReturn(true);
        when(tenants.getHeaderName()).thenReturn("X-Key");
        SecurityFilter filter = new SecurityFilter(tenants);

        Invocation unknown = invocation("POST", "/provider", 2, "application/json");
        filter.doFilter(unknown.request, unknown.response, unknown.chain);
        verify(unknown.response).setStatus(401);

        Tenant submitKey = mock(Tenant.class);
        when(submitKey.id()).thenReturn("submit-feed");
        when(tenants.resolve(any())).thenReturn(submitKey);
        Invocation submissionKey = invocation("POST", "/provider", 2, "application/json");
        filter.doFilter(submissionKey.request, submissionKey.response, submissionKey.chain);
        verify(submissionKey.response).setStatus(401);

        Tenant normal = mock(Tenant.class);
        when(normal.id()).thenReturn("tenant-a");
        when(normal.tryConsume()).thenReturn(true);
        when(tenants.resolve(any())).thenReturn(normal);
        Invocation good = invocation("POST", "/provider", 2, "application/json");
        filter.doFilter(good.request, good.response, good.chain);
        verify(good.request).setAttribute(TenantService.TENANT_ATTRIBUTE, "tenant-a");
        verify(good.chain).doFilter(good.request, good.response);

        Invocation reserved = invocation("POST", "/check", 2, "application/json");
        filter.doFilter(reserved.request, reserved.response, reserved.chain);
        verify(reserved.chain).doFilter(reserved.request, reserved.response);
    }

    @Test
    void rejectsExhaustedTenantsAndUsesRequestUriWhenServletPathIsUnavailable() throws Exception {
        TenantService tenants = mock(TenantService.class);
        when(tenants.isEnabled()).thenReturn(true);
        when(tenants.getHeaderName()).thenReturn("X-Key");
        Tenant exhausted = mock(Tenant.class);
        when(exhausted.id()).thenReturn("tenant-a");
        when(exhausted.tryConsume()).thenReturn(false);
        when(tenants.resolve("key")).thenReturn(exhausted);

        SecurityFilter filter = new SecurityFilter(tenants);
        Invocation provider = invocation("POST", "", 2, "application/json");
        when(provider.request.getRequestURI()).thenReturn("/provider");
        filter.doFilter(provider.request, provider.response, provider.chain);
        verify(provider.response).setStatus(429);

        Invocation submit = invocation("POST", null, 262_144, "application/json");
        when(submit.request.getRequestURI()).thenReturn("/submit/acomics");
        filter.doFilter(submit.request, submit.response, submit.chain);
        verify(submit.chain).doFilter(submit.request, submit.response);
    }

    @Test
    void handlesEmptyAndNestedPathsAndAllContentTypeBoundaries() throws Exception {
        TenantService tenants = mock(TenantService.class);
        SecurityFilter filter = new SecurityFilter(tenants);

        Invocation empty = invocation("POST", "", 2, "application/json");
        when(empty.request.getRequestURI()).thenReturn("");
        filter.doFilter(empty.request, empty.response, empty.chain);
        verify(empty.chain).doFilter(empty.request, empty.response);

        Invocation nested = invocation("POST", "/internal/index-feed", 2, "application/json");
        filter.doFilter(nested.request, nested.response, nested.chain);
        verify(nested.chain).doFilter(nested.request, nested.response);

        Invocation missingType = invocation("POST", "/submit/acomics", 2, null);
        filter.doFilter(missingType.request, missingType.response, missingType.chain);
        verify(missingType.response).setStatus(415);

        Invocation invalidSuffix = invocation("POST", "/submit/acomics", 2, "application/jsonx");
        filter.doFilter(invalidSuffix.request, invalidSuffix.response, invalidSuffix.chain);
        verify(invalidSuffix.response).setStatus(415);

        Invocation exactType = invocation("POST", "/submit/acomics", 2, "application/json");
        filter.doFilter(exactType.request, exactType.response, exactType.chain);
        verify(exactType.chain).doFilter(exactType.request, exactType.response);
    }

    @Test
    void anonymousModeTagsProviderRequests() throws Exception {
        TenantService tenants = mock(TenantService.class);
        when(tenants.isEnabled()).thenReturn(false);
        Invocation invocation = invocation("POST", "/provider", 2, "application/json");
        new SecurityFilter(tenants).doFilter(invocation.request, invocation.response, invocation.chain);
        verify(invocation.request).setAttribute(TenantService.TENANT_ATTRIBUTE, TenantService.ANONYMOUS);
        verify(invocation.chain).doFilter(invocation.request, invocation.response);
    }

    @Test
    void treatsMissingRequestUrisAndRootPathsAsNonProviderEndpoints() throws Exception {
        TenantService tenants = mock(TenantService.class);
        SecurityFilter filter = new SecurityFilter(tenants);

        Invocation noPath = invocation("POST", null, 2, "application/json");
        filter.doFilter(noPath.request, noPath.response, noPath.chain);
        verify(noPath.chain).doFilter(noPath.request, noPath.response);

        Invocation root = invocation("POST", "/", 2, "application/json");
        filter.doFilter(root.request, root.response, root.chain);
        verify(root.chain).doFilter(root.request, root.response);

        Invocation providerWithoutLeadingSlash = invocation("POST", "provider", 2, "application/json");
        filter.doFilter(providerWithoutLeadingSlash.request, providerWithoutLeadingSlash.response,
                providerWithoutLeadingSlash.chain);
        verify(providerWithoutLeadingSlash.request)
                .setAttribute(TenantService.TENANT_ATTRIBUTE, TenantService.ANONYMOUS);
        verify(providerWithoutLeadingSlash.chain).doFilter(providerWithoutLeadingSlash.request,
                providerWithoutLeadingSlash.response);
    }

    private static Invocation invocation(String method, String path, long contentLength, String contentType) throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        when(request.getMethod()).thenReturn(method);
        when(request.getServletPath()).thenReturn(path);
        when(request.getContentLengthLong()).thenReturn(contentLength);
        when(request.getHeader("Content-Type")).thenReturn(contentType);
        when(request.getHeader("X-Key")).thenReturn("key");
        when(response.getWriter()).thenReturn(new PrintWriter(new StringWriter()));
        return new Invocation(request, response, chain);
    }

    private record Invocation(HttpServletRequest request, HttpServletResponse response, FilterChain chain) {

    }
}
