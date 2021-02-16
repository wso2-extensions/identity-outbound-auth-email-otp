/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.authenticator.emailotp;

import org.apache.commons.lang.StringUtils;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ENDPOINT_URL;
import static org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ERROR_PAGE_URL;
import static org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticatorConstants.EMAIL_ADDRESS_REQ_PAGE;
import static org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticatorTestConstants.TENANT_DOMAIN;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

@PrepareForTest({IdentityTenantUtil.class, ServiceURLBuilder.class})
public class EmailOtpURLUtilTest extends PowerMockTestCase {

    @BeforeMethod
    public void setUp() throws URLBuilderException {

        mockServiceURLBuilder();
    }

    @DataProvider(name = "requestEmailPageDataProvider")
    public static Object[][] getRequestEmailPageURLData() {

        return new Object[][]{
                // Tenant null is thread local context
                {false, null, "https://localhost:9443/authenticationendpoint/email_capture.do"},
                {true, null, "https://localhost:9443/t/null/authenticationendpoint/email_capture.do"},

                // Super tenant
                {false, "carbon.super", "https://localhost:9443/authenticationendpoint/email_capture.do"},
                {true, "carbon.super", "https://localhost:9443/authenticationendpoint/email_capture.do"},

                // Tenant
                {false, "wso2.com", "https://localhost:9443/authenticationendpoint/email_capture.do"},
                {true, "wso2.com", "https://localhost:9443/t/wso2.com/authenticationendpoint/email_capture.do"},
        };
    }

    @Test(dataProvider = "requestEmailPageDataProvider")
    public void testGetRequestEmailPage(boolean isTenantQualifiedURLEnabled,
                                        String tenantDomainInThreadLocal,
                                        String expectedURL) throws AuthenticationFailedException {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifiedURLEnabled);
        when(IdentityTenantUtil.getTenantDomainFromContext()).thenReturn(tenantDomainInThreadLocal);

        assertEquals(EmailOTPUrlUtil.getRequestEmailPageUrl(new AuthenticationContext(), new HashMap<>()), expectedURL);
    }

    @DataProvider(name = "emailOTPLoginPageURLDataProvider")
    public static Object[][] getEmailOTPLoginPageURLData() {

        return new Object[][]{
                // Tenant null is thread local context
                {false, null, "https://localhost:9443/authenticationendpoint/email_otp.do"},
                {true, null, "https://localhost:9443/t/null/authenticationendpoint/email_otp.do"},

                // Super tenant
                {false, "carbon.super", "https://localhost:9443/authenticationendpoint/email_otp.do"},
                {true, "carbon.super", "https://localhost:9443/authenticationendpoint/email_otp.do"},

                // Tenant
                {false, "wso2.com", "https://localhost:9443/authenticationendpoint/email_otp.do"},
                {true, "wso2.com", "https://localhost:9443/t/wso2.com/authenticationendpoint/email_otp.do"},
        };
    }

    @Test(dataProvider = "emailOTPLoginPageURLDataProvider")
    public void testGetLoginPage(boolean isTenantQualifiedURLEnabled,
                                 String tenantDomainInThreadLocal,
                                 String expectedURL) throws AuthenticationFailedException {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifiedURLEnabled);
        when(IdentityTenantUtil.getTenantDomainFromContext()).thenReturn(tenantDomainInThreadLocal);

        assertEquals(EmailOTPUrlUtil.getEmailOTPLoginPageUrl(new AuthenticationContext(), new HashMap<>()), expectedURL);
    }

    @DataProvider(name = "emailOTPErrorPageURLDataProvider")
    public static Object[][] getEmailOTPErrorPagePageURLData() {

        return new Object[][]{
                // Tenant null is thread local context
                {false, null, "https://localhost:9443/authenticationendpoint/email_otp_error.do"},
                {true, null, "https://localhost:9443/t/null/authenticationendpoint/email_otp_error.do"},

                // Super tenant
                {false, "carbon.super", "https://localhost:9443/authenticationendpoint/email_otp_error.do"},
                {true, "carbon.super", "https://localhost:9443/authenticationendpoint/email_otp_error.do"},

                // Tenant
                {false, "wso2.com", "https://localhost:9443/authenticationendpoint/email_otp_error.do"},
                {true, "wso2.com", "https://localhost:9443/t/wso2.com/authenticationendpoint/email_otp_error.do"},
        };
    }

    @Test(dataProvider = "emailOTPErrorPageURLDataProvider")
    public void testGetErrorPage(boolean isTenantQualifiedURLEnabled,
                                 String tenantDomainInThreadLocal,
                                 String expectedURL) throws AuthenticationFailedException {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifiedURLEnabled);
        when(IdentityTenantUtil.getTenantDomainFromContext()).thenReturn(tenantDomainInThreadLocal);

        assertEquals(EmailOTPUrlUtil.getEmailOTPErrorPageUrl(new AuthenticationContext(), new HashMap<>()), expectedURL);
    }

    @Test(description = "Tests getting email request page URL in non tenant qualified URL mode.")
    public void testGetEmailAddressRequestPage() throws Exception {

        String reqPage = "emailotpEndpoint/reqPage.jsp";
        String expectedURL = "https://localhost:9443/emailotpEndpoint/reqPage.jsp";

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(false);

        Map<String, String> parameters = new HashMap<>();
        parameters.put(EMAIL_ADDRESS_REQ_PAGE, reqPage);

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(TENANT_DOMAIN);
        context.setProperty(EMAIL_ADDRESS_REQ_PAGE, reqPage);
        Assert.assertEquals(EmailOTPUrlUtil.getRequestEmailPageUrl(context, parameters), expectedURL);

        // Super tenant test.
        mockServiceURLBuilder();
        AuthenticationContext superTenantAuthContext = new AuthenticationContext();
        superTenantAuthContext.setTenantDomain(TENANT_DOMAIN);
        superTenantAuthContext.setProperty(EMAIL_ADDRESS_REQ_PAGE, reqPage);
        superTenantAuthContext.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        Assert.assertEquals(EmailOTPUrlUtil.getRequestEmailPageUrl(superTenantAuthContext, parameters), expectedURL);
    }

    @DataProvider(name = "EmailCapturePageFromConfigData")
    public static Object[][] getEmailCapturePageFromConfigData() {

        return new Object[][]{
                {TENANT_DOMAIN,
                        "https://localhost:9443/myemailotp/capture.do",
                        "https://localhost:9443/myemailotp/capture.do"},
                {TENANT_DOMAIN,
                        "myemailotp/capture.do",
                        "https://localhost:9443/t/wso2.org/myemailotp/capture.do"},
                {TENANT_DOMAIN,
                        null,
                        "https://localhost:9443/t/wso2.org/authenticationendpoint/email_capture.do"},
                {SUPER_TENANT_DOMAIN_NAME,
                        "https://localhost:9443/myemailotp/capture.do",
                        "https://localhost:9443/myemailotp/capture.do"},
                {SUPER_TENANT_DOMAIN_NAME,
                        "myemailotp/capture.do",
                        "https://localhost:9443/myemailotp/capture.do"},
                {SUPER_TENANT_DOMAIN_NAME,
                        null,
                        "https://localhost:9443/authenticationendpoint/email_capture.do"}
        };
    }

    @Test(description = "Tests email capture page URL building logic when tenant qualified URL mode is enabled and " +
            "URL are externalized through config.", dataProvider = "EmailCapturePageFromConfigData")
    public void testBuildEmailCaptureURLWithExternalizedURLs(String tenantDomain, String valueFromConfig,
                                                             String expectedURL) throws Exception {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(true);
        when(IdentityTenantUtil.getTenantDomainFromContext()).thenReturn(tenantDomain);

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(tenantDomain);

        Map<String, String> parameters = new HashMap<>();

        if (SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            // For super tenant externalized URLs are read from parameter map.
            parameters.put(EMAIL_ADDRESS_REQ_PAGE, valueFromConfig);
        } else {
            // For tenants externalized URLs are read from context.
            context.setProperty(EMAIL_ADDRESS_REQ_PAGE, valueFromConfig);
        }

        Assert.assertEquals(EmailOTPUrlUtil.getRequestEmailPageUrl(context, parameters), expectedURL);
    }

    @DataProvider(name = "EmailOTPLoginPageFromConfigData")
    public static Object[][] getEmailOTPLoginPageFromConfigData() {

        return new Object[][]{
                {TENANT_DOMAIN,
                        "https://localhost:9443/myemailotp/login.do",
                        "https://localhost:9443/myemailotp/login.do"},
                {TENANT_DOMAIN,
                        "myemailotp/login.do",
                        "https://localhost:9443/t/wso2.org/myemailotp/login.do"},
                {TENANT_DOMAIN,
                        null,
                        "https://localhost:9443/t/wso2.org/authenticationendpoint/email_otp.do"},
                {SUPER_TENANT_DOMAIN_NAME,
                        "https://localhost:9443/myemailotp/login.do",
                        "https://localhost:9443/myemailotp/login.do"},
                {SUPER_TENANT_DOMAIN_NAME,
                        "myemailotp/login.do",
                        "https://localhost:9443/myemailotp/login.do"},
                {SUPER_TENANT_DOMAIN_NAME,
                        null,
                        "https://localhost:9443/authenticationendpoint/email_otp.do"}
        };
    }

    @Test(description = "Tests email OTP login URL building logic when tenant qualified URL mode is enabled and " +
            "URL are externalized through config.", dataProvider = "EmailOTPLoginPageFromConfigData")
    public void testBuildEmailOtpLoginURLWithExternalizedURLs(String tenantDomain, String valueFromConfig,
                                                             String expectedURL) throws Exception {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(true);
        when(IdentityTenantUtil.getTenantDomainFromContext()).thenReturn(tenantDomain);

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(tenantDomain);

        Map<String, String> parameters = new HashMap<>();

        if (SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            // For super tenant externalized URLs are read from parameter map.
            parameters.put(EMAILOTP_AUTHENTICATION_ENDPOINT_URL, valueFromConfig);
        } else {
            // For tenants externalized URLs are read from context.
            context.setProperty(EMAILOTP_AUTHENTICATION_ENDPOINT_URL, valueFromConfig);
        }

        Assert.assertEquals(EmailOTPUrlUtil.getEmailOTPLoginPageUrl(context, parameters), expectedURL);
    }

    @DataProvider(name = "EmailOTPErrorPageFromConfigData")
    public static Object[][] getEmailOTPErrorPageFromConfigData() {

        return new Object[][]{
                {TENANT_DOMAIN,
                        "https://localhost:9443/myemailotp/error.do",
                        "https://localhost:9443/myemailotp/error.do"},
                {TENANT_DOMAIN,
                        "myemailotp/error.do",
                        "https://localhost:9443/t/wso2.org/myemailotp/error.do"},
                {TENANT_DOMAIN,
                        null,
                        "https://localhost:9443/t/wso2.org/authenticationendpoint/email_otp_error.do"},
                {SUPER_TENANT_DOMAIN_NAME,
                        "https://localhost:9443/myemailotp/error.do",
                        "https://localhost:9443/myemailotp/error.do"},
                {SUPER_TENANT_DOMAIN_NAME,
                        "myemailotp/error.do",
                        "https://localhost:9443/myemailotp/error.do"},
                {SUPER_TENANT_DOMAIN_NAME,
                        null,
                        "https://localhost:9443/authenticationendpoint/email_otp_error.do"}
        };
    }

    @Test(description = "Tests email OTP login URL building logic when tenant qualified URL mode is enabled and " +
            "URL are externalized through config.", dataProvider = "EmailOTPErrorPageFromConfigData")
    public void testBuildEmailOtpErrorPageURLWithExternalizedURLs(String tenantDomain, String valueFromConfig,
                                                              String expectedURL) throws Exception {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(true);
        when(IdentityTenantUtil.getTenantDomainFromContext()).thenReturn(tenantDomain);

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(tenantDomain);

        Map<String, String> parameters = new HashMap<>();

        if (SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            // For super tenant externalized URLs are read from parameter map.
            parameters.put(EMAILOTP_AUTHENTICATION_ERROR_PAGE_URL, valueFromConfig);
        } else {
            // For tenants externalized URLs are read from context.
            context.setProperty(EMAILOTP_AUTHENTICATION_ERROR_PAGE_URL, valueFromConfig);
        }

        Assert.assertEquals(EmailOTPUrlUtil.getEmailOTPErrorPageUrl(context, parameters), expectedURL);
    }

    private void mockServiceURLBuilder() {

        ServiceURLBuilder builder = new ServiceURLBuilder() {

            String path = "";

            @Override
            public ServiceURLBuilder addPath(String... strings) {

                Arrays.stream(strings).forEach(x -> path += "/" + x);
                return this;
            }

            @Override
            public ServiceURLBuilder addParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURLBuilder setFragment(String s) {

                return this;
            }

            @Override
            public ServiceURLBuilder addFragmentParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURL build() {

                ServiceURL serviceURL = mock(ServiceURL.class);
                when(serviceURL.getRelativePublicURL()).thenReturn(path);
                when(serviceURL.getRelativeInternalURL()).thenReturn(path);

                String tenantDomain = IdentityTenantUtil.getTenantDomainFromContext();
                if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()
                        && !StringUtils.equals(tenantDomain, SUPER_TENANT_DOMAIN_NAME)) {
                    when(serviceURL.getAbsolutePublicURL())
                            .thenReturn("https://localhost:9443/t/" + tenantDomain + path);
                } else {
                    when(serviceURL.getAbsolutePublicURL()).thenReturn("https://localhost:9443" + path);
                }
                return serviceURL;
            }
        };

        mockStatic(ServiceURLBuilder.class);
        when(ServiceURLBuilder.create()).thenReturn(builder);
    }
}
