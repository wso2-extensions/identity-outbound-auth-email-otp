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
import org.powermock.reflect.Whitebox;
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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
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
                {false, null, "https://localhost:9443/emailotpauthenticationendpoint/emailAddress.jsp"},
                {true, null, "https://localhost:9443/t/null/emailotpauthenticationendpoint/emailAddress.jsp"},

                // Super tenant
                {false, "carbon.super", "https://localhost:9443/emailotpauthenticationendpoint/emailAddress.jsp"},
                {true, "carbon.super", "https://localhost:9443/emailotpauthenticationendpoint/emailAddress.jsp"},

                // Tenant
                {false, "wso2.com", "https://localhost:9443/emailotpauthenticationendpoint/emailAddress.jsp"},
                {true, "wso2.com", "https://localhost:9443/t/wso2.com/emailotpauthenticationendpoint/emailAddress.jsp"},
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
                {false, null, "https://localhost:9443/emailotpauthenticationendpoint/emailotp.jsp"},
                {true, null, "https://localhost:9443/t/null/emailotpauthenticationendpoint/emailotp.jsp"},

                // Super tenant
                {false, "carbon.super", "https://localhost:9443/emailotpauthenticationendpoint/emailotp.jsp"},
                {true, "carbon.super", "https://localhost:9443/emailotpauthenticationendpoint/emailotp.jsp"},

                // Tenant
                {false, "wso2.com", "https://localhost:9443/emailotpauthenticationendpoint/emailotp.jsp"},
                {true, "wso2.com", "https://localhost:9443/t/wso2.com/emailotpauthenticationendpoint/emailotp.jsp"},
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
                {false, null, "https://localhost:9443/emailotpauthenticationendpoint/emailotpError.jsp"},
                {true, null, "https://localhost:9443/t/null/emailotpauthenticationendpoint/emailotpError.jsp"},

                // Super tenant
                {false, "carbon.super", "https://localhost:9443/emailotpauthenticationendpoint/emailotpError.jsp"},
                {true, "carbon.super", "https://localhost:9443/emailotpauthenticationendpoint/emailotpError.jsp"},

                // Tenant
                {false, "wso2.com", "https://localhost:9443/emailotpauthenticationendpoint/emailotpError.jsp"},
                {true, "wso2.com", "https://localhost:9443/t/wso2.com/emailotpauthenticationendpoint/emailotpError.jsp"},
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
        parameters.put(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS_REQ_PAGE, reqPage);

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(TENANT_DOMAIN);
        context.setProperty(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS_REQ_PAGE, reqPage);
        Assert.assertEquals(EmailOTPUrlUtil.getRequestEmailPageUrl(context, parameters), expectedURL);

        // Super tenant test
        mockServiceURLBuilder();
        AuthenticationContext superTenantAuthContext = new AuthenticationContext();
        superTenantAuthContext.setTenantDomain(TENANT_DOMAIN);
        superTenantAuthContext.setProperty(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS_REQ_PAGE, reqPage);
        superTenantAuthContext.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        Assert.assertEquals(EmailOTPUrlUtil.getRequestEmailPageUrl(superTenantAuthContext, parameters), expectedURL);
    }


    @DataProvider(name = "x")
    public static Object[][] getEmailRequestPageFromConfig() {

        return new Object[][]{
                // Tenant null is thread local context
                {"carbon.super", "https://localhost:9443/emailotpauthenticationendpoint/emailotpError.jsp"},
                {"carbon.super", "https://localhost:9443/emailotpauthenticationendpoint/emailotpError.jsp"},

                {TENANT_DOMAIN, "https://localhost:9443/t/null/emailotpauthenticationendpoint/emailotpError.jsp"},
                {TENANT_DOMAIN, "https://localhost:9443/t/null/emailotpauthenticationendpoint/emailotpError.jsp"},

        };
    }

    @Test(description = "Tests getting email request page URL from config in tenant qualified URL mode.")
    public void testGetEmailAddressRequestPageFromConfig() throws Exception {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(true);
        when(IdentityTenantUtil.getTenantDomainFromContext()).thenReturn(TENANT_DOMAIN);

        String reqPageFromConfig = "emailotpEndpoint/reqPage.jsp";

        Map<String, String> parameters = new HashMap<>();
        parameters.put(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS_REQ_PAGE, reqPageFromConfig);

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(TENANT_DOMAIN);
        context.setProperty(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS_REQ_PAGE, reqPageFromConfig);

        String expectedURL = "https://localhost:9443/t/wso2.org/emailotpEndpoint/reqPage.jsp";
        Assert.assertEquals(EmailOTPUrlUtil.getRequestEmailPageUrl(context, parameters), expectedURL);
    }

    private void mockServiceURLBuilder() throws URLBuilderException {

        ServiceURLBuilder builder = new ServiceURLBuilder() {

            private String path = "";

            @Override
            public ServiceURLBuilder addPath(String... strings) {

                Arrays.stream(strings).forEach(x -> {
                    path += "/" + x;
                });
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
            public ServiceURL build() throws URLBuilderException {

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
