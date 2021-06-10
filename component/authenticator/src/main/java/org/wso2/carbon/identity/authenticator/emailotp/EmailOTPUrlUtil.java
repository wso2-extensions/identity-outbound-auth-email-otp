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
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import static org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticatorConstants.EMAILOTP_PAGE;
import static org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticatorConstants.EMAIL_ADDRESS_CAPTURE_PAGE;
import static org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticatorConstants.EMAIL_ADDRESS_REQ_PAGE;
import static org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticatorConstants.ERROR_PAGE;

/**
 * Utility for building URLs related to email otp authentication flow.
 */
public class EmailOTPUrlUtil {

    private EmailOTPUrlUtil() {

    }

    public static String getRequestEmailPageUrl(AuthenticationContext context,
                                                Map<String, String> authenticationConfigs)
            throws AuthenticationFailedException {

        try {
            String requestEmailPage = getEmailAddressRequestPage(context, authenticationConfigs);
            return buildURL(requestEmailPage, EMAIL_ADDRESS_CAPTURE_PAGE);
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error building email request page URL.", e);
        }
    }

    public static String getEmailOTPLoginPageUrl(AuthenticationContext context,
                                                 Map<String, String> authenticationConfigs)
            throws AuthenticationFailedException {

        try {
            String emailOTPLoginPage = getEmailOTPLoginPage(context, authenticationConfigs);
            return buildURL(emailOTPLoginPage, EMAILOTP_PAGE);
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error building email OTP login page URL.", e);
        }
    }

    public static String getEmailOTPErrorPageUrl(AuthenticationContext context,
                                                 Map<String, String> authenticationConfigs)
            throws AuthenticationFailedException {

        try {
            String emailOTPErrorPage = getEmailOTPErrorPage(context, authenticationConfigs);
            return buildURL(emailOTPErrorPage, ERROR_PAGE);
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error building email OTP error page URL.", e);
        }
    }

    /**
     * Get the email address request page url from the application-authentication.xml file.
     *
     * @param context The AuthenticationContext.
     * @return Email address request page.
     */
    private static String getEmailAddressRequestPage(AuthenticationContext context,
                                                     Map<String, String> parametersMap) throws URLBuilderException {

        String emailAddressReqPage;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || EmailOTPAuthenticatorConstants.SUPER_TENANT.equals(tenantDomain)) &&
                parametersMap.containsKey(EMAIL_ADDRESS_REQ_PAGE)) {
            emailAddressReqPage = parametersMap.get(EMAIL_ADDRESS_REQ_PAGE);
        } else if ((context.getProperty(EMAIL_ADDRESS_REQ_PAGE)) != null) {
            emailAddressReqPage = String.valueOf(context.getProperty(EMAIL_ADDRESS_REQ_PAGE));
        } else {
            emailAddressReqPage =
                    ServiceURLBuilder.create().addPath(EMAIL_ADDRESS_CAPTURE_PAGE).build().getAbsolutePublicURL();
        }
        return emailAddressReqPage;
    }

    /**
     * Get ErrorPage for Gmail APIs.
     *
     * @param context       Authentication Context.
     * @param parametersMap Parameter map.
     * @return ErrorPage for Gmail APIs.
     * @throws URLBuilderException If an error occurred while getting the ErrorPage for Gmail APIs.
     */
    private static String getEmailOTPErrorPage(AuthenticationContext context,
                                               Map<String, String> parametersMap) throws URLBuilderException {

        String errorPage;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || EmailOTPAuthenticatorConstants.SUPER_TENANT.equals(tenantDomain)) &&
                parametersMap.containsKey(EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ERROR_PAGE_URL)) {
            errorPage = parametersMap.get(EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ERROR_PAGE_URL);
        } else if ((context.getProperty(EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ERROR_PAGE_URL))
                != null) {
            errorPage = String.valueOf(context.getProperty
                    (EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ERROR_PAGE_URL));
        } else {
            errorPage = ServiceURLBuilder.create().addPath(ERROR_PAGE).build().getAbsolutePublicURL();
        }
        return errorPage;
    }

    /**
     * Get LoginPage for Gmail APIs.
     *
     * @param context       Authentication Context.
     * @param parametersMap Parameter map.
     * @return ErrorPage for Gmail APIs.
     * @throws URLBuilderException If an error occurred while getting the LoginPage for Gmail APIs.
     */
    private static String getEmailOTPLoginPage(AuthenticationContext context,
                                               Map<String, String> parametersMap) throws URLBuilderException {

        String loginPage;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || EmailOTPAuthenticatorConstants.SUPER_TENANT.equals(tenantDomain)) &&
                parametersMap.containsKey(EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ENDPOINT_URL)) {
            loginPage = parametersMap.get(EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ENDPOINT_URL);
        } else if ((context.getProperty(EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ENDPOINT_URL)) != null) {
            loginPage = String.valueOf(context.getProperty
                    (EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ENDPOINT_URL));
        } else {
            loginPage = ServiceURLBuilder.create().addPath(EMAILOTP_PAGE).build().getAbsolutePublicURL();
        }
        return loginPage;
    }

    private static String buildURL(String urlFromConfig, String defaultContext) throws URLBuilderException {

        String contextToBuildURL = defaultContext;
        if (StringUtils.isNotBlank(urlFromConfig)) {
            contextToBuildURL = urlFromConfig;
        }
        try {
            if (isURLRelative(contextToBuildURL)) {
                // When tenant qualified URL feature is enabled, this will generate a tenant qualified URL.
                return ServiceURLBuilder.create().addPath(contextToBuildURL).build().getAbsolutePublicURL();
            }
        } catch (URISyntaxException e) {
            throw new URLBuilderException("Error while building public absolute URL for context: " + defaultContext, e);
        }

        // URL from the configuration was an absolute one. We return the same without any modification.
        return contextToBuildURL;
    }

    private static boolean isURLRelative(String contextFromConfig) throws URISyntaxException {

        return !new URI(contextFromConfig).isAbsolute();
    }
}
