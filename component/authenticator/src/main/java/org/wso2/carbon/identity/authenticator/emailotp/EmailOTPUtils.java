/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.authenticator.emailotp;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.authenticator.emailotp.exception.EmailOTPException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Map;

public class EmailOTPUtils {

    private static Log log = LogFactory.getLog(EmailOTPUtils.class);

    /**
     * Check whether EmailOTP is enable by user.
     *
     * @param username the user name
     * @param context  the authentication context
     * @return true or false
     * @throws EmailOTPException
     */
    public static boolean isEmailOTPEnableForLocalUser(String username, AuthenticationContext context)
            throws EmailOTPException {
        String email = getEmailValueForUsername(username, context);
        return !StringUtils.isEmpty(email);
    }

    /**
     * Get email value for username
     *
     * @param username the user name
     * @param context  the authentication context
     * @return email
     * @throws EmailOTPException
     */
    public static String getEmailValueForUsername(String username, AuthenticationContext context)
            throws EmailOTPException {
        UserRealm userRealm;
        String tenantAwareUsername;
        String email;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
            if (userRealm != null) {
                email = userRealm.getUserStoreManager()
                        .getUserClaimValue(tenantAwareUsername, EmailOTPAuthenticatorConstants.EMAIL_CLAIM, null);
                context.setProperty(EmailOTPAuthenticatorConstants.RECEIVER_EMAIL, email);
            } else {
                throw new EmailOTPException("Cannot find the user realm for the given tenant domain : "
                        + CarbonContext.getThreadLocalCarbonContext().getTenantDomain());
            }
        } catch (UserStoreException e) {
            throw new EmailOTPException("Cannot find the user claim for email " + e.getMessage(), e);
        }
        return email;
    }

    /**
     * Get clientId for Gmail APIs
     */
    public static String getClientId(AuthenticationContext context, Map<String, String> parametersMap,
                                     String authenticatorName, String api) throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String clientId = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if (propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            if (parametersMap.containsKey(api + OIDCAuthenticatorConstants.CLIENT_ID)) {
                clientId = parametersMap.get(api + OIDCAuthenticatorConstants.CLIENT_ID);
            }
        } else {
            if ((context.getProperty(api + OIDCAuthenticatorConstants.CLIENT_ID)) != null) {
                clientId = String.valueOf(context.getProperty(api + OIDCAuthenticatorConstants.CLIENT_ID));
            }
        }
        return clientId;
    }

    /**
     * Get clientSecret for Gmail APIs
     */
    public static String getClientSecret(AuthenticationContext context, Map<String, String> parametersMap,
                                         String authenticatorName, String api) throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String clientSecret = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if (propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            if (parametersMap.containsKey(api + OIDCAuthenticatorConstants.CLIENT_SECRET)) {
                clientSecret = parametersMap.get(api + OIDCAuthenticatorConstants.CLIENT_SECRET);
            }
        } else {
            if ((context.getProperty(api + OIDCAuthenticatorConstants.CLIENT_SECRET)) != null) {
                clientSecret = String.valueOf(context.getProperty(api + OIDCAuthenticatorConstants.CLIENT_SECRET));
            }
        }
        return clientSecret;
    }

    /**
     * Get RefreshToken for Gmail APIs
     */
    public static String getRefreshToken(AuthenticationContext context, Map<String, String> parametersMap,
                                         String authenticatorName, String api) throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String refreshToken = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if (propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            if (parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.REFRESH_TOKEN)) {
                refreshToken = parametersMap.get(api + EmailOTPAuthenticatorConstants.REFRESH_TOKEN);
            }
        } else {
            if ((context.getProperty(api + EmailOTPAuthenticatorConstants.REFRESH_TOKEN)) != null) {
                refreshToken = String.valueOf(context.getProperty(api + EmailOTPAuthenticatorConstants.REFRESH_TOKEN));
            }
        }
        return refreshToken;
    }

    /**
     * Get ApiKey for Gmail APIs
     */
    public static String getApiKey(AuthenticationContext context, Map<String, String> parametersMap,
                                   String authenticatorName, String api) throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String apiKey = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if (propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            if (parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY)) {
                apiKey = parametersMap.get(api + EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY);
            }
        } else {
            if ((context.getProperty(api + EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY)) != null) {
                apiKey = String.valueOf(context.getProperty(api + EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY));
            }
        }
        return apiKey;
    }

    /**
     * Get MailingEndpoint for Gmail APIs
     */
    public static String getMailingEndpoint(AuthenticationContext context, Map<String, String> parametersMap,
                                            String authenticatorName, String api) throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String mailingEndpoint = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if (propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            if (parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.MAILING_ENDPOINT)) {
                mailingEndpoint = parametersMap.get(api + EmailOTPAuthenticatorConstants.MAILING_ENDPOINT);
            }
        } else {
            if ((context.getProperty(api + EmailOTPAuthenticatorConstants.MAILING_ENDPOINT)) != null) {
                mailingEndpoint = String.valueOf(context.getProperty
                        (api + EmailOTPAuthenticatorConstants.MAILING_ENDPOINT));
            }
        }
        return mailingEndpoint;
    }

    /**
     * Get required payload for Gmail APIs
     */
    public static String getPreparePayload(AuthenticationContext context, Map<String, String> parametersMap,
                                           String authenticatorName, String api) throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String payload = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if (propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            if (parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.PAYLOAD)) {
                payload = parametersMap.get(api + EmailOTPAuthenticatorConstants.PAYLOAD);
            }
        } else {
            if ((context.getProperty(api + EmailOTPAuthenticatorConstants.PAYLOAD)) != null) {
                payload = String.valueOf(context.getProperty(api + EmailOTPAuthenticatorConstants.PAYLOAD));
            }
        }
        return payload;
    }

    /**
     * Get required FormData for Gmail APIs
     */
    public static String getPrepareFormData(AuthenticationContext context, Map<String, String> parametersMap,
                                            String authenticatorName, String api) throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String prepareFormData = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if (propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            if (parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.FORM_DATA)) {
                prepareFormData = parametersMap.get(api + EmailOTPAuthenticatorConstants.FORM_DATA);
            }
        } else {
            if ((context.getProperty(api + EmailOTPAuthenticatorConstants.FORM_DATA)) != null) {
                prepareFormData = String.valueOf(context.getProperty(api + EmailOTPAuthenticatorConstants.FORM_DATA));
            }
        }
        return prepareFormData;
    }

    /**
     * Get required URL params for Gmail APIs
     */
    public static String getPrepareURLParams(AuthenticationContext context, Map<String, String> parametersMap,
                                             String authenticatorName, String api) throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String prepareUrlParams = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if (propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            if (parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.URL_PARAMS)) {
                prepareUrlParams = parametersMap.get(api + EmailOTPAuthenticatorConstants.URL_PARAMS);
            }
        } else {
            if ((context.getProperty(api + EmailOTPAuthenticatorConstants.URL_PARAMS)) != null) {
                prepareUrlParams = String.valueOf(context.getProperty(api + EmailOTPAuthenticatorConstants.URL_PARAMS));
            }
        }
        return prepareUrlParams;
    }

    /**
     * Get failureString for Gmail APIs
     */
    public static String getFailureString(AuthenticationContext context, Map<String, String> parametersMap,
                                          String authenticatorName, String api) throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String failureString = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if (propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            if (parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.FAILURE)) {
                failureString = parametersMap.get(api + EmailOTPAuthenticatorConstants.FAILURE);
            }
        } else {
            if ((context.getProperty(api + EmailOTPAuthenticatorConstants.FAILURE)) != null) {
                failureString = String.valueOf(context.getProperty(api + EmailOTPAuthenticatorConstants.FAILURE));
            }
        }
        return failureString;
    }

    /**
     * Get AuthToken type for Gmail APIs
     */
    public static String getAuthTokenType(AuthenticationContext context, Map<String, String> parametersMap,
                                          String authenticatorName, String api) throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String authTokenType = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if (propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            if (parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.HTTP_AUTH_TOKEN_TYPE)) {
                authTokenType = parametersMap.get(api + EmailOTPAuthenticatorConstants.HTTP_AUTH_TOKEN_TYPE);
            }
        } else {
            if ((context.getProperty(api + EmailOTPAuthenticatorConstants.HTTP_AUTH_TOKEN_TYPE)) != null) {
                authTokenType = String.valueOf(context.getProperty
                        (api + EmailOTPAuthenticatorConstants.HTTP_AUTH_TOKEN_TYPE));
            }
        }
        return authTokenType;
    }

    /**
     * Get AccessToken endpoint for Gmail APIs
     */
    public static String getAccessTokenEndpoint(AuthenticationContext context, Map<String, String> parametersMap,
                                                String authenticatorName, String api)
            throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String tokenEndpoint = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if (propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            if (parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.EMAILOTP_TOKEN_ENDPOINT)) {
                tokenEndpoint = parametersMap.get(api + EmailOTPAuthenticatorConstants.EMAILOTP_TOKEN_ENDPOINT);
            }
        } else {
            if ((context.getProperty(api + EmailOTPAuthenticatorConstants.EMAILOTP_TOKEN_ENDPOINT)) != null) {
                tokenEndpoint = String.valueOf(context.getProperty
                        (api + EmailOTPAuthenticatorConstants.EMAILOTP_TOKEN_ENDPOINT));
            }
        }
        return tokenEndpoint;
    }

    /**
     * Get ErrorPage for Gmail APIs
     */
    public static String getErrorPage(AuthenticationContext context, Map<String, String> parametersMap,
                                      String authenticatorName) throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String errorPage = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if (propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            if (parametersMap.containsKey(EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ERROR_PAGE_URL)) {
                errorPage = parametersMap.get(EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ERROR_PAGE_URL);
            }
        } else {
            if ((context.getProperty(EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ERROR_PAGE_URL)) != null) {
                errorPage = String.valueOf(context.getProperty
                        (EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ERROR_PAGE_URL));
            }
        }
        return errorPage;
    }

    /**
     * Get LoginPage for Gmail APIs
     */
    public static String getLoginPage(AuthenticationContext context, Map<String, String> parametersMap,
                                      String authenticatorName) throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String loginPage = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if (propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            if (parametersMap.containsKey(EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ENDPOINT_URL)) {
                loginPage = parametersMap.get(EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ENDPOINT_URL);
            }
        } else {
            if ((context.getProperty(EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ENDPOINT_URL)) != null) {
                loginPage = String.valueOf(context.getProperty
                        (EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ENDPOINT_URL));
            }
        }
        return loginPage;
    }
}