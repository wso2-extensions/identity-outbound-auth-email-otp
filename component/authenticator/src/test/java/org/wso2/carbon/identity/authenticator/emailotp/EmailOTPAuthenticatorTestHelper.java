/*
 *  Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.emailotp;

import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;

/**
 * Helper class to invoke private methods of {@link EmailOTPAuthenticator} for testing using reflection.
 */
public class EmailOTPAuthenticatorTestHelper {

    private EmailOTPAuthenticatorTestHelper() {
        // Utility class.
    }

    public static boolean retryAuthenticationEnabled(EmailOTPAuthenticator authenticator) throws Exception {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("retryAuthenticationEnabled");
        method.setAccessible(true);
        return (Boolean) method.invoke(authenticator);
    }

    public static String getPrepareURLParams(EmailOTPAuthenticator authenticator, AuthenticationContext context,
                                             Map<String, String> parameters, String api) throws Exception {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("getPrepareURLParams",
                AuthenticationContext.class, Map.class, String.class);
        method.setAccessible(true);
        return (String) method.invoke(authenticator, context, parameters, api);
    }

    public static String getPrepareFormData(EmailOTPAuthenticator authenticator, AuthenticationContext context,
                                            Map<String, String> parameters, String api) throws Exception {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("getPrepareFormData",
                AuthenticationContext.class, Map.class, String.class);
        method.setAccessible(true);
        return (String) method.invoke(authenticator, context, parameters, api);
    }

    public static String getFailureString(EmailOTPAuthenticator authenticator, AuthenticationContext context,
                                          Map<String, String> parameters, String api) throws Exception {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("getFailureString",
                AuthenticationContext.class, Map.class, String.class);
        method.setAccessible(true);
        return (String) method.invoke(authenticator, context, parameters, api);
    }

    public static String getAuthTokenType(EmailOTPAuthenticator authenticator, AuthenticationContext context,
                                          Map<String, String> parameters, String api) throws Exception {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("getAuthTokenType",
                AuthenticationContext.class, Map.class, String.class);
        method.setAccessible(true);
        return (String) method.invoke(authenticator, context, parameters, api);
    }

    public static String getAccessTokenEndpoint(EmailOTPAuthenticator authenticator, AuthenticationContext context,
                                                Map<String, String> parameters, String api) throws Exception {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("getAccessTokenEndpoint",
                AuthenticationContext.class, Map.class, String.class);
        method.setAccessible(true);
        return (String) method.invoke(authenticator, context, parameters, api);
    }

    public static String getAPI(EmailOTPAuthenticator authenticator, Map<String, String> authenticatorProperties)
            throws Exception {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("getAPI", Map.class);
        method.setAccessible(true);
        return (String) method.invoke(authenticator, authenticatorProperties);
    }

    public static boolean isShowEmailAddressInUIEnable(EmailOTPAuthenticator authenticator,
                                                       AuthenticationContext context,
                                                       Map<String, String> parameters) throws Exception {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("isShowEmailAddressInUIEnable",
                AuthenticationContext.class, Map.class);
        method.setAccessible(true);
        return (Boolean) method.invoke(authenticator, context, parameters);
    }

    public static boolean isEmailAddressUpdateEnable(EmailOTPAuthenticator authenticator,
                                                     AuthenticationContext context,
                                                     Map<String, String> parameters) throws Exception {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("isEmailAddressUpdateEnable",
                AuthenticationContext.class, Map.class);
        method.setAccessible(true);
        return (Boolean) method.invoke(authenticator, context, parameters);
    }

    public static void updateUserAttribute(EmailOTPAuthenticator authenticator, String username,
                                           Map<String, String> attributes, String tenantDomain) throws Throwable {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("updateUserAttribute",
                String.class, Map.class, String.class);
        method.setAccessible(true);
        try {
            method.invoke(authenticator, username, attributes, tenantDomain);
        } catch (InvocationTargetException e) {
            throw e.getTargetException();
        }
    }

    public static void checkEmailOTPBehaviour(EmailOTPAuthenticator authenticator, AuthenticationContext context,
                                              Map<String, String> emailOTPParameters,
                                              Map<String, String> authenticatorProperties,
                                              String emailAddress, String username, String token,
                                              String ipAddress) throws Throwable {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("checkEmailOTPBehaviour",
                AuthenticationContext.class, Map.class, Map.class, String.class, String.class, String.class,
                String.class);
        method.setAccessible(true);
        try {
            method.invoke(authenticator, context, emailOTPParameters, authenticatorProperties, emailAddress, username,
                    token, ipAddress);
        } catch (InvocationTargetException e) {
            throw e.getTargetException();
        }
    }

    public static void processAuthenticationResponse(EmailOTPAuthenticator authenticator,
                                                     javax.servlet.http.HttpServletRequest request,
                                                     javax.servlet.http.HttpServletResponse response,
                                                     AuthenticationContext context) throws Exception {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("processAuthenticationResponse",
                javax.servlet.http.HttpServletRequest.class,
                javax.servlet.http.HttpServletResponse.class,
                AuthenticationContext.class);
        method.setAccessible(true);
        method.invoke(authenticator, request, response, context);
    }

    public static void processValidUserToken(EmailOTPAuthenticator authenticator, AuthenticationContext context,
                                             org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser user)
            throws Exception {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("processValidUserToken",
                AuthenticationContext.class,
                org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser.class);
        method.setAccessible(true);
        method.invoke(authenticator, context, user);
    }

    public static boolean isBackUpCodeValid(EmailOTPAuthenticator authenticator, String[] savedOTPs,
                                            String userToken) throws Exception {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("isBackUpCodeValid",
                String[].class, String.class);
        method.setAccessible(true);
        return (Boolean) method.invoke(authenticator, new Object[]{savedOTPs, userToken});
    }

    public static boolean isBackupCodeEnabled(EmailOTPAuthenticator authenticator, AuthenticationContext context)
            throws Exception {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("isBackupCodeEnabled",
                AuthenticationContext.class);
        method.setAccessible(true);
        return (Boolean) method.invoke(authenticator, context);
    }

    public static org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser
    getAuthenticatedUser(EmailOTPAuthenticator authenticator, AuthenticationContext context) throws Exception {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("getAuthenticatedUser",
                AuthenticationContext.class);
        method.setAccessible(true);
        return (org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser)
                method.invoke(authenticator, context);
    }

    public static void verifyUserExists(EmailOTPAuthenticator authenticator, String username, String tenantDomain)
            throws Throwable {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("verifyUserExists",
                String.class, String.class);
        method.setAccessible(true);
        try {
            method.invoke(authenticator, username, tenantDomain);
        } catch (InvocationTargetException e) {
            throw e.getTargetException();
        }
    }

    public static String getRedirectURL(EmailOTPAuthenticator authenticator, String baseURI, String queryParams)
            throws Exception {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("getRedirectURL",
                String.class, String.class);
        method.setAccessible(true);
        return (String) method.invoke(authenticator, baseURI, queryParams);
    }

    public static int getEmailOTPLength(EmailOTPAuthenticator authenticator, Map<String, String> properties)
            throws Exception {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("getEmailOTPLength", Map.class);
        method.setAccessible(true);
        return (Integer) method.invoke(authenticator, properties);
    }

    public static int getEmailOTPExpiryTime(EmailOTPAuthenticator authenticator, Map<String, String> properties)
            throws Exception {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("getEmailOTPExpiryTime", Map.class);
        method.setAccessible(true);
        return (Integer) method.invoke(authenticator, properties);
    }

    public static String getMultiOptionURIQueryParam(EmailOTPAuthenticator authenticator,
                                                     javax.servlet.http.HttpServletRequest request)
            throws Exception {
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("getMultiOptionURIQueryParam",
                javax.servlet.http.HttpServletRequest.class);
        method.setAccessible(true);
        return (String) method.invoke(authenticator, request);
    }
}

