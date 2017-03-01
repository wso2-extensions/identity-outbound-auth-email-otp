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
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.authenticator.emailotp.exception.EmailOTPException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

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
    public static boolean isEmailOTPEnableForLocalUser(String username, AuthenticationContext context, boolean isUserExistence)
            throws EmailOTPException {
        String email = getEmailValueForUsername(username, context, isUserExistence);
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
    public static String getEmailValueForUsername(String username, AuthenticationContext context, boolean isUserExistence)
            throws EmailOTPException {
        UserRealm userRealm;
        String tenantAwareUsername = null;
        String email = null;
        try {
            if (isUserExistence) {
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
                    throw new EmailOTPException("Cannot find the user realm for the given tenant domain : " + CarbonContext
                            .getThreadLocalCarbonContext().getTenantDomain());
                }
            } else {
                return null;
            }
        } catch (UserStoreException e) {
            throw new EmailOTPException("Cannot find the user claim for email " + e.getMessage(), e);
        }
        return email;
    }
}