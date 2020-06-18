/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.authenticator.emailotp.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticator;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Hashtable;

/**
 * @scr.component name="identity.application.authenticator.emailotp.component" immediate="true"
 * @scr.reference name="EventMgtService"
 * interface="org.wso2.carbon.identity.event.services.IdentityEventService" cardinality="1..1"
 * policy="dynamic" bind="setIdentityEventService" unbind="unsetIdentityEventService"
 * @scr.reference name="RealmService"
 * interface="org.wso2.carbon.user.core.service.RealmService" cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 * @scr.reference name="IdentityGovernanceService"
 * interface="org.wso2.carbon.identity.governance.IdentityGovernanceService"  cardinality="1..1"
 * policy="dynamic" bind="setIdentityGovernanceService" unbind="unsetIdentityGovernanceService"
 * @scr.reference name="AccountLockService"
 * interface="org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService"  cardinality="1..1"
 * policy="dynamic" bind="setAccountLockService" unbind="unsetAccountLockService"
 */
public class EmailOTPAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(EmailOTPAuthenticatorServiceComponent.class);

    protected void activate(ComponentContext ctxt) {
        try {
            EmailOTPAuthenticator authenticator = new EmailOTPAuthenticator();
            Hashtable<String, String> props = new Hashtable<String, String>();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                    authenticator, props);
            if (log.isDebugEnabled()) {
                log.debug("EmailOTP authenticator is activated");
            }
        } catch (Throwable e) {
            log.fatal("Error while activating the EmailOTP authenticator ", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("EmailOTP authenticator is deactivated");
        }
    }
    protected void unsetIdentityEventService(IdentityEventService eventService) {
        EmailOTPServiceDataHolder.getInstance().setIdentityEventService(null);
    }

    protected void setIdentityEventService(IdentityEventService eventService) {
        EmailOTPServiceDataHolder.getInstance().setIdentityEventService(eventService);
    }

    protected void setRealmService(RealmService realmService) {
         EmailOTPServiceDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        EmailOTPServiceDataHolder.getInstance().setRealmService(null);
    }

    protected void setIdentityGovernanceService(IdentityGovernanceService idpManager) {

        EmailOTPServiceDataHolder.getInstance().setIdentityGovernanceService(idpManager);
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService idpManager) {

        EmailOTPServiceDataHolder.getInstance().setIdentityGovernanceService(null);
    }

    protected void setAccountLockService(AccountLockService accountLockService) {

        EmailOTPServiceDataHolder.getInstance().setAccountLockService(accountLockService);
    }

    protected void unsetAccountLockService(AccountLockService accountLockService) {

        EmailOTPServiceDataHolder.getInstance().setAccountLockService(null);
    }
}
