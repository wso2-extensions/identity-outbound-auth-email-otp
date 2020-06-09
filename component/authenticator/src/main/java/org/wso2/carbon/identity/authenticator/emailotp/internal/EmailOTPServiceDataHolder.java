/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 *  Encapsulates the data of EmailOTP authenticator.
 */
public class EmailOTPServiceDataHolder {
    private static EmailOTPServiceDataHolder emailOTPServiceDataHolder;
    private AccountLockService accountLockService;
    private IdentityEventService identityEventService;
    private IdentityGovernanceService identityGovernanceService;
    private RealmService realmService;

    public static EmailOTPServiceDataHolder getInstance() {
        if (emailOTPServiceDataHolder == null) {
            emailOTPServiceDataHolder = new EmailOTPServiceDataHolder();
        }
        return emailOTPServiceDataHolder;
    }

    private EmailOTPServiceDataHolder() {

    }

    public IdentityEventService getIdentityEventService() {
        return identityEventService;
    }

    public void setIdentityEventService(IdentityEventService identityEventService) {
        this.identityEventService = identityEventService;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    /**
     * Get Identity Governance Service.
     *
     * @return Identity Governance Service.
     */
    public IdentityGovernanceService getIdentityGovernanceService() {

        if (identityGovernanceService == null) {
            throw new RuntimeException("IdentityGovernanceService not available. Component is not started properly.");
        }
        return identityGovernanceService;
    }

    /**
     * Set Identity Governance Service.
     *
     * @param identityGovernanceService Identity Governance Service.
     */
    public void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        this.identityGovernanceService = identityGovernanceService;
    }

    /**
     * Get Account Lock service.
     *
     * @return Account Lock service.
     */
    public AccountLockService getAccountLockService() {

        return accountLockService;
    }

    /**
     * set Account Lock service.
     *
     * @param accountLockService Account Lock service.
     */
    public void setAccountLockService(AccountLockService accountLockService) {

        this.accountLockService = accountLockService;
    }
}
