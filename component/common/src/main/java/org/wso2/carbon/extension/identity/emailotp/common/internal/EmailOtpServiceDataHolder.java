/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.extension.identity.emailotp.common.internal;

import org.wso2.carbon.extension.identity.emailotp.common.dto.ConfigsDTO;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Data holder for Email OTP Service.
 */
public class EmailOtpServiceDataHolder {

    private static final EmailOtpServiceDataHolder dataHolder = new EmailOtpServiceDataHolder();
    private RealmService realmService;
    private AccountLockService accountLockService;
    private IdentityGovernanceService identityGovernanceService;
    private static final ConfigsDTO configs = new ConfigsDTO();

    /**
     * To get the Email OTP service data holder instance.
     *
     * @return The instance of EmailOtpServiceDataHolder.
     */
    public static EmailOtpServiceDataHolder getInstance() {

        return dataHolder;
    }

    /**
     * This is to get the Realm service.
     *
     * @return The instance of RealmService.
     */
    public RealmService getRealmService() {

        return realmService;
    }

    /**
     * To set the Realm Service.
     *
     * @param realmService RealmService instance.
     */
    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    /**
     * To get the configurations.
     *
     * @return The configurations are applied to the Email OTP service.
     */
    public static ConfigsDTO getConfigs() {

        return configs;
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
     * Set Account Lock service.
     *
     * @param accountLockService Account Lock service.
     */
    public void setAccountLockService(AccountLockService accountLockService) {

        this.accountLockService = accountLockService;
    }

    /**
     * Get Identity Governance service.
     *
     * @return Identity Governance service.
     */
    public IdentityGovernanceService getIdentityGovernanceService() {

        return identityGovernanceService;
    }

    /**
     * Set Identity Governance service.
     *
     * @param identityGovernanceService Identity Governance service.
     */
    public void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        this.identityGovernanceService = identityGovernanceService;
    }
}
