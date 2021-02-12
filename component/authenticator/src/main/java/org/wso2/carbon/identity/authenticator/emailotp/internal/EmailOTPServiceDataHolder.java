/*
 *  Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.wso2.carbon.identity.mgt.account.lock.AccountLockService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 *  Encapsulates the data of EmailOTP authenticator.
 */
public class EmailOTPServiceDataHolder {

    private static EmailOTPServiceDataHolder emailOTPServiceDataHolder;
    private AccountLockService accountLockService;
    private RealmService realmService;

    /**
     * Returns the DataHolder instance.
     *
     * @return The DataHolder instance
     */
    public static EmailOTPServiceDataHolder getInstance() {

        if (emailOTPServiceDataHolder == null) {
            emailOTPServiceDataHolder = new EmailOTPServiceDataHolder();
        }
        return emailOTPServiceDataHolder;
    }

    /**
     * Returns the Realm service.
     *
     * @return Realm service.
     */
    public RealmService getRealmService() {

        return realmService;
    }

    /**
     * Sets the Realm service.
     *
     * @param realmService Realm service.
     */
    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
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
}
