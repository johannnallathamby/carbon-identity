/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2new.admin.listener;

import org.wso2.carbon.identity.user.store.configuration.listener.AbstractUserStoreConfigListener;
import org.wso2.carbon.user.api.UserStoreException;

/*
 * If user store names are updated, or user stores are deleted, the corresponding access tokens in
 * IDN_OAUTH2_ACCESS_TOKEN table should be updated to reflect the name change or to REVOKED state.
 */
public class OAuth2UserStoreConfigListener extends AbstractUserStoreConfigListener {

    @Override
    public void onUserStoreNamePreUpdate(int tenantId, String currentUserStoreName, String newUserStoreName) throws UserStoreException {

    }

    @Override
    public void onUserStorePreDelete(int tenantId, String userStoreName) throws UserStoreException {

    }
}
