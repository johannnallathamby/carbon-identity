/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2new.bean.message.request.token;

import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationRequestBuilder;

import java.util.HashSet;
import java.util.Set;

public class RefreshGrantRequest extends OAuth2TokenRequest {

    char[] refreshToken;

    private Set<String> scopes = new HashSet<>();

    protected RefreshGrantRequest(InboundAuthenticationRequestBuilder builder) {
        super(builder);
        RefreshGrantBuilder refreshGrantBuilder = (RefreshGrantBuilder)builder;
        this.refreshToken = refreshGrantBuilder.refreshToken;
    }

    public Set<String> getScopes() {
        return scopes;
    }
}
