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

package org.wso2.carbon.identity.oauth2new.bean.message.request.authz;

import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationRequestBuilder;

import java.util.Set;

public class TokenResponseRequest extends OAuth2AuthzRequest {

    private static final long serialVersionUID = -2571263137456231933L;

    String clientId;
    String redirectURI;
    Set<String> scopes;

    protected TokenResponseRequest(InboundAuthenticationRequestBuilder builder) {
        super(builder);
        TokenResponseRequestBuilder requestBuilder = (TokenResponseRequestBuilder)builder;
        this.clientId = requestBuilder.clientId;
        this.redirectURI = requestBuilder.redirectURI;
        this.scopes = requestBuilder.scopes;
    }
}
