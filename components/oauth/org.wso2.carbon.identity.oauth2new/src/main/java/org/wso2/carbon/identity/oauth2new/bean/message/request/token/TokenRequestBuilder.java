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

import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2InboundRequestBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Set;

public abstract class TokenRequestBuilder extends OAuth2InboundRequestBuilder {

    String grantType;
    Set<String> requestedScopes;

    public TokenRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
        super(request, response);
    }

    @Override
    public String getName() {
        return "TokenRequestBuilder";
    }

    public TokenRequestBuilder setGrantType(String grantType) {
        this.grantType = grantType;
        return this;
    }

    public TokenRequestBuilder setRequestedScopes(Set<String> requestedScopes) {
        this.requestedScopes = requestedScopes;
        return this;
    }

}
