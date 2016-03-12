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
import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2InboundRequest;

import java.util.Set;

public class OAuth2AuthzRequest extends OAuth2InboundRequest {

    private static final long serialVersionUID = 6738091486923517921L;

    private String responseType;
    private String redirectURI;
    private String state;

    protected OAuth2AuthzRequest(InboundAuthenticationRequestBuilder builder) {
        super(builder);
        AuthzRequestBuilder authzRequestBuilder = ((AuthzRequestBuilder)builder);
        this.responseType = authzRequestBuilder.responseType;
        this.redirectURI = authzRequestBuilder.redirectURI;
        this.state = authzRequestBuilder.state;
    }

    public String getResponseType() {
        return responseType;
    }

    public String getRedirectURI() {
        return redirectURI;
    }

    public String getState() {
        return state;
    }

}
