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

public class AuthzCodeGrantRequest extends OAuth2TokenRequest {

    private static final long serialVersionUID = -7079593227614826792L;

    private String code;
    private String redirectURI;

    protected AuthzCodeGrantRequest(InboundAuthenticationRequestBuilder builder) {
        super(builder);
        AuthzCodeGrantBuilder authzCodeGrantBuilder = (AuthzCodeGrantBuilder)builder;
        this.code = ((AuthzCodeGrantBuilder) builder).code;
        this.redirectURI = ((AuthzCodeGrantBuilder) builder).redirectURI;
    }

    public String getCode() {
        return code;
    }

    public String getRedirectURI() {
        return redirectURI;
    }
}
