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

public class PasswordGrantRequest extends OAuth2TokenRequest {

    private static final long serialVersionUID = -4072916934667966426L;

    private String username;
    private char[] password;
    private Set<String> scopes = new HashSet<>();

    protected PasswordGrantRequest(InboundAuthenticationRequestBuilder builder) {
        super(builder);
        PasswordGrantBuilder passwordGrantBuilder = (PasswordGrantBuilder)builder;
        this.username = passwordGrantBuilder.username;
        this.password = passwordGrantBuilder.password;
    }

    public String getUsername() {
        return username;
    }

    public char[] getPassword() {
        return password;
    }

    public Set<String> getScopes() {
        return scopes;
    }
}
