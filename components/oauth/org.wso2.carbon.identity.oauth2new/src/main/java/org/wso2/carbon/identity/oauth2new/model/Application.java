/*
 *Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *WSO2 Inc. licenses this file to you under the Apache License,
 *Version 2.0 (the "License"); you may not use this file except
 *in compliance with the License.
 *You may obtain a copy of the License at
 *
 *http://www.apache.org/licenses/LICENSE-2.0
 *
 *Unless required by applicable law or agreed to in writing,
 *software distributed under the License is distributed on an
 *"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *KIND, either express or implied.  See the License for the
 *specific language governing permissions and limitations
 *under the License.
 */

package org.wso2.carbon.identity.oauth2new.model;

import org.wso2.carbon.identity.application.common.model.User;

import java.io.Serializable;
import java.util.Set;

public class Application implements Serializable {

    private String clientId;
    private String clientSecret;
    private String applicationName;
    private String redirectURI;
    private User applicationOwner;
    private Set<String> allowedResponseTypes;
    private Set<String> allowedGrantTypes;

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    public String getRedirectURI() {
        return redirectURI;
    }

    public void setRedirectURI(String redirectURI) {
        this.redirectURI = redirectURI;
    }

    public User getApplicationOwner() {
        return applicationOwner;
    }

    public void setApplicationOwner(User applicationOwner) {
        this.applicationOwner = applicationOwner;
    }

    public Set<String> getAllowedResponseTypes() {
        return allowedResponseTypes;
    }

    public void setAllowedResponseTypes(Set<String> allowedResponseTypes) {
        this.allowedResponseTypes = allowedResponseTypes;
    }

    public Set<String> getAllowedGrantTypes() {
        return allowedGrantTypes;
    }

    public void setAllowedGrantTypes(Set<String> allowedGrantTypes) {
        this.allowedGrantTypes = allowedGrantTypes;
    }
}
