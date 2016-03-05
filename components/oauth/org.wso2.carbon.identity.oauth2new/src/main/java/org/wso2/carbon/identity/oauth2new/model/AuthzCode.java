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
import java.sql.Timestamp;
import java.util.Set;

public class AuthzCode implements Serializable {

    private String authzCode;

    private String clientId;

    private String redirectURI;

    private User authzUser;

    private Set<String> scopes;

    private Timestamp issuedTime;

    private long validityPeriod;

    public AuthzCode(String authzCode, String clientId, String redirectURI, User authzUser, Timestamp issuedTime, long validityPeriod) {
        this.authzCode = authzCode;
        this.clientId = clientId;
        this.redirectURI = redirectURI;
        this.authzUser = authzUser;
        this.issuedTime = issuedTime;
        this.validityPeriod = validityPeriod;
    }

    public String getAuthzCode() {
        return authzCode;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRedirectURI() {
        return redirectURI;
    }

    public User getAuthzUser() {
        return authzUser;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public Timestamp getIssuedTime() {
        return issuedTime;
    }

    public long getValidityPeriod() {
        return validityPeriod;
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes;
    }

    @Override
    public String toString() {
        return "AuthzCode{" +
                "clientId='" + clientId + '\'' +
                ", redirectURI='" + redirectURI + '\'' +
                ", authzUser=" + authzUser +
                ", scopes=" + scopes +
                ", issuedTime=" + issuedTime +
                ", validityPeriod=" + validityPeriod +
                '}';
    }

}
