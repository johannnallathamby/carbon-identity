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

public class AccessToken implements Serializable {

    private String accessToken;

    private String refreshToken;

    private String clientId;

    private User authzUser;

    private String userType;

    private Set<String> scopes;

    private String tokenState;

    private Timestamp issuedTime;

    private long expiresIn;

    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken){
        this.refreshToken = refreshToken;
    }

    public String getClientId() {
        return clientId;
    }

    public User getAuthzUser() {
        return authzUser;
    }

    public String getUserType() {
        return userType;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes;
    }

    public String getTokenState() {
        return tokenState;
    }

    public void setTokenState(String tokenState) {
        this.tokenState = tokenState;
    }

    public Timestamp getIssuedTime() {
        return issuedTime;
    }

    public void setIssuedTime(Timestamp issuedTime){
        this.issuedTime = issuedTime;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }

    public AccessToken(String accessToken, String clientId, User authzUser, Set<String> approvedScopes,
                       String tokenState, Timestamp issuedTime, long expiresIn, String userType) {

        this.accessToken = accessToken;
        this.clientId = clientId;
        this.authzUser = authzUser;
        this.scopes = approvedScopes;
        this.tokenState = tokenState;
        this.issuedTime = issuedTime;
        this.expiresIn = expiresIn;
        this.userType = userType;
    }

    @Override
    public String toString() {
        return "AccessTokenDO{" +
                "accessToken='" + accessToken + '\'' +
                ", refreshToken='" + refreshToken + '\'' +
                ", clientId='" + clientId + '\'' +
                ", authzUser=" + authzUser +
                ", userType='" + userType + '\'' +
                ", scopes=" + scopes +
                ", tokenState='" + tokenState + '\'' +
                ", issuedTime=" + issuedTime +
                ", expiresIn=" + expiresIn +
                '}';
    }
}
