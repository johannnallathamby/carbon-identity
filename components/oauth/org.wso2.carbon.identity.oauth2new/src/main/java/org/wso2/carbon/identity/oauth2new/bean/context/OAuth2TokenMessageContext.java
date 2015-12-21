package org.wso2.carbon.identity.oauth2new.bean.context;

import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2AuthzRequest;
import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2Request;
import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2TokenRequest;
import org.wso2.carbon.identity.oauth2new.bean.message.response.OAuth2AuthzResponse;
import org.wso2.carbon.identity.oauth2new.bean.message.response.OAuth2Response;
import org.wso2.carbon.identity.oauth2new.bean.message.response.OAuth2TokenResponse;

import java.io.Serializable;
import java.util.Map;
import java.util.Set;

/*
 * Message context that holds information about the token request to the token endpoint
 */
public class OAuth2TokenMessageContext extends OAuth2MessageContext {

    private static final long serialVersionUID = -4217491299787490535L;

    private User authzUser;

    private Set<String> approvedScopes;

    private long validityPeriod;

    private String clientId;

    public OAuth2TokenMessageContext(OAuth2TokenRequest request, OAuth2TokenResponse response, String tenantDomain,
                                     Map<String, String> parameters) {
        super(request, response, tenantDomain, parameters);
    }

    public Set<String> getApprovedScopes() {
        return approvedScopes;
    }

    public void setApprovedScopes(Set<String> approvedScopes) {
        this.approvedScopes = approvedScopes;
    }

    public long getValidityPeriod() {
        return validityPeriod;
    }

    public void setValidityPeriod(long validityPeriod) {
        this.validityPeriod = validityPeriod;
    }

    public User getAuthzUser() {
        return authzUser;
    }

    public void setAuthzUser(User authzUser) {
        this.authzUser = authzUser;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public OAuth2TokenRequest getRequest(){
        return (OAuth2TokenRequest)request;
    }

    public OAuth2TokenResponse getResponse(){
        return (OAuth2TokenResponse)response;
    }

}
