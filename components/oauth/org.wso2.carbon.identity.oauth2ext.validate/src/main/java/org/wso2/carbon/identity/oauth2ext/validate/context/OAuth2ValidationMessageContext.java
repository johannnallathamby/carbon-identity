package org.wso2.carbon.identity.oauth2ext.validate.context;

import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationResponse;
import org.wso2.carbon.identity.application.common.model.User;

import java.io.Serializable;
import java.util.Map;
import java.util.Set;

/*
 * Message context that holds information about the token validation request to the validation endpoint
 */
public class OAuth2ValidationMessageContext<T1 extends InboundAuthenticationRequest, T2 extends InboundAuthenticationResponse, T3 extends Serializable,
        T4 extends Serializable> extends OAuth2MessageContext {

    private static final long serialVersionUID = -5255523207823152460L;

    private User authzUser;

    private Set<String> approvedScopes;

    private long validityPeriod;

    private String clientId;

    public OAuth2ValidationMessageContext(T1 request, T2 response, String tenantDomain,
                                          Map<T3,T4> parameters) {
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

}
