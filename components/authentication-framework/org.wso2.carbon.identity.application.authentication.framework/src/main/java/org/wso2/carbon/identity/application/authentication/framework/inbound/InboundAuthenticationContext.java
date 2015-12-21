package org.wso2.carbon.identity.application.authentication.framework.inbound;

import org.wso2.carbon.identity.core.bean.context.MessageContext;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class InboundAuthenticationContext<T1 extends InboundAuthenticationRequest,T2 extends InboundAuthenticationResponse,
        T3 extends Serializable, T4 extends Serializable> extends MessageContext implements Serializable {

    private static final long serialVersionUID = -2355601132733908632L;

	protected T1 request;
    protected T2 response;
    protected String tenantDomain;
    protected Map<T3,T4> parameters = new HashMap<>();

    public InboundAuthenticationContext(T1 request, T2 response, String tenantDomain, Map<T3,T4> parameters){
        super(parameters);
        this.request = request;
        this.response = response;
        this.tenantDomain = tenantDomain;
    }

	public T1 getRequest() {
		return request;
	}

    public T2 getResponse() {
        return response;
    }

	public String getTenantDomain() {
		return tenantDomain;
	}

	public void setTenantDomain(String tenantDomain) {
		this.tenantDomain = tenantDomain;
	}
}
