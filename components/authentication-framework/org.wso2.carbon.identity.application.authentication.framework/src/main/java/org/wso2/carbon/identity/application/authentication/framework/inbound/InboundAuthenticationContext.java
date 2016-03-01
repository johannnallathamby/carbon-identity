package org.wso2.carbon.identity.application.authentication.framework.inbound;

import org.wso2.carbon.identity.core.bean.context.MessageContext;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class InboundAuthenticationContext<T1 extends Serializable, T2 extends Serializable> extends MessageContext
        implements Serializable {

    private static final long serialVersionUID = -2355601132733908632L;

	protected InboundAuthenticationRequest request;
    protected InboundAuthenticationResponse response;
    protected String tenantDomain;
    protected Map<T1,T2> parameters = new HashMap<>();

    public InboundAuthenticationContext(InboundAuthenticationRequest request, InboundAuthenticationResponse response,
                                        String tenantDomain, Map<T1,T2> parameters){
        super(parameters);
        this.request = request;
        this.response = response;
        this.tenantDomain = tenantDomain;
    }

	public InboundAuthenticationRequest getRequest() {
		return request;
	}

    public InboundAuthenticationResponse getResponse() {
        return response;
    }

	public String getTenantDomain() {
		return tenantDomain;
	}

	public void setTenantDomain(String tenantDomain) {
		this.tenantDomain = tenantDomain;
	}
}
