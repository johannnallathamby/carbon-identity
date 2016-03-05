package org.wso2.carbon.identity.application.authentication.framework.inbound;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.Serializable;
import java.nio.channels.MulticastChannel;
import java.util.HashMap;
import java.util.Map;

public class InboundAuthenticationContext<T1 extends Serializable, T2 extends Serializable> extends MessageContext
        implements Serializable {

    private static final long serialVersionUID = -2355601132733908632L;

	protected InboundAuthenticationRequest request;
    protected String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
    protected Map<T1,T2> parameters = new HashMap<>();

    public InboundAuthenticationContext(InboundAuthenticationRequest request, String tenantDomain, Map<T1,T2> parameters){
        super(parameters);
        this.request = request;
        if(StringUtils.isNotBlank(tenantDomain)) {
            this.tenantDomain = tenantDomain;
        }
    }

	public InboundAuthenticationRequest getRequest() {
		return request;
	}

	public String getTenantDomain() {
		return tenantDomain;
	}
}
