package org.wso2.carbon.identity.application.authentication.framework.inbound;

import org.wso2.carbon.identity.core.bean.context.MessageContext;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class InboundAuthenticationContext<T1 extends Serializable, T2 extends Serializable> extends MessageContext
        implements Serializable {

    private static final long serialVersionUID = -2355601132733908632L;

	protected InboundAuthenticationRequest request;
    protected Map<T1,T2> parameters = new HashMap<>();

    public InboundAuthenticationContext(InboundAuthenticationRequest request, Map<T1,T2> parameters){
        super(parameters);
        this.request = request;
    }

	public InboundAuthenticationRequest getRequest() {
		return request;
	}
}
