package edu.internet2.middleware.shibboleth.idp.profile.saml2;

import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.provider.BasicAttribute;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandlerManager;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.Saml2LoginContext;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.util.DatatypeHelper;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * Servlet Filter acting as an integration point between IDP processing pipeline and external flow
 * to facilitate post login actions such as additional authorization based on IDP attributes,
 * attributes release consent, etc.
 * <p/>
 * <p>This filter checks if the authentication step has been performed by IDP already, and if so,
 * packages necessary data for the post login flow into the HttpServletRequest and forwards this
 * request to the post login endpoint running in the separate ServletContext. At this point
 * the IDP flow is interupted until post login flow finishes its processing and either halts the entire process
 * or redirects back to IDP signalling that all went well by setting an attribute in IDP's ServletContext
 * keyed by the current IDP HttpSession ID. At this point this filter will be invoked again and it will
 * check this signal attribute and if present, will forward the request down the IDP's chain for normal processing.</p>
 * <p/>
 * <p>Note that this filter has no knowledge of the post login's endpoint implementation details, which facilitates
 * the loose-coupling of the two and enables the two components to be evolved independently</p>
 *
 * @author Dmitriy Kopylenko
 */
public class PostLoginFlowFilter implements Filter {

    ServletContext servletContext;

    ProfileHandlerManager profileHandlerManager;

    public void init(FilterConfig config) throws ServletException {
        this.servletContext = config.getServletContext();
        String handlerManagerId = config.getInitParameter("handlerManagerId");
        if (DatatypeHelper.isEmpty(handlerManagerId)) {
            handlerManagerId = "shibboleth.HandlerManager";
        }
        this.profileHandlerManager = (ProfileHandlerManager) servletContext.getAttribute(handlerManagerId);
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        //Ensure thread safety for the atomic operation on the ServletContext and visibility from SWF update
        //which synchronizes on the same ServletContext monitor
        synchronized (this.servletContext) {
            String swfCheckStatus = (String) this.servletContext.getAttribute(req.getSession().getId());
            if (swfCheckStatus != null) {
                if (swfCheckStatus.equals("POST_LOGIN_FLOW_CONTINUE")) {
                    this.servletContext.removeAttribute(req.getSession().getId());
                    filterChain.doFilter(request, response);
                    return;
                } else {
                    this.servletContext.removeAttribute(req.getSession().getId());
                    throw new IllegalStateException("The postlogin flow is broken either on purpose or accidently. Start over!");
                }
            }
        }
        LoginContext loginContext = HttpServletHelper.getLoginContext(HttpServletHelper.getStorageService(servletContext), servletContext, req);
        if (loginContext != null && loginContext.isPrincipalAuthenticated()) {
            SSOProfileHandler.SSORequestContext ssoRequestContext = buildSsoRequestContext(req, resp, (Saml2LoginContext) loginContext);
            Map<String, Object>[] data = marshallAttributes(req, loginContext, ssoRequestContext);
            req.setAttribute("relyingParty", data[0]);
            req.setAttribute("user", data[1]);
            req.setAttribute("idp", data[2]);
            //Forward the request with all the necessary data to the post login flow deployed in the 'plf' ServletContext
            this.servletContext.getContext("/plf").getRequestDispatcher("/postlogin").forward(req, resp);
            return;
        }
        filterChain.doFilter(request, response);
        req.toString();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object>[] marshallAttributes(HttpServletRequest request, LoginContext loginContext, SSOProfileHandler.SSORequestContext ssoRequestContext) {
        Map<String, Object> relyingParty = new HashMap<String, Object>();
        Map<String, Object> user = new HashMap<String, Object>();
        Map<String, Object> idp = new HashMap<String, Object>();
        idp.put("returnUrl", request.getRequestURL().toString());
        idp.put("callingContextName", "/idp");
        idp.put("callingSessionId", request.getSession().getId());
        relyingParty.put("id", loginContext.getRelyingPartyId());
        user.put("name", loginContext.getPrincipalName());
        Map<String, BaseAttribute> idpAtributes = ssoRequestContext.getAttributes();
        Map<String, Collection<String>> attributes = new HashMap<String, Collection<String>>();
        for (Map.Entry<String, BaseAttribute> entry : idpAtributes.entrySet()) {
            attributes.put(entry.getKey(), entry.getValue().getValues());
        }
        user.put("attributes", attributes);
        return new Map[]{relyingParty, user, idp};
    }

    private SSOProfileHandler.SSORequestContext buildSsoRequestContext(HttpServletRequest req, HttpServletResponse resp, Saml2LoginContext loginContext) throws ServletException {
        SSOProfileHandler.SSORequestContext ssoRequestContext = null;
        SSOProfileHandler ssoProfileHandler = (SSOProfileHandler) this.profileHandlerManager.getProfileHandler(req);
        try {
            ssoRequestContext = ssoProfileHandler.buildRequestContext(loginContext, new HttpServletRequestAdapter(req), new HttpServletResponseAdapter(resp, true));
            ssoProfileHandler.resolveAttributes(ssoRequestContext);
        } catch (ProfileException ex) {
            throw new ServletException(ex);
        }
        return ssoRequestContext;
    }

    public void destroy() {
        //NOOP
    }
}
