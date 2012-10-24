/*
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.jasig.cas.support.wsfederation.web.flow;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.validation.constraints.NotNull;
import org.apache.commons.lang.StringUtils;
import org.jasig.cas.CentralAuthenticationService;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.support.wsfederation.WsFederationConfiguration;
import org.jasig.cas.support.wsfederation.WsFederationConstants;
import org.jasig.cas.support.wsfederation.WsFederationUtils;
import org.jasig.cas.support.wsfederation.authentication.principal.WsFederationCredential;
import org.jasig.cas.support.wsfederation.authentication.principal.WsFederationCredentials;
import org.jasig.cas.ticket.TicketException;
import org.jasig.cas.web.support.WebUtils;
import org.opensaml.saml1.core.impl.AssertionImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * This class represents an action in the webflow to retrieve WsFederation information on the callback url which is the webflow url (/login). The
 * 
 * @author John Gasper
 * @since 3.5.1
 */
public final class WsFederationAction extends AbstractAction {
    
    private static final Logger logger = LoggerFactory.getLogger(WsFederationAction.class);
    
    @NotNull
    private WsFederationConfiguration configuration;
    
    @NotNull
    private CentralAuthenticationService centralAuthenticationService;
    
    @Override
    protected Event doExecute(final RequestContext context) throws Exception {
        final HttpServletRequest request = WebUtils.getHttpServletRequest(context);
        final HttpSession session = request.getSession();
        
        String wresult = request.getParameter(WsFederationConstants.WRESULT);
        logger.debug("wresult : {}", wresult);
        
        // it's an authentication
        if ( StringUtils.isNotBlank(wresult) ) {
                    
            // create credentials
            AssertionImpl assertion = WsFederationUtils.parseTokenString(wresult);
            
            //Validate the signature
            if ( assertion != null && WsFederationUtils.validateSignature(assertion, configuration.getSigningCertificates()) ) {
                final WsFederationCredential credential = WsFederationUtils.createCredentialFromToken(assertion);
                
                final Credentials credentials;
                if ( credential != null 
                        && credential.isValid(configuration.getRelyingPartyIdentifier(), 
                                               configuration.getIdentityProviderIdentifier(),
                                               configuration.getTolerance()) ) {
                    credentials = new WsFederationCredentials(credential);
                } else {
                    logger.equals("Saml assertions are blank or no longer valid.");
                    return error();
                }
                        
                // retrieve parameters from web session
                final Service service = (Service) session.getAttribute(WsFederationConstants.SERVICE);
                context.getFlowScope().put(WsFederationConstants.SERVICE, service);
                restoreRequestAttribute(request, session, WsFederationConstants.THEME);
                restoreRequestAttribute(request, session, WsFederationConstants.LOCALE);
                restoreRequestAttribute(request, session, WsFederationConstants.METHOD);

                try {
                    WebUtils.putTicketGrantingTicketInRequestScope(context, this.centralAuthenticationService
                        .createTicketGrantingTicket(credentials));
                    return success();
                } catch (final TicketException e) {
                    logger.error(e.getMessage());
                    return error();
                }
            }
            else {
                logger.error("WS Requested Security Token is blank or the signature is not valid. ");
                return error();
            }
            
        } else { // no authentication : go to login page
            
            // save parameters in web session
            final Service service = (Service) context.getFlowScope().get(WsFederationConstants.SERVICE);
            if ( service != null ) {
                session.setAttribute(WsFederationConstants.SERVICE, service);
            }
            saveRequestParameter(request, session, WsFederationConstants.THEME);
            saveRequestParameter(request, session, WsFederationConstants.LOCALE);
            saveRequestParameter(request, session, WsFederationConstants.METHOD);
            
            final String key = WsFederationConstants.PROPERTYURL;
            String authorizationUrl = null;
            authorizationUrl = this.configuration.getIdentityProviderUrl() +
                               WsFederationConstants.QUERYSTRING +
                                this.configuration.getRelyingPartyIdentifier();

            logger.debug("{} -> {}", key, authorizationUrl);
            context.getFlowScope().put(key, authorizationUrl);
        }     

        return error();
    }
    
    /**
     * Restore an attribute in web session as an attribute in request.
     * 
     * @param request
     * @param session
     * @param name
     */
    private void restoreRequestAttribute(final HttpServletRequest request, final HttpSession session, final String name) {
        final String value = (String) session.getAttribute(name);
        request.setAttribute(name, value);
    }
    
    /**
     * Save a request parameter in the web session.
     * 
     * @param request
     * @param session
     * @param name
     */
    private void saveRequestParameter(final HttpServletRequest request, final HttpSession session, final String name) {
        final String value = request.getParameter(name);
        if ( value != null ) {
            session.setAttribute(name, value);
        }
    }
    
    public void setCentralAuthenticationService(final CentralAuthenticationService centralAuthenticationService) {
        this.centralAuthenticationService = centralAuthenticationService;
    }
      
    public void setConfiguration(final WsFederationConfiguration configuration) {
        this.configuration = configuration;
    }
}