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
package org.jasig.cas.support.wsfederation.authentication.handler.support;

import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.support.wsfederation.authentication.principal.WsFederationCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This handler authenticates Security token/credentials
 * 
 * @author John Gasper
 * @since 3.5.1
 */
public final class WsFederationAuthenticationHandler extends AbstractPreAndPostProcessingAuthenticationHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(WsFederationAuthenticationHandler.class);
    
    @Override
    public boolean supports(final Credentials credentials) {
        return credentials != null && (WsFederationCredentials.class.isAssignableFrom(credentials.getClass()));
    }
    
    @Override
    protected boolean doAuthentication(final Credentials credentials) throws AuthenticationException {
        final WsFederationCredentials wsFederationCredentials = (WsFederationCredentials) credentials;
        
        if (wsFederationCredentials.getCredential() != null ) {
            return true;
        } else {
            return false;
        }
    }
}