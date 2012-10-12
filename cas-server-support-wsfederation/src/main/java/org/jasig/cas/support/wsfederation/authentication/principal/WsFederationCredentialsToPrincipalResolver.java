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
package org.jasig.cas.support.wsfederation.authentication.principal;

import org.jasig.cas.authentication.principal.AbstractPersonDirectoryCredentialsToPrincipalResolver;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.CredentialsToPrincipalResolver;
import org.jasig.cas.support.wsfederation.WsFederationConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class resolves the principal id regarding the WsFederation credentials.
 * 
 * @author John Gasper
 * @since 3.5.1
 */
public final class WsFederationCredentialsToPrincipalResolver extends AbstractPersonDirectoryCredentialsToPrincipalResolver
    implements CredentialsToPrincipalResolver {
    
    private static final Logger logger = LoggerFactory.getLogger(WsFederationCredentialsToPrincipalResolver.class);
    
    private WsFederationConfiguration configuration;
    
    @Override
    protected String extractPrincipalId(final Credentials credentials) {
   
        WsFederationCredentials wsFedCredentials = (WsFederationCredentials) credentials;
        String principalId = wsFedCredentials.getCredential().getAttributes().get(this.configuration.getIdentityAttribute()).toString();
        logger.debug("principalId : {}", principalId);
        return principalId;
    }
       
    /**
     * Return true if Credentials are WsFederationCredentials, false otherwise.
     */
    @Override
    public boolean supports(final Credentials credentials) {
        return credentials != null && (WsFederationCredentials.class.isAssignableFrom(credentials.getClass()));
    }
    
    public void setConfiguration(WsFederationConfiguration configuration) {
        this.configuration = configuration;
    }
}