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
package org.jasig.cas.support.wsfederation.authentication;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.AuthenticationMetaDataPopulator;
import org.jasig.cas.authentication.MutableAuthentication;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.SimplePrincipal;
import org.jasig.cas.support.wsfederation.authentication.principal.WsFederationCredentials;

/**
 * This class is a metadata populator for WsFederation authentication. The attributes returned 
 * in the Security Token are added to returned principal. 
 * 
 * @author John Gasper
 * @since 3.5.1
 */
public final class WsFederationAuthenticationMetaDataPopulator implements AuthenticationMetaDataPopulator {
    
    @Override
    public Authentication populateAttributes(final Authentication authentication, final Credentials credentials) {
        if (credentials instanceof WsFederationCredentials) {
            WsFederationCredentials wsfedCredentials = (WsFederationCredentials) credentials;
            final Principal simplePrincipal = new SimplePrincipal(authentication.getPrincipal().getId(),
                                                                  wsfedCredentials.getCredential().getAttributes());
            final MutableAuthentication mutableAuthentication = new MutableAuthentication(simplePrincipal,
                                                                                          authentication.getAuthenticatedDate());
            mutableAuthentication.getAttributes().putAll(authentication.getAttributes());
            
            return mutableAuthentication;
        }
        return authentication;
    }
}