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
package org.jasig.cas.support.wsfederation;

import java.util.ArrayList;
import java.util.List;
import javax.validation.constraints.NotNull;
import org.opensaml.xml.security.x509.BasicX509Credential;

/**
 * This class gathers configuration information for the WS Federation Identity Provider.
 * 
 * @author John Gasper
 * @since 3.5.1
 */
public final class WsFederationConfiguration {
    @NotNull
    private String identityProviderUrl,
                   identityProviderIdentifier;

    @NotNull 
    private List<String> signingCertificateFiles;
    
    @NotNull
    private String relyingPartyIdentifier;
    
    @NotNull
    private String identityAttribute;
    
    private int tolerance = 10000;

    private static List<BasicX509Credential> wallet;
    
    private WsFederationAttributeMutator attributeMutator;

    public String getIdentityProviderUrl() {
        return this.identityProviderUrl;
    }
    public void setIdentityProviderUrl(final String identityProviderUrl) {
        this.identityProviderUrl = identityProviderUrl;
    }

    public String getIdentityProviderIdentifier() {
        return identityProviderIdentifier;
    }
    public void setIdentityProviderIdentifier(String identityProviderIdentifier) {
        this.identityProviderIdentifier = identityProviderIdentifier;
    }
    
    public String getRelyingPartyIdentifier() {
        return this.relyingPartyIdentifier;
    }
    public void setRelyingPartyIdentifier(final String relyingPartyIdentifier) {
        this.relyingPartyIdentifier = relyingPartyIdentifier;
    }
    
    public List<String> getSigningCertificateFiles() {
        return this.signingCertificateFiles;
    }
    public void setSigningCertificateFiles(final List<String> signingCertificateFiles) {
        this.signingCertificateFiles = signingCertificateFiles;
        
         List<BasicX509Credential> signingCerts = new ArrayList<BasicX509Credential>();
            
            for (String file : signingCertificateFiles) {
                signingCerts.add(WsFederationUtils.getSigningCredential(file));
            }
            
            this.wallet = signingCerts;
    }
    public List<BasicX509Credential> getSigningCertificates() {
        return this.wallet;
    }
    
    public String getIdentityAttribute() {
        return this.identityAttribute;
    }
    public void setIdentityAttribute(final String identityAttribute) {
        this.identityAttribute = identityAttribute;
    }

    public int getTolerance() {
        return tolerance;
    }
    public void setTolerance(int tolerance) {
        this.tolerance = tolerance;
    }

    public WsFederationAttributeMutator getAttributeMutator() {
        return attributeMutator;
    }

    public void setAttributeMutator(WsFederationAttributeMutator attributeMutator) {
        this.attributeMutator = attributeMutator;
    }

}