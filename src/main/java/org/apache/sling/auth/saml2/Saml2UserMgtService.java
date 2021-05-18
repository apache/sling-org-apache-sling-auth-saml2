/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package org.apache.sling.auth.saml2;

import org.apache.jackrabbit.api.security.user.User;

public interface Saml2UserMgtService {

    /**
     * Call setUp before using any other Saml2UserMgtService method
     * Setup initializes service resolver and called before each use
     * @return returns true if setup is successful
     */
    boolean setUp();

    /**
     * getOrCreateSamlUser(Saml2User user) will be called if userHome is not configured
     * @param user creates the JCR user in the default /home location
     * @return returns the existing or new JCR user
     */
    User getOrCreateSamlUser(Saml2User user);
    
    /**
     * getOrCreateSamlUser(Saml2User user) will be called if userHome is configured
     * @param user gets or creates the JCR user in supplied userHome path
     * @param userHome is the supplied path under which to find or create the user
     * @return returns the existing or new JCR user
     */
    User getOrCreateSamlUser(Saml2User user, String userHome);
    
    /**
     * Users group membership will be updated based on the groups contained in the 
     * configured element of the SAML Assertion
     * @param user to update membership
     * @return returns true if the user's group membership was updated
     */
    boolean updateGroupMembership(Saml2User user);

    /**
     * Users properties will be updated based on user properties contained in the 
     * configured properties of the SAML Assertion
     * @param user to update properties
     * @return returns true if the user properties were updated 
     */
    boolean updateUserProperties(Saml2User user);
    
    /**
     * Call cleanUp after using Saml2UserMgtService methods
     * This should be called after using the service to close out the service resolver
     */
    void cleanUp();
}
