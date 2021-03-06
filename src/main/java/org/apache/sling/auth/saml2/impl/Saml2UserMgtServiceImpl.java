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

package org.apache.sling.auth.saml2.impl;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.*;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.auth.saml2.Saml2User;
import org.apache.sling.auth.saml2.Saml2UserMgtService;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.jcr.*;
import java.security.Principal;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;


@Component(service={Saml2UserMgtService.class}, immediate = true)
public class Saml2UserMgtServiceImpl implements Saml2UserMgtService {

    @Reference
    private ResourceResolverFactory resolverFactory;
    private ResourceResolver resourceResolver;
    private Session session;
    private UserManager userManager;
    private ValueFactory vf;
    private static Logger logger = LoggerFactory.getLogger(Saml2UserMgtServiceImpl.class);
    public static final String SERVICE_NAME = "Saml2UserMgtService";
    public static final String SERVICE_USER = "saml2-user-mgt";

    @Override
    public boolean setUp() {
        try {
            Map<String, Object> param = new HashMap<>();
            param.put(ResourceResolverFactory.SUBSERVICE, SERVICE_NAME);
            this.resourceResolver = resolverFactory.getServiceResourceResolver(param);
            if (Objects.isNull(this.getResourceResolver())){
                logger.error("Could not setup Saml2UserMgtService. Problem with Service User.");
                return false;
            }
            logger.info(this.resourceResolver.getUserID());
            session = this.resourceResolver.adaptTo(Session.class);
            JackrabbitSession jrSession = (JackrabbitSession) session;
            if (Objects.isNull(jrSession)){
                logger.error("Could not setup Saml2UserMgtService. JackrabbitSession was null.");
                return false;
            }
            userManager = jrSession.getUserManager();
            vf = this.session.getValueFactory();
            return true;
        } catch (LoginException e) {
            logger.error("Could not get SAML2 User Service \r\n" +
                    "Check mapping org.apache.sling.auth.saml2:{}={}", SERVICE_NAME, SERVICE_USER, e);
        } catch (RepositoryException e) {
            logger.error("RepositoryException", e);
        }
        return false;
    }

    ResourceResolver getResourceResolver(){
        return this.resourceResolver;
    }

    void setResolverFactory(ResourceResolverFactory resourceResolverFactory){
        this.resolverFactory = resourceResolverFactory;
    }

    ResourceResolverFactory getResolverFactory(){
        return this.resolverFactory;
    }

    @Override
    public void cleanUp() {
        resourceResolver.close();
        session = null;
        userManager = null;
        vf = null;
    }

    @Override
    public User getOrCreateSamlUser(Saml2User user) {
        User jackrabbitUser;
        try {
            // find and return the user if it exists
            Authorizable authorizable = userManager.getAuthorizable(user.getId());
            jackrabbitUser = (User) authorizable;
            if(jackrabbitUser != null) {
                return jackrabbitUser;
            }
            jackrabbitUser = userManager.createUser(user.getId(), null);
            session.save();
            return jackrabbitUser;
        } catch (RepositoryException e) {
            logger.error("Could not get User", e);
        }
        return null;
    }

    @Override
    public User getOrCreateSamlUser(Saml2User user, String userHome) {
        User jackrabbitUser;
        try {
            // find and return the user if it exists
            Authorizable authorizable = userManager.getAuthorizable(user.getId());
            jackrabbitUser = (User) authorizable;
            if(jackrabbitUser != null) {
                return jackrabbitUser;
            }
            // if Saml2 User Home is configured, then create a principle
            Principal principal = new SimplePrincipal(user.getId());
            jackrabbitUser = userManager.createUser(user.getId(), null, principal, userHome);
            session.save();
            return jackrabbitUser;
        } catch (RepositoryException e) {
            logger.error("Could not get User", e);
        }
        return null;
    }

    @Override
    public boolean updateGroupMembership(Saml2User user) {
        // get list of groups from assertion (see ConsumerServlet::doUserManagement)
        try {
            User jrcUser = (User) this.userManager.getAuthorizable(user.getId());
            Iterator<Authorizable> allGroups = userManager.findAuthorizables("jcr:primaryType", "rep:Group");
            // get and iterate all groups
            while (allGroups.hasNext()) {
                Group managedGroup = (Group) allGroups.next();
                // IF a group has managedProperty flag set true
                Value[] valueList = managedGroup.getProperty("managedGroup");
                if (valueList == null && user.getGroupMembership().contains(managedGroup.getID())) {
                    // IF the group does not have the managedGroup flag
                    // AND the group is in the ext users groupMembership list
                    // THEN set the managedGroup flag and add user
                    managedGroup.setProperty("managedGroup", vf.createValue(true));
                    managedGroup.addMember(jrcUser);
                } else if (valueList != null && valueList.length > 0 && valueList[0].getBoolean()) {
                    // IF the group has the managedGroup flag set
                    // AND the users list of groups (from assertion) contains this group ID
                    // THEN add the user to the managed group
                    // ELSE remove the user from the managed group
                    if (user.getGroupMembership().contains(managedGroup.getID())) {
                        managedGroup.addMember(jrcUser);
                    } else {
                        managedGroup.removeMember(jrcUser);
                    }
                }
            }
            session.save();
            return true;
        } catch (RepositoryException e) {
            logger.error("RepositoryException", e);
            return false;
        }
    }

    @Override
    public boolean updateUserProperties(Saml2User user) {
        try {
            User jcrUser = (User) this.userManager.getAuthorizable(user.getId());
            for (Map.Entry<String,String> entry : user.getUserProperties().entrySet()) {
                jcrUser.setProperty(entry.getKey(), vf.createValue(entry.getValue()));
            }
            session.save();
            return true;
        } catch (RepositoryException e) {
            logger.error("User Properties could not synchronize", e);
            return false;
        }
    }
}
