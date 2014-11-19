import javax.jcr.query.Query
import javax.jcr.security.*
import org.apache.jackrabbit.api.security.*
import org.apache.jackrabbit.api.security.user.*
import org.apache.jackrabbit.api.security.principal.*

// ==================
// Configuration
// ==================

// true if testing script, false if changes should be saved
DRY_RUN = true

// whether the missing AD groups should be created
CREATE_MISSING_AD_GROUPS = true

// output debugging messages
DEBUG = false

// format must have either a single %s or many %1$s
// $s/%1$s will be replaced by the group ids from
// getADGroupToRoleGroupMappings()'s keys
AD_GROUP_FORMAT = "CN=%1$s,OU=Groups,DC=site,DC=com"

// ==================
// Code
// ==================
userManager = session.userManager
principalManager = session.principalManager
accessManager = session.accessControlManager
valueFactory = session.valueFactory

println "Dry Run: ${DRY_RUN}"
println "Create Missing Groups: ${CREATE_MISSING_AD_GROUPS}"
println "======================="

def roleToPermissionMappings = getRoleGroupToPermissionMappings()
def groupToRoleMappings = getADGroupToRoleGroupMappings()
def rolePrincipals = roleToPermissionMappings.keySet()
def groupIds = groupToRoleMappings.keySet()
def groupPrincipals = groupIds.collect { groupId ->
    getADPrincipalName(groupId)
}

createMissingGroups(rolePrincipals, groupIds)
removeExistingRolePermisssionMappings(rolePrincipals + groupPrincipals)
addRolePermissionMappings(roleToPermissionMappings)
removeExistingRoleMappings(roleToPermissionMappings.keySet())
addGroupToRoleMappings(groupToRoleMappings)

if (!DRY_RUN) {
    save()
}

def getADGroupToRoleGroupMappings() {
    [ 
        "CQ-Admin": [
            "administrators" // default CQ Group
        ],
        "CQ-User": [
            "contributor" // default CQ Group
        ],
        "CQ-User-Permission-Manager": [
            "contributor",
            "acl-manager",
            "user-administrators" // default CQ Group
        ],
        "CQ-Author": [
            "contributor",
            "author",
            "workflow-users", // default CQ Group
            "tag-administrator" // default CQ Group
        ],
        "CQ-Approver": [
            "contributor",
            "approver"
        ],
        "CQ-Developer": [
            "contributor",
            "author",
            "approver",
            "developer"
        ]
    ]
}

def getRoleGroupToPermissionMappings () {
    // possible permissions: [read: true, modify: true, create: true, delete: true, readAcl: true, editAcl: true, replicate: true]
    [
        'acl-manager': [
            '/': [readAcl: true, editAcl: true]
        ],
        'author': [
            '/content': [read: true, modify: true, create: true, delete: true],
            '/etc/designs': [read: true, modify: true, create: true, delete: true]
        ],
        'approver': [
            '/content': [replicate: true],
            '/etc/designs': [replicate: true]
        ],
        'developer': [
            '/apps': [read: true, modify: true, create: true, delete: true],
            '/var/classes': [read: true, delete: true],
            '/var/clientlibs': [read: true, delete: true]
        ]
    ]
}

def createMissingGroups(roleIds, groupIds) {
    if (!CREATE_MISSING_AD_GROUPS) {
        return
    }
    
    roleIds.each { roleId ->
        if (!principalManager.getPrincipal(roleId)) {
            info "Creating the missing group ${roleId}"
    
            if (!DRY_RUN) {
                group = createGroup(roleId, roleId, null)
            }
        }
    }
    
    groupIds.each { groupId ->
        def groupPrincipalName = getADPrincipalName(groupId)
        if (!principalManager.getPrincipal(groupPrincipalName)) {
            info "Creating the missing group ${groupPrincipalName}"
    
            if (!DRY_RUN) {
                group = createGroup(groupId, groupPrincipalName, "")
            }
        }
    }
}

def removeExistingRolePermisssionMappings(allGroupPrincipals) {
    def resourcesWithACL = resourceResolver
        .findResources("select * from [rep:ACL]", Query.JCR_SQL2)
        .toList().collect { resource ->
        return resource.parent
    }
    
    resourcesWithACL.each { resource ->
        def path = resource.path
        def policy = accessManager.getPolicies(path)[0]
        def entries = policy.entries.collect {it}
        def policyChanged = false
        
        entries.each { entry ->
            def principalName = entry.principal.name
            def entryType = entry.allow ? 'allow' : 'deny'
            
            if (!policy.path.startsWith("/home/groups") && allGroupPrincipals.contains(principalName)) {
                policyChanged = true
                
                info "Removing access control entry at ${policy.path} for ${entry.principal.name}: ${entryType} ${entry.privileges}"
                
                if (!DRY_RUN) {
                    policy.removeAccessControlEntry(entry)
                }
            }
        }
        
        if (policyChanged) {
            info "Saving policy update"
            
            if (!DRY_RUN) {
                accessManager.setPolicy(policy.path, policy);
            }
        }
    }
}

def addRolePermissionMappings(roleToPermissionMappings) {
    roleToPermissionMappings.each { roleName, permissionMappings ->
        debug "Adding ${permissionMappings} to ${roleName}"
        permissionMappings.each { locationPath, permissionSet ->
            def locationResource = getResource(locationPath)
            
            if (!locationResource) {
                info "Location ${locationPath} does not exist"
                return
            }
            
            def locationIsPage = locationResource.resourceType  == 'cq:Page'
            def principal = principalManager.getPrincipal(roleName)
            
            if (!principal) {
                info "Principal ${roleName} does not exist"
                return
            }
            
            def policies = accessManager.getPolicies(locationPath)
            def policy
            
            if (policies.length) {
                policy = accessManager.getPolicies(locationPath)[0]
            } else {
                policy = accessManager.getApplicablePolicies(locationPath).nextAccessControlPolicy()
            }
            
            addStandardEntry(principal, permissionSet, policy)
            
            if (locationIsPage) {
                addJcrContentEntry(principal, permissionSet, policy)
            }
            
            accessManager.setPolicy(policy.path, policy);
        }
    }
}

def addStandardEntry(principal, permissionSet, policy) {
    def privileges = []
    
    if (permissionSet.readAcl == true) {
        privileges.push(accessManager.privilegeFromName(Privilege.JCR_READ_ACCESS_CONTROL))
    }
    
    if (permissionSet.replicate == true) {
        privileges.push(accessManager.privilegeFromName('crx:replicate'))
    }
    
    if (permissionSet.read) {
        privileges.push(accessManager.privilegeFromName(Privilege.JCR_READ))
    }
    
    if (permissionSet.create) {
        privileges.push(accessManager.privilegeFromName(Privilege.JCR_ADD_CHILD_NODES))
        privileges.push(accessManager.privilegeFromName(Privilege.JCR_NODE_TYPE_MANAGEMENT))
    }
    
    if (permissionSet.modify) {
        privileges.push(accessManager.privilegeFromName(Privilege.JCR_MODIFY_PROPERTIES))
        privileges.push(accessManager.privilegeFromName(Privilege.JCR_VERSION_MANAGEMENT))
        privileges.push(accessManager.privilegeFromName(Privilege.JCR_LOCK_MANAGEMENT))
    }
    
    if (permissionSet.delete) {
        privileges.push(accessManager.privilegeFromName(Privilege.JCR_REMOVE_NODE))
        privileges.push(accessManager.privilegeFromName(Privilege.JCR_REMOVE_CHILD_NODES))
    }
    
    info "Adding access control entry to ${policy.path} for ${principal.name}: allow ${privileges}"
    
    if (!DRY_RUN) {
        policy.addEntry(principal, privileges as Privilege[], true /*, [:]*/)
    }
}

def addJcrContentEntry(principal, permissionSet, policy) {
    def jcrContentPrivileges = []
    def allow
    
    if (permissionSet.modify) {
        allow = true
        
        jcrContentPrivileges.push(accessManager.privilegeFromName(Privilege.JCR_REMOVE_NODE))
        jcrContentPrivileges.push(accessManager.privilegeFromName(Privilege.JCR_REMOVE_CHILD_NODES))
        jcrContentPrivileges.push(accessManager.privilegeFromName(Privilege.JCR_ADD_CHILD_NODES))
        jcrContentPrivileges.push(accessManager.privilegeFromName(Privilege.JCR_NODE_TYPE_MANAGEMENT))
    } else if (permissionSet.create || permissionSet.delete) {
        allow = false
        
        if (permissionSet.create) {
            jcrContentPrivileges.push(accessManager.privilegeFromName(Privilege.JCR_ADD_CHILD_NODES))
            jcrContentPrivileges.push(accessManager.privilegeFromName(Privilege.JCR_NODE_TYPE_MANAGEMENT))
        }
        
        if (permissionSet.delete) {
            jcrContentPrivileges.push(accessManager.privilegeFromName(Privilege.JCR_REMOVE_NODE))
            jcrContentPrivileges.push(accessManager.privilegeFromName(Privilege.JCR_REMOVE_CHILD_NODES))
        }
    }
    
    if (jcrContentPrivileges) {
        info "Adding access control entry to ${policy.path} for ${principal.name}: ${allow ? 'allow' : 'deny'} ${jcrContentPrivileges}"
        
        if (!DRY_RUN) {
            policy.addEntry(principal, jcrContentPrivileges as Privilege[], allow, ['rep:glob': valueFactory.createValue('*/jcr:content*')])
        }
    }
}

def removeExistingRoleMappings(roleNames) {
    roleNames.each { roleName ->
        def role = userManager.getAuthorizable(roleName);
        
        if (role) {
            debug "Role ${role.ID} found"
            
            def assignedGroups = role.getDeclaredMembers().toList()
            
            info "Removing ${assignedGroups.collect { it.ID }} from ${role.ID}"
            
            if (!DRY_RUN) {
                assignedGroups.each { assignedGroup ->
                    role.removeMember(assignedGroup)
                }
            }
        }
    }
}

def addGroupToRoleMappings(groupToRoleMappings) {
    groupToRoleMappings.each { groupId, roleNames ->
        debug "${groupId} -> ${roleNames}"
        
        def group = userManager.getAuthorizable(groupId)
        
        if (!group) {
            info "Group ${groupId} does not exist"
            return
        }
        
        if (group) {
            debug "Group '${group.ID}' found"   
            roleNames.each { roleName ->
                def role = userManager.getAuthorizable(roleName);
                
                if (role) {
                    debug "Role ${role.ID} found"
                    
                    info "Adding ${group.ID} to ${role.ID}"
                    
                    if (!DRY_RUN) {
                        role.addMember(group)
                    }
                }
            }
        } else {
            info "Group ${groupId} not found"
        }
    }
}

def debug(message) {
  if (DEBUG) {
    println "DEBUG: ${message}"
  }
}

def info(message) {
  println "INFO: ${message}"
}

def getADPrincipalName(groupId) {
    AD_GROUP_FORMAT.format(groupId)
}

def createPrincipal(groupId, principalName) {
    [
        getName: {principalName.toString()},
        getPath: {"/home/groups/${groupId}".toString()}
    ] as ItemBasedPrincipal
}

def createGroup(groupId, principalName, intermediatePath) {
    def principal = createPrincipal(groupId, principalName)
    userManager.createGroup(groupId, principal, intermediatePath)
}

"Script Complete"
