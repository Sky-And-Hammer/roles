package roles

import (
	"errors"
)

//  'PermissionMode' permission mode
type PermissionMode string

const (
	Create PermissionMode = "create"
	Read   PermissionMode = "read"
	Update PermissionMode = "update"
	Delete PermissionMode = "delete"
	CRUD   PermissionMode = "crud"
)

//	'ErrPermissionDenied' no permission error
var ErrPermissionDenied = errors.New("Permission denied")

//	'NewPermission' initialize a nwe permission for defualt role
func NewPermission() *Permission {
	return role.newPermission()
}

//	'Permission' a struct contails permission definitions
type Permission struct {
	Role         *Role
	AllowedRoles map[PermissionMode][]string
	DeniedRoles  map[PermissionMode][]string
}

func includeRoles(roles []string, values []string) bool {
	for _, role := range roles {
		if role == Anyone {
			return true
		}

		for _, value := range values {
			if value == role {
				return true
			}
		}
	}

	return false
}

//	'Concat' concat two permission into a new one
func (permission *Permission) Concat(newPermission *Permission) *Permission {
	var result = Permission{
		Role:         role,
		AllowedRoles: map[PermissionMode][]string{},
		DeniedRoles:  map[PermissionMode][]string{},
	}

	var appendRoles = func(p *Permission) {
		if p != nil {
			result.Role = p.Role
			for mode, roles := range p.DeniedRoles {
				result.DeniedRoles[mode] = append(result.DeniedRoles[mode], roles...)
			}

			for mode, roles := range p.AllowedRoles {
				result.AllowedRoles[mode] = append(result.AllowedRoles[mode], roles...)
			}
		}
	}

	appendRoles(newPermission)
	appendRoles(permission)
	return &result
}

//	'HasPermission' check roles has permission for mode or not
func (permission Permission) HasPermission(mode PermissionMode, roles ...string) bool {
	if len(permission.DeniedRoles) != 0 {
		if DeniedRoles := permission.DeniedRoles[mode]; DeniedRoles != nil {
			if includeRoles(DeniedRoles, roles) {
				return false
			}
		}
	}

	if len(permission.AllowedRoles) == 0 {
		return true
	}

	if AllowRoles := permission.AllowedRoles[mode]; AllowRoles != nil {
		if includeRoles(AllowRoles, roles) {
			return true
		}
	}

	return false
}

//	'Allow' allows permission mode for roles
func (permission *Permission) Allow(mode PermissionMode, roles ...string) *Permission {
	if mode == CRUD {
		return permission.Allow(Create, roles...).Allow(Update, roles...).Allow(Read, roles...).Allow(Delete, roles...)
	}

	if permission.AllowedRoles[mode] == nil {
		permission.AllowedRoles[mode] = []string{}
	}

	permission.AllowedRoles[mode] = append(permission.AllowedRoles[mode], roles...)

	return permission
}

//	'Deny' deny permission mode for roles
func (permission *Permission) Deny(mode PermissionMode, roles ...string) *Permission {
	if mode == CRUD {
		return permission.Deny(Create, roles...).Deny(Read, roles...).Deny(Update, roles...).Deny(Delete, roles...)
	}

	if permission.DeniedRoles[mode] == nil {
		permission.DeniedRoles[mode] = []string{}
	}

	permission.DeniedRoles[mode] = append(permission.DeniedRoles[mode], roles...)
	return permission
}
