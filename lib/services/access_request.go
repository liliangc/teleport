/*
Copyright 2019 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package services

import (
	"fmt"
	"time"

	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"

	"github.com/jonboulle/clockwork"
	"github.com/pborman/uuid"
)

// RequestIDs is a collection of IDs for privelege escalation requests.
type RequestIDs struct {
	AccessRequests []string `json:"access_requests,omitempty"`
}

func (r *RequestIDs) Marshal() ([]byte, error) {
	data, err := utils.FastMarshal(r)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return data, nil
}

func (r *RequestIDs) Unmarshal(data []byte) error {
	if err := utils.FastUnmarshal(data, r); err != nil {
		return trace.Wrap(err)
	}
	return trace.Wrap(r.Check())
}

func (r *RequestIDs) Check() error {
	for _, id := range r.AccessRequests {
		if uuid.Parse(id) == nil {
			return trace.BadParameter("invalid request id %q", id)
		}
	}
	return nil
}

func (r *RequestIDs) IsEmpty() bool {
	return len(r.AccessRequests) < 1
}

// Match checks if a given access request matches this filter.
func (f *AccessRequestFilter) Match(req AccessRequest) bool {
	if f.ID != "" && req.GetName() != f.ID {
		return false
	}
	if f.User != "" && req.GetUser() != f.User {
		return false
	}
	return true
}

// DynamicAccess is a service which manages dynamic RBAC.
type DynamicAccess interface {
	// CreateAccessRequest stores a new access request.
	CreateAccessRequest(AccessRequest) error
	// SetAccessRequestState updates the state of an existing access request.
	SetAccessRequestState(reqID string, state RequestState) error
	// GetAccessRequest gets an access request by name (uuid).
	GetAccessRequest(string) (AccessRequest, error)
	// GetAccessRequests gets all currently active access requests.
	GetAccessRequests(AccessRequestFilter) ([]AccessRequest, error)
	// DeleteAccessRequest deletes an access request.
	DeleteAccessRequest(string) error
}

// AccessRequest is a request for temporarily granted roles
type AccessRequest interface {
	Resource
	// GetUser gets the name of the requesting user
	GetUser() string
	// GetRoles gets the roles being requested by the user
	GetRoles() []string
	// GetState gets the current state of the request
	GetState() RequestState
	// SetState sets the approval state of the request
	SetState(RequestState) error
	// GetCreationTime gets the time at which the request was
	// originally registered with the auth server.
	GetCreationTime() time.Time
	// SetCreationTime sets the creation time of the request.
	SetCreationTime(time.Time)
	// GetAccessExpiry gets the upper limit for which this request
	// may be considered active.
	GetAccessExpiry() time.Time
	// SetAccessExpiry sets the upper limit for which this request
	// may be considered active.
	SetAccessExpiry(time.Time)
	// CheckAndSetDefaults validates the access request and
	// supplies default values where appropriate.
	CheckAndSetDefaults() error
	// Equals checks equality between access request values.
	Equals(AccessRequest) bool
}

func (s RequestState) IsPending() bool {
	return s == RequestState_PENDING
}

func (s RequestState) IsApproved() bool {
	return s == RequestState_APPROVED
}

func (s RequestState) IsDenied() bool {
	return s == RequestState_DENIED
}

// NewAccessRequest assembled an AccessReqeust resource.
func NewAccessRequest(user string, roles ...string) (AccessRequest, error) {
	req := AccessRequestV1{
		Kind:    KindAccessRequest,
		Version: V3,
		Metadata: Metadata{
			Name: uuid.New(),
		},
		Spec: AccessRequestSpecV1{
			User:  user,
			Roles: roles,
			State: RequestState_PENDING,
		},
	}
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &req, nil
}

func (r *AccessRequestV1) GetUser() string {
	return r.Spec.User
}

func (r *AccessRequestV1) GetRoles() []string {
	return r.Spec.Roles
}

func (r *AccessRequestV1) GetState() RequestState {
	return r.Spec.State
}

func (r *AccessRequestV1) SetState(state RequestState) error {
	if r.Spec.State.IsDenied() {
		if state.IsDenied() {
			return nil
		}
		return trace.BadParameter("cannot set request-state %q (already denied)", state.String())
	}
	r.Spec.State = state
	return nil
}

func (r *AccessRequestV1) GetCreationTime() time.Time {
	return r.Spec.Created
}

func (r *AccessRequestV1) SetCreationTime(t time.Time) {
	r.Spec.Created = t
}

func (r *AccessRequestV1) GetAccessExpiry() time.Time {
	return r.Spec.Expires
}

func (r *AccessRequestV1) SetAccessExpiry(expiry time.Time) {
	r.Spec.Expires = expiry
}

func (r *AccessRequestV1) CheckAndSetDefaults() error {
	if err := r.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if err := r.Check(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (r *AccessRequestV1) Check() error {
	if r.Kind == "" {
		return trace.BadParameter("access request kind not set")
	}
	if r.Version == "" {
		return trace.BadParameter("access request version not set")
	}
	if r.GetName() == "" {
		return trace.BadParameter("access request id not set")
	}
	if uuid.Parse(r.GetName()) == nil {
		return trace.BadParameter("invalid access request id %q", r.GetName())
	}
	if r.GetUser() == "" {
		return trace.BadParameter("access request user name not set")
	}
	if len(r.GetRoles()) < 1 {
		return trace.BadParameter("access request does not specify any roles")
	}
	return nil
}

func (r *AccessRequestV1) Equals(other AccessRequest) bool {
	o, ok := other.(*AccessRequestV1)
	if !ok {
		return false
	}
	if r.GetName() != o.GetName() {
		return false
	}
	return r.Spec.Equals(&o.Spec)
}

func (s *AccessRequestSpecV1) Equals(other *AccessRequestSpecV1) bool {
	if s.User != other.User {
		return false
	}
	if len(s.Roles) != len(other.Roles) {
		return false
	}
	for i, role := range s.Roles {
		if role != other.Roles[i] {
			return false
		}
	}
	if s.Created != other.Created {
		return false
	}
	if s.Expires != other.Expires {
		return false
	}
	return s.State == other.State
}

// --------------------------------------------------------------------

type AccessRequestMarshaler interface {
	MarshalAccessRequest(req AccessRequest, opts ...MarshalOption) ([]byte, error)
	UnmarshalAccessRequest(bytes []byte, opts ...MarshalOption) (AccessRequest, error)
}

type accessRequestMarshaler struct{}

func (r *accessRequestMarshaler) MarshalAccessRequest(req AccessRequest, opts ...MarshalOption) ([]byte, error) {
	cfg, err := collectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch r := req.(type) {
	case *AccessRequestV1:
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			cp := *r
			cp.SetResourceID(0)
			r = &cp
		}
		return utils.FastMarshal(r)
	default:
		return nil, trace.BadParameter("unrecognized access request type: %T", req)
	}
}

func (r *accessRequestMarshaler) UnmarshalAccessRequest(data []byte, opts ...MarshalOption) (AccessRequest, error) {
	cfg, err := collectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var req AccessRequestV1
	if cfg.SkipValidation {
		if err := utils.FastUnmarshal(data, &req); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		if err := utils.UnmarshalWithSchema(GetAccessRequestSchema(), &req, data); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	if cfg.ID != 0 {
		req.SetResourceID(cfg.ID)
	}
	if !cfg.Expires.IsZero() {
		req.SetExpiry(cfg.Expires)
	}
	return &req, nil
}

var accessRequestMarshalerInstance AccessRequestMarshaler = &accessRequestMarshaler{}

func GetAccessRequestMarshaler() AccessRequestMarshaler {
	marshalerMutex.Lock()
	defer marshalerMutex.Unlock()
	return accessRequestMarshalerInstance
}

const AccessRequestSpecSchema = `{
	"type": "object",
	"additionalProperties": false,
	"properties": {
		"user": { "type": "string" },
		"roles": {
			"type": "array",
			"items": { "type": "string" }
		},
		"state": { "type": "integer" },
		"created": { "type": "string" },
		"expires": { "type": "string" }
	}
}`

func GetAccessRequestSchema() string {
	return fmt.Sprintf(V2SchemaTemplate, MetadataSchema, AccessRequestSpecSchema, DefaultDefinitions)
}

// --------------------------------------------------------------------

func (r *AccessRequestV1) GetKind() string {
	return r.Kind
}

func (r *AccessRequestV1) GetSubKind() string {
	return r.SubKind
}

func (r *AccessRequestV1) SetSubKind(subKind string) {
	r.SubKind = subKind
}

func (r *AccessRequestV1) GetVersion() string {
	return r.Version
}

func (r *AccessRequestV1) GetName() string {
	return r.Metadata.Name
}

func (r *AccessRequestV1) SetName(name string) {
	r.Metadata.Name = name
}

func (r *AccessRequestV1) Expiry() time.Time {
	return r.Metadata.Expiry()
}

func (r *AccessRequestV1) SetExpiry(expiry time.Time) {
	r.Metadata.SetExpiry(expiry)
}

func (r *AccessRequestV1) SetTTL(clock clockwork.Clock, ttl time.Duration) {
	r.Metadata.SetTTL(clock, ttl)
}

func (r *AccessRequestV1) GetMetadata() Metadata {
	return r.Metadata
}

func (r *AccessRequestV1) GetResourceID() int64 {
	return r.Metadata.GetID()
}

func (r *AccessRequestV1) SetResourceID(id int64) {
	r.Metadata.SetID(id)
}

func (r *AccessRequestV1) String() string {
	return fmt.Sprintf("AccessRequest(user=%v,roles=%+v)", r.Spec.User, r.Spec.Roles)
}
