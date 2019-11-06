/*
Copyright 2016 Gravitational, Inc.

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

package local

import (
	"bytes"
	"context"

	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"

	"github.com/gravitational/trace"
)

// DynamicAccessService manages dynamic RBAC
type DynamicAccessService struct {
	backend.Backend
}

// NewDynamicAccessService returns new dynamic access service instance
func NewDynamicAccessService(backend backend.Backend) *AccessService {
	return &AccessService{Backend: backend}
}

func (s *AccessService) CreateAccessRequest(req services.AccessRequest) error {
	if err := req.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	item, err := itemFromAccessRequest(req)
	if err != nil {
		return trace.Wrap(err)
	}
	if _, err := s.Create(context.TODO(), item); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (s *AccessService) SetAccessRequestState(name string, state services.RequestState) error {
	item, err := s.Get(context.TODO(), accessRequestKey(name))
	if err != nil {
		if trace.IsNotFound(err) {
			return trace.NotFound("cannot set state of access request %q (not found)", name)
		}
		return trace.Wrap(err)
	}
	req, err := itemToAccessRequest(*item)
	if err != nil {
		return trace.Wrap(err)
	}
	if err := req.SetState(state); err != nil {
		return trace.Wrap(err)
	}
	// approved requests should have a resource expiry which matches
	// the underlying access expiry.
	if state.IsApproved() {
		req.SetExpiry(req.GetAccessExpiry())
	}
	newItem, err := itemFromAccessRequest(req)
	if err != nil {
		return trace.Wrap(err)
	}
	if _, err := s.CompareAndSwap(context.TODO(), *item, newItem); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (s *AccessService) GetAccessRequest(name string) (services.AccessRequest, error) {
	item, err := s.Get(context.TODO(), accessRequestKey(name))
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.NotFound("access request %q not found", name)
		}
		return nil, trace.Wrap(err)
	}
	req, err := itemToAccessRequest(*item)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return req, nil
}

func (s *AccessService) GetAccessRequests(filter services.AccessRequestFilter) ([]services.AccessRequest, error) {
	result, err := s.GetRange(context.TODO(), backend.Key(accessRequestsPrefix), backend.RangeEnd(backend.Key(accessRequestsPrefix)), backend.NoLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var requests []services.AccessRequest
	for _, item := range result.Items {
		if !bytes.HasSuffix(item.Key, []byte(paramsPrefix)) {
			continue
		}
		req, err := itemToAccessRequest(item)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		if !filter.Match(req) {
			// TODO(fspmarshall): optimize filtering to
			// avoid full query/iteration in some cases.
			continue
		}
		requests = append(requests, req)
	}
	return requests, nil
}

func (s *AccessService) DeleteAccessRequest(name string) error {
	err := s.Delete(context.TODO(), accessRequestKey(name))
	if err != nil {
		if trace.IsNotFound(err) {
			return trace.NotFound("cannot delete access request %q (not found)", name)
		}
		return trace.Wrap(err)
	}
	return nil
}

func itemFromAccessRequest(req services.AccessRequest) (backend.Item, error) {
	value, err := services.GetAccessRequestMarshaler().MarshalAccessRequest(req)
	if err != nil {
		return backend.Item{}, trace.Wrap(err)
	}
	return backend.Item{
		Key:     accessRequestKey(req.GetName()),
		Value:   value,
		Expires: req.Expiry(),
		ID:      req.GetResourceID(),
	}, nil
}

func itemToAccessRequest(item backend.Item) (services.AccessRequest, error) {
	req, err := services.GetAccessRequestMarshaler().UnmarshalAccessRequest(
		item.Value,
		services.WithResourceID(item.ID),
		services.WithExpires(item.Expires),
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return req, nil
}

func accessRequestKey(name string) []byte {
	return backend.Key(accessRequestsPrefix, name, paramsPrefix)
}

const (
	accessRequestsPrefix = "access_requests"
)
