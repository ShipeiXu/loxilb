/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package handler

import (
	"strings"

	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

func ConfigPostDNSPolicy(params operations.PostConfigDnspolicyParams, principal interface{}) middleware.Responder {
	policy := &cmn.DnsPolicyMod{}
	policy.Rule.Domain = *params.Attr.Domain
	switch *params.Attr.Action {
	case models.DNSPolicyEntryActionAllow:
		policy.Opts.Allow = true
	case models.DNSPolicyEntryActionDrop:
		policy.Opts.Drop = true
	case models.DNSPolicyEntryActionTrap:
		policy.Opts.Trap = true
	}

	_, err := ApiHooks.NetDnsPolicyAdd(policy)
	if err == nil {
		return operations.NewPostConfigDnspolicyNoContent()
	}
	payload := &models.Error{Message: err.Error()}
	if strings.Contains(err.Error(), "exists") {
		return operations.NewPostConfigDnspolicyConflict().WithPayload(payload)
	}
	return operations.NewPostConfigDnspolicyBadRequest().WithPayload(payload)
}

func ConfigDeleteDNSPolicy(params operations.DeleteConfigDnspolicyParams, principal interface{}) middleware.Responder {
	policy := &cmn.DnsPolicyMod{Rule: cmn.DnsPolicyArg{Domain: params.Domain}}
	_, err := ApiHooks.NetDnsPolicyDel(policy)
	if err == nil {
		return operations.NewDeleteConfigDnspolicyNoContent()
	}
	payload := &models.Error{Message: err.Error()}
	if strings.Contains(err.Error(), "no-rule") {
		return operations.NewDeleteConfigDnspolicyNotFound().WithPayload(payload)
	}
	return operations.NewDeleteConfigDnspolicyBadRequest().WithPayload(payload)
}

func ConfigGetDNSPolicy(params operations.GetConfigDnspolicyAllParams, principal interface{}) middleware.Responder {
	policies, err := ApiHooks.NetDnsPolicyGet()
	if err != nil {
		return operations.NewGetConfigDnspolicyAllInternalServerError().WithPayload(&models.Error{Message: err.Error()})
	}

	result := make([]*models.DNSPolicyEntry, 0, len(policies))
	for _, policy := range policies {
		action := models.DNSPolicyEntryActionDrop
		if policy.Opts.Allow {
			action = models.DNSPolicyEntryActionAllow
		} else if policy.Opts.Trap {
			action = models.DNSPolicyEntryActionTrap
		}
		domain := policy.Rule.Domain
		result = append(result, &models.DNSPolicyEntry{
			Action:  &action,
			Counter: policy.Opts.Counter,
			Domain:  &domain,
		})
	}

	body := &operations.GetConfigDnspolicyAllOKBody{DNSPolicyAttr: result}
	return operations.NewGetConfigDnspolicyAllOK().WithPayload(body)
}
