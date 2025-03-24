/*
Ory Identities API

This is the API specification for Ory Identities with features such as registration, login, recovery, account verification, profile settings, password reset, identity management, session management, email and sms delivery, and more.

API version:
Contact: office@ory.sh
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package client

import (
	"encoding/json"
	"fmt"
)

// RecoveryFlowState The experimental state represents the state of a recovery flow. This field is EXPERIMENTAL and subject to change!
type RecoveryFlowState string

// List of recoveryFlowState
const (
	RECOVERYFLOWSTATE_CHOOSE_METHOD    RecoveryFlowState = "choose_method"
	RECOVERYFLOWSTATE_SENT_EMAIL       RecoveryFlowState = "sent_email"
	RECOVERYFLOWSTATE_PASSED_CHALLENGE RecoveryFlowState = "passed_challenge"
)

// All allowed values of RecoveryFlowState enum
var AllowedRecoveryFlowStateEnumValues = []RecoveryFlowState{
	"choose_method",
	"sent_email",
	"passed_challenge",
}

func (v *RecoveryFlowState) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := RecoveryFlowState(value)
	for _, existing := range AllowedRecoveryFlowStateEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid RecoveryFlowState", value)
}

// NewRecoveryFlowStateFromValue returns a pointer to a valid RecoveryFlowState
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewRecoveryFlowStateFromValue(v string) (*RecoveryFlowState, error) {
	ev := RecoveryFlowState(v)
	if ev.IsValid() {
		return &ev, nil
	} else {
		return nil, fmt.Errorf("invalid value '%v' for RecoveryFlowState: valid values are %v", v, AllowedRecoveryFlowStateEnumValues)
	}
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v RecoveryFlowState) IsValid() bool {
	for _, existing := range AllowedRecoveryFlowStateEnumValues {
		if existing == v {
			return true
		}
	}
	return false
}

// Ptr returns reference to recoveryFlowState value
func (v RecoveryFlowState) Ptr() *RecoveryFlowState {
	return &v
}

type NullableRecoveryFlowState struct {
	value *RecoveryFlowState
	isSet bool
}

func (v NullableRecoveryFlowState) Get() *RecoveryFlowState {
	return v.value
}

func (v *NullableRecoveryFlowState) Set(val *RecoveryFlowState) {
	v.value = val
	v.isSet = true
}

func (v NullableRecoveryFlowState) IsSet() bool {
	return v.isSet
}

func (v *NullableRecoveryFlowState) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableRecoveryFlowState(val *RecoveryFlowState) *NullableRecoveryFlowState {
	return &NullableRecoveryFlowState{value: val, isSet: true}
}

func (v NullableRecoveryFlowState) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableRecoveryFlowState) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
