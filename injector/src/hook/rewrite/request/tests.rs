use super::*;
use crate::hook::rewrite::tests::*;
use crate::{
    android::system::keystore2::Domain::Domain,
    android::system::keystore2::IKeystoreService::transactions as service_tx,
    android::system::keystore2::KeyDescriptor::KeyDescriptor,
};
use rsbinder::{Status, StatusCode};
use std::mem::size_of;

#[test]
fn native_system_callers_use_the_configured_android_package_block() {
    let cfg = config::InjectorConfig::default();
    for (uid, sid) in [(0, "u:r:vold:s0"), (1000, "u:r:system_server:s0")] {
        let caller = CallerInfo { uid, sid: sid.to_string(), pid: 1458 };
        let decision = evaluate_caller(&caller, &cfg);
        assert!(!decision.allowed);
        assert_eq!(decision.reason, FilterReason::RejectedAndroidPackage);
    }
}

#[test]
fn omk_grant_blocker_preserves_inbound_binder_buffer() {
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.code = service_tx::r#grant;
    tr.data_size = 64;
    tr.offsets_size = size_of::<usize>();
    tr.data.ptr.buffer = 0x1000;
    tr.data.ptr.offsets = 0x2000;

    block_system_request(&mut tr);

    assert_eq!(tr.code, u32::MAX);
    assert_eq!(tr.data_size, 64);
    assert_eq!(tr.offsets_size, size_of::<usize>());
    assert_eq!(unsafe { tr.data.ptr.buffer }, 0x1000);
    assert_eq!(unsafe { tr.data.ptr.offsets }, 0x2000);
}

#[test]
fn namespace_boundary_applies_to_all_service_key_and_listing_methods() {
    for domain in
        [Domain::APP, Domain::KEY_ID, Domain::GRANT, Domain::SELINUX, Domain::BLOB, Domain(99)]
    {
        for mut request in sample_service_requests() {
            let has_namespace = match &mut request {
                ParsedServiceRequest::GetKeyEntry { key }
                | ParsedServiceRequest::UpdateSubcomponent { key, .. }
                | ParsedServiceRequest::DeleteKey { key }
                | ParsedServiceRequest::Grant { key, .. }
                | ParsedServiceRequest::Ungrant { key, .. } => {
                    key.domain = domain;
                    true
                }
                ParsedServiceRequest::ListEntries { domain: target, .. }
                | ParsedServiceRequest::GetNumberOfEntries { domain: target, .. }
                | ParsedServiceRequest::ListEntriesBatched { domain: target, .. } => {
                    *target = domain;
                    true
                }
                _ => false,
            };
            let expected = if has_namespace && matches!(domain, Domain::SELINUX | Domain::BLOB) {
                RouteTarget::System
            } else {
                RouteTarget::Omk
            };
            assert_eq!(
                route_for_service_request(&request, true, &config::InterceptConfig::default()),
                expected,
                "method={:?} domain={domain:?}",
                request.method()
            );
            assert_eq!(
                route_for_service_request(&request, true, &disabled_intercept_config()),
                RouteTarget::System
            );
        }
    }
}

#[test]
fn security_level_scope_uses_primary_namespace_and_keeps_secondary_descriptors_unchanged() {
    for domain in
        [Domain::APP, Domain::KEY_ID, Domain::GRANT, Domain::SELINUX, Domain::BLOB, Domain(99)]
    {
        let key = KeyDescriptor { domain, ..sample_key_descriptor() };
        let external = KeyDescriptor { domain: Domain::SELINUX, ..sample_key_descriptor() };
        let requests = [
            ParsedSecurityLevelRequest::CreateOperation {
                key: key.clone(),
                operation_parameters: vec![],
                forced: false,
            },
            ParsedSecurityLevelRequest::GenerateKey {
                key: key.clone(),
                attestation_key: Some(external.clone()),
                params: vec![],
                flags: 123,
                entropy: vec![],
            },
            ParsedSecurityLevelRequest::ImportKey {
                key: key.clone(),
                attestation_key: Some(external.clone()),
                params: vec![],
                flags: 123,
                key_data: vec![],
            },
            ParsedSecurityLevelRequest::ImportWrappedKey {
                key: key.clone(),
                wrapping_key: external,
                masking_key: None,
                params: vec![],
                authenticators: vec![],
            },
            ParsedSecurityLevelRequest::ConvertStorageKeyToEphemeral { storage_key: key.clone() },
            ParsedSecurityLevelRequest::DeleteKey { key },
        ];
        for request in requests {
            assert_eq!(
                security_level_request_uses_system_namespace(&request),
                matches!(domain, Domain::SELINUX | Domain::BLOB),
                "{:?}",
                request.method()
            );
        }
    }
}

#[test]
fn system_namespace_cannot_enter_omk_via_a_wrapping_key_grant() {
    let request = ParsedSecurityLevelRequest::ImportWrappedKey {
        key: KeyDescriptor { domain: Domain::SELINUX, ..sample_key_descriptor() },
        wrapping_key: KeyDescriptor { domain: Domain::GRANT, ..sample_key_descriptor() },
        masking_key: None,
        params: vec![],
        authenticators: vec![],
    };
    assert!(security_level_request_uses_system_namespace(&request));
    assert!(!maintenance_requires_mirror(&ParsedMaintenanceRequest::ClearNamespace {
        domain: Domain::SELINUX,
        nspace: 100
    }));
    assert!(maintenance_requires_mirror(&ParsedMaintenanceRequest::ClearNamespace {
        domain: Domain::APP,
        nspace: 1000
    }));
}

#[test]
fn grant_and_ungrant_return_system_error_when_omk_unavailable() {
    let _guard = route_state_test_guard();
    let request = ParsedServiceRequest::Grant {
        key: sample_key_descriptor(),
        grantee_uid: 12345,
        access_vector: 7,
    };
    let caller = CallerInfo { uid: 1000, sid: String::new(), pid: 2000 };

    let result = precompute_omk_grant_service_reply_with(
        &request,
        &caller,
        |_, _, _, _| Err(anyhow::Error::new(Status::from(StatusCode::RpcError))),
        |_, _, _| panic!("grant requests must not call ungrant"),
    );

    let PrecomputedServiceReply::Error(status) = result else {
        panic!("OMK transport failure must return an error");
    };
    assert_eq!(status.service_specific_error(), ResponseCode::SYSTEM_ERROR.0);

    let request =
        ParsedServiceRequest::Ungrant { key: sample_key_descriptor(), grantee_uid: 12345 };
    let caller = CallerInfo { uid: 1000, sid: String::new(), pid: 2000 };

    let result = precompute_omk_grant_service_reply_with(
        &request,
        &caller,
        |_, _, _, _| panic!("ungrant requests must not call grant"),
        |_, _, _| Err(anyhow::Error::new(Status::from(StatusCode::NotEnoughData))),
    );

    let PrecomputedServiceReply::Error(status) = result else {
        panic!("OMK transport failure must return an error");
    };
    assert_eq!(status.service_specific_error(), ResponseCode::SYSTEM_ERROR.0);
}

#[test]
fn grant_precompute_returns_reachable_omk_business_error() {
    let request = ParsedServiceRequest::Grant {
        key: sample_key_descriptor(),
        grantee_uid: 12345,
        access_vector: 7,
    };
    let caller = CallerInfo { uid: 1000, sid: String::new(), pid: 2000 };

    let result = precompute_omk_grant_service_reply_with(
        &request,
        &caller,
        |_, _, _, _| Err(anyhow::Error::new(Status::new_service_specific_error(7, None))),
        |_, _, _| panic!("grant requests must not call ungrant"),
    );

    let PrecomputedServiceReply::Error(status) = result else {
        panic!("reachable OMK business error should be precomputed as an authoritative status");
    };
    assert_eq!(status.exception_code(), rsbinder::ExceptionCode::ServiceSpecific);
    assert_eq!(status.service_specific_error(), 7);
}

#[test]
fn service_route_respects_intercept_configuration() {
    let _guard = route_state_test_guard();
    let intercept = config::InterceptConfig::default();

    for request in sample_service_requests() {
        assert_eq!(
            route_for_service_request(&request, true, &intercept),
            RouteTarget::Omk,
            "{:?} should use the OMK backend when the method is enabled",
            request.method()
        );
    }

    let intercept = disabled_intercept_config();

    for request in sample_service_requests() {
        assert_eq!(
            route_for_service_request(&request, true, &intercept),
            RouteTarget::System,
            "{:?} should use the system backend when the method is disabled",
            request.method()
        );
    }

    let mut intercept = disabled_intercept_config();
    intercept.get_key_entry = true;
    assert!(security_level_scoop_enabled(&intercept));
    intercept.get_key_entry = false;
    intercept.get_security_level = true;
    assert!(security_level_scoop_enabled(&intercept));
    intercept.get_security_level = false;
    assert!(!security_level_scoop_enabled(&intercept));
}

#[test]
fn descriptor_domain_does_not_bypass_scope_or_intercept() {
    for domain in [Domain::APP, Domain::KEY_ID, Domain::GRANT] {
        let request = ParsedServiceRequest::GetKeyEntry {
            key: KeyDescriptor { domain, nspace: 123, alias: None, blob: None },
        };
        for allowed in [false, true] {
            for enabled in [false, true] {
                let mut intercept = disabled_intercept_config();
                intercept.get_key_entry = enabled;
                assert_eq!(
                    route_for_service_request(&request, allowed, &intercept),
                    if allowed && enabled { RouteTarget::Omk } else { RouteTarget::System }
                );
            }
        }
    }
}
