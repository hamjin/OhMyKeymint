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
        let caller = CallerInfo {
            uid,
            sid: sid.to_string(),
            pid: 1458,
        };
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
    for domain in [
        Domain::APP,
        Domain::KEY_ID,
        Domain::GRANT,
        Domain::SELINUX,
        Domain::BLOB,
        Domain(99),
    ] {
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
                route_for_service_request(&request, &config::InterceptConfig::default()),
                expected,
                "method={:?} domain={domain:?}",
                request.method()
            );
            assert_eq!(
                route_for_service_request(&request, &disabled_intercept_config()),
                RouteTarget::System
            );
        }
    }
}

#[test]
fn security_level_scope_uses_primary_namespace_and_keeps_secondary_descriptors_unchanged() {
    for domain in [
        Domain::APP,
        Domain::KEY_ID,
        Domain::GRANT,
        Domain::SELINUX,
        Domain::BLOB,
        Domain(99),
    ] {
        let key = KeyDescriptor {
            domain,
            ..sample_key_descriptor()
        };
        let external = KeyDescriptor {
            domain: Domain::SELINUX,
            ..sample_key_descriptor()
        };
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
            ParsedSecurityLevelRequest::ConvertStorageKeyToEphemeral {
                storage_key: key.clone(),
            },
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
    let caller = CallerInfo {
        uid: 1000,
        pid: 2957,
        sid: "u:r:system_server:s0".into(),
    };
    let decision = filter::FilterDecision {
        allowed: false,
        reason: FilterReason::RejectedNotInScope,
        packages: vec![],
    };
    let request = ParsedSecurityLevelRequest::ImportWrappedKey {
        key: KeyDescriptor {
            domain: Domain::SELINUX,
            ..sample_key_descriptor()
        },
        wrapping_key: KeyDescriptor {
            domain: Domain::GRANT,
            ..sample_key_descriptor()
        },
        masking_key: None,
        params: vec![],
        authenticators: vec![],
    };
    assert!(!should_allow_omk_grant_security_level_request_with_probe(
        &request,
        &decision,
        &caller,
        |_, _| panic!("system namespaces must not probe OMK")
    )
    .unwrap());
    assert!(!maintenance_requires_mirror(
        &ParsedMaintenanceRequest::ClearNamespace {
            domain: Domain::SELINUX,
            nspace: 100
        }
    ));
    assert!(maintenance_requires_mirror(
        &ParsedMaintenanceRequest::ClearNamespace {
            domain: Domain::APP,
            nspace: 1000
        }
    ));
}

#[test]
fn grant_and_ungrant_preserve_system_only_when_omk_unavailable() {
    let _guard = route_state_test_guard();
    let request = ParsedServiceRequest::Grant {
        key: sample_key_descriptor(),
        grantee_uid: 12345,
        access_vector: 7,
    };
    let caller = CallerInfo {
        uid: 1000,
        sid: String::new(),
        pid: 2000,
    };

    let result = precompute_omk_grant_service_reply_with(
        &request,
        &caller,
        |_, _, _, _| Err(anyhow::Error::new(Status::from(StatusCode::RpcError))),
        |_, _, _| panic!("grant requests must not call ungrant"),
    );

    assert!(matches!(result, OmkServicePrecompute::PreserveSystem));

    let request = ParsedServiceRequest::Ungrant {
        key: sample_key_descriptor(),
        grantee_uid: 12345,
    };
    let caller = CallerInfo {
        uid: 1000,
        sid: String::new(),
        pid: 2000,
    };

    let result = precompute_omk_grant_service_reply_with(
        &request,
        &caller,
        |_, _, _, _| panic!("ungrant requests must not call grant"),
        |_, _, _| Err(anyhow::Error::new(Status::from(StatusCode::NotEnoughData))),
    );

    assert!(matches!(result, OmkServicePrecompute::PreserveSystem));
}

#[test]
fn grant_precompute_returns_reachable_omk_business_error() {
    let request = ParsedServiceRequest::Grant {
        key: sample_key_descriptor(),
        grantee_uid: 12345,
        access_vector: 7,
    };
    let caller = CallerInfo {
        uid: 1000,
        sid: String::new(),
        pid: 2000,
    };

    let result = precompute_omk_grant_service_reply_with(
        &request,
        &caller,
        |_, _, _, _| {
            Err(anyhow::Error::new(Status::new_service_specific_error(
                7, None,
            )))
        },
        |_, _, _| panic!("grant requests must not call ungrant"),
    );

    let OmkServicePrecompute::Reply(PrecomputedServiceReply::Error(status)) = result else {
        panic!("reachable OMK business error should be precomputed as an authoritative status");
    };
    assert_eq!(
        status.exception_code(),
        rsbinder::ExceptionCode::ServiceSpecific
    );
    assert_eq!(status.service_specific_error(), 7);
}

#[test]
fn service_route_respects_intercept_configuration() {
    let _guard = route_state_test_guard();
    let intercept = config::InterceptConfig::default();

    for request in sample_service_requests() {
        assert_eq!(
            route_for_service_request(&request, &intercept),
            RouteTarget::Omk,
            "{:?} should use the OMK backend when the method is enabled",
            request.method()
        );
    }

    let intercept = disabled_intercept_config();

    for request in sample_service_requests() {
        assert_eq!(
            route_for_service_request(&request, &intercept),
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
fn service_route_uses_omk_for_key_id() {
    let key = KeyDescriptor {
        domain: Domain::KEY_ID,
        nspace: 123,
        alias: None,
        blob: None,
    };

    assert_eq!(
        route_for_service_request(
            &ParsedServiceRequest::GetKeyEntry { key },
            &config::InterceptConfig::default(),
        ),
        RouteTarget::Omk
    );
}

#[test]
fn unconfirmed_grant_readback_stays_rejected() {
    let _guard = route_state_test_guard();
    let decision = crate::filter::FilterDecision {
        allowed: false,
        reason: crate::filter::FilterReason::RejectedNotInScope,
        packages: vec!["com.grantee".to_string()],
    };
    let caller = CallerInfo {
        uid: 10002,
        sid: String::new(),
        pid: 2000,
    };
    let grant = KeyDescriptor {
        domain: Domain::GRANT,
        nspace: 123,
        alias: None,
        blob: None,
    };

    assert!(!should_allow_omk_grant_service_request_with_probe(
        &ParsedServiceRequest::GetKeyEntry { key: grant },
        &decision,
        &caller,
        |_, _| Ok(false),
    )
    .expect("unconfirmed grant lookup should succeed"));
    assert!(!should_allow_omk_grant_service_request_with_probe(
        &ParsedServiceRequest::GetKeyEntry {
            key: sample_key_descriptor(),
        },
        &decision,
        &caller,
        |_, _| -> anyhow::Result<bool> { panic!("non-GRANT descriptors must not be probed") },
    )
    .expect("non-GRANT lookup should succeed"));
}

#[test]
fn soft_rejected_grant_probe_error_is_fail_closed() {
    let _guard = route_state_test_guard();
    let grant = KeyDescriptor {
        domain: Domain::GRANT,
        nspace: 123,
        alias: None,
        blob: None,
    };
    let decision = crate::filter::FilterDecision {
        allowed: false,
        reason: crate::filter::FilterReason::RejectedUnknownPackage,
        packages: vec![],
    };
    let caller = CallerInfo {
        uid: 10002,
        sid: String::new(),
        pid: 2000,
    };

    let error = should_allow_omk_grant_service_request_with_probe(
        &ParsedServiceRequest::GetKeyEntry { key: grant },
        &decision,
        &caller,
        |_, _| Err(anyhow::anyhow!("reachable probe failure")),
    )
    .expect_err("non-unavailable probe errors must block System fallback");

    assert!(error.to_string().contains("reachable probe failure"));
}

#[test]
fn soft_rejected_grant_positive_probe_works_for_service_and_security_level() {
    let _guard = route_state_test_guard();
    let grant = KeyDescriptor {
        domain: Domain::GRANT,
        nspace: 123,
        alias: None,
        blob: None,
    };
    let decision = crate::filter::FilterDecision {
        allowed: false,
        reason: crate::filter::FilterReason::RejectedUnknownPackage,
        packages: vec![],
    };
    let caller = CallerInfo {
        uid: 10002,
        sid: String::new(),
        pid: 2000,
    };

    assert!(should_allow_omk_grant_service_request_with_probe(
        &ParsedServiceRequest::GetKeyEntry { key: grant.clone() },
        &decision,
        &caller,
        |probe_caller, probe_grant| {
            assert_eq!(probe_caller.uid, caller.uid);
            assert_eq!(probe_grant, &grant);
            Ok(true)
        },
    )
    .expect("positive grant probe should succeed"));

    let grant = KeyDescriptor {
        domain: Domain::GRANT,
        nspace: 321,
        alias: None,
        blob: None,
    };
    let decision = crate::filter::FilterDecision {
        allowed: false,
        reason: crate::filter::FilterReason::RejectedNotInScope,
        packages: vec!["com.grantee".to_string()],
    };

    assert!(should_allow_omk_grant_security_level_request_with_probe(
        &ParsedSecurityLevelRequest::CreateOperation {
            key: grant.clone(),
            operation_parameters: vec![],
            forced: false,
        },
        &decision,
        &caller,
        |probe_caller, probe_grant| {
            assert_eq!(probe_caller.uid, caller.uid);
            assert_eq!(probe_grant, &grant);
            Ok(true)
        },
    )
    .expect("positive grant probe should succeed"));
}

#[test]
fn denylisted_grant_readback_does_not_probe_omk() {
    let _guard = route_state_test_guard();
    let grant = KeyDescriptor {
        domain: Domain::GRANT,
        nspace: 123,
        alias: None,
        blob: None,
    };
    let decision = crate::filter::FilterDecision {
        allowed: false,
        reason: crate::filter::FilterReason::RejectedByDenylist,
        packages: vec!["com.blocked".to_string()],
    };
    let caller = CallerInfo {
        uid: 10002,
        sid: String::new(),
        pid: 2000,
    };

    assert!(!should_allow_omk_grant_service_request_with_probe(
        &ParsedServiceRequest::GetKeyEntry { key: grant },
        &decision,
        &caller,
        |_, _| -> anyhow::Result<bool> { panic!("denylisted callers must not probe OMK grants") },
    )
    .expect("denylisted grant lookup should succeed"));
}
