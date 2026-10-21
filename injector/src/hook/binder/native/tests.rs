use super::*;
use std::sync::atomic::{AtomicI32, AtomicUsize};

struct ForwardTestState {
    backend: usize,
    error: AtomicI32,
    backend_error: AtomicI32,
    calls: AtomicUsize,
    expected: Vec<u8>,
}

unsafe extern "C" fn forward_test_create(data: *mut c_void) -> *mut c_void {
    data
}
unsafe extern "C" fn forward_test_destroy(_data: *mut c_void) {}

unsafe extern "C" fn forward_test_service(
    binder: *mut c_void,
    code: u32,
    _input: *const c_void,
    output: *mut c_void,
) -> i32 {
    let api = native_binder_api().unwrap();
    let state = &*((api.binder_get_user_data)(binder) as *const ForwardTestState);
    if code != crate::android::system::keystore2::IKeystoreService::transactions::r#getSecurityLevel
    {
        return rsbinder::StatusCode::UnknownTransaction.into();
    }
    let error = state.error.load(Ordering::Relaxed);
    let status = if error == 0 {
        rsbinder::Status::from(rsbinder::StatusCode::Ok)
    } else {
        rsbinder::Status::new_service_specific_error(error, None)
    };
    let reply = crate::parcel::build_status_reply(&status).unwrap();
    let platform = api.view_platform_mut(output, binder, false);
    let result = (api.platform_parcel_write)(platform, reply.data_ptr().cast(), reply.data_size());
    if result != 0 || error != 0 {
        return result;
    }
    (api.parcel_write_strong_binder)(output, state.backend as *mut c_void)
}

unsafe extern "C" fn forward_test_backend(
    binder: *mut c_void,
    _code: u32,
    input: *const c_void,
    output: *mut c_void,
) -> i32 {
    let api = native_binder_api().unwrap();
    let state = &*((api.binder_get_user_data)(binder) as *const ForwardTestState);
    let platform = api.view_platform_const(input, binder, false);
    let bytes = std::slice::from_raw_parts(
        (api.platform_parcel_data)(platform),
        (api.platform_parcel_data_size)(platform),
    );
    if bytes != state.expected {
        return rsbinder::StatusCode::BadValue.into();
    }
    state.calls.fetch_add(1, Ordering::Relaxed);
    let output_platform = api.view_platform_mut(output, binder, false);
    let error = state.backend_error.load(Ordering::Relaxed);
    if error != 0 {
        let reply = crate::parcel::build_status_reply(
            &rsbinder::Status::new_service_specific_error(error, None),
        )
        .unwrap();
        return (api.platform_parcel_write)(
            output_platform,
            reply.data_ptr().cast(),
            reply.data_size(),
        );
    }
    let values = [0i32, (api.binder_get_calling_uid)() as i32];
    let status = (api.platform_parcel_write)(
        output_platform,
        values.as_ptr().cast(),
        std::mem::size_of_val(&values),
    );
    if status != 0 {
        return status;
    }
    (api.parcel_write_strong_binder)(output, binder)
}

#[test]
fn native_system_forwarding_preserves_parcel_identity_binder_objects_and_business_errors() {
    let api = native_binder_api().unwrap();
    unsafe {
        let forward = SystemForwardApi::load().unwrap();
        let ndk = open_library(b"libbinder_ndk.so\0").unwrap();
        let define: ClassDefine = load_symbol(ndk, b"AIBinder_Class_define\0").unwrap();
        let mut state = Box::new(ForwardTestState {
            backend: 0,
            error: AtomicI32::new(0),
            backend_error: AtomicI32::new(0),
            calls: AtomicUsize::new(0),
            expected: vec![],
        });
        let backend_class = define(
            SECURITY_LEVEL_DESCRIPTOR.as_ptr().cast(),
            forward_test_create,
            forward_test_destroy,
            forward_test_backend,
        );
        let backend = RawBinder {
            binder: (api.binder_new)(backend_class, (&mut *state as *mut ForwardTestState).cast())
                as usize,
            dec_strong: api.binder_dec_strong,
        };
        state.backend = backend.binder;
        let service_class = define(
            c"android.system.keystore2.IKeystoreService".as_ptr(),
            forward_test_create,
            forward_test_destroy,
            forward_test_service,
        );
        let service = RawBinder {
            binder: (api.binder_new)(service_class, (&mut *state as *mut ForwardTestState).cast())
                as usize,
            dec_strong: api.binder_dec_strong,
        };
        let input = forward.prepare_local(api, &backend, backend_class as usize).unwrap();
        check_forward_status((forward.write_int)(input.parcel, 0x11223344)).unwrap();
        let input_platform =
            api.view_platform_const(input.parcel, backend.binder as *const c_void, true);
        state.expected = std::slice::from_raw_parts(
            (api.platform_parcel_data)(input_platform),
            (api.platform_parcel_data_size)(input_platform),
        )
        .to_vec();
        let caller_uid = (api.binder_get_calling_uid)();
        for (error, backend_error, calls) in [(0, 0, 1), (7, 0, 1), (0, -100, 2)] {
            state.error.store(error, Ordering::Relaxed);
            state.backend_error.store(backend_error, Ordering::Relaxed);
            let output = RawParcel { parcel: (api.parcel_create)(), delete: api.parcel_delete };
            let output_platform = api.view_platform_mut(output.parcel, std::ptr::null(), true);
            let mut tr: binder_transaction_data = std::mem::zeroed();
            tr.code = crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#convertStorageKeyToEphemeral;
            forward_security_level_from_service(
                api,
                &forward,
                &service,
                1,
                &tr,
                input_platform,
                output_platform,
            )
            .unwrap();
            let data = (api.platform_parcel_data)(output_platform);
            let status = crate::parcel::parse_reply_status(
                data.cast_mut(),
                (api.platform_parcel_data_size)(output_platform),
                std::ptr::null_mut(),
                0,
            )
            .unwrap();
            if error == 0 && backend_error == 0 {
                assert!(status.is_ok());
                assert_eq!(std::ptr::read_unaligned(data.add(4).cast::<u32>()), caller_uid);
                assert_eq!((api.platform_parcel_objects_count)(output_platform), 1);
            } else {
                assert_eq!(
                    status.service_specific_error(),
                    if error == 0 { backend_error } else { error }
                );
                assert_eq!((api.platform_parcel_objects_count)(output_platform), 0);
            }
            assert_eq!(state.calls.load(Ordering::Relaxed), calls);
        }
    }
}

#[test]
fn native_request_offsets_admit_base_transactions_only() {
    assert_eq!(native_request_offsets(1, 0), Some([].as_slice()));
    assert_eq!(native_request_offsets(rsbinder::SHELL_COMMAND_TRANSACTION, 3), Some([].as_slice()));
    assert_eq!(
        native_request_offsets(rsbinder::DUMP_TRANSACTION, 1),
        Some(DUMP_OBJECT_OFFSETS.as_slice())
    );
    assert!(native_request_offsets(1, 1).is_none());
    assert!(native_request_offsets(rsbinder::DUMP_TRANSACTION, 2).is_none());
}

#[test]
fn legacy_aparcel_matches_android_12_13_aarch64_layout() {
    assert_eq!(size_of::<usize>(), 8);
    assert_eq!(std::mem::offset_of!(LegacyAParcel, binder), 0);
    assert_eq!(std::mem::offset_of!(LegacyAParcel, parcel), 8);
    assert_eq!(std::mem::offset_of!(LegacyAParcel, owns_parcel), 16);
    assert_eq!(size_of::<LegacyAParcel>(), 24);
}
