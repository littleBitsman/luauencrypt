#![expect(non_camel_case_types)]

use std::{fmt::{Debug, Display, Formatter, Result as FmtResult}, marker::{PhantomData, PhantomPinned}, os::raw::{c_char, c_int, c_void}, ptr, slice};

#[repr(C)]
pub struct lua_CompileConstant {
    _data: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

pub type lua_LibraryMemberTypeCallback =
    unsafe extern "C-unwind" fn(library: *const c_char, member: *const c_char) -> c_int;
pub type lua_LibraryMemberConstantCallback = unsafe extern "C-unwind" fn(
    library: *const c_char,
    member: *const c_char,
    constant: *mut lua_CompileConstant,
);

#[derive(Clone, Copy, Debug)]
#[repr(C)]
#[non_exhaustive]
#[expect(non_snake_case)]
pub struct lua_CompileOptions {
    pub optimizationLevel: c_int,
    pub debugLevel: c_int,
    pub typeInfoLevel: c_int,
    pub coverageLevel: c_int,
    pub vectorLib: *const c_char,
    pub vectorCtor: *const c_char,
    pub vectorType: *const c_char,
    pub mutableGlobals: *const *const c_char,
    pub userdataTypes: *const *const c_char,
    pub librariesWithKnownMembers: *const *const c_char,
    pub libraryMemberTypeCallback: Option<lua_LibraryMemberTypeCallback>,
    pub libraryMemberConstantCallback: Option<lua_LibraryMemberConstantCallback>,
    pub disabledBuiltins: *const *const c_char,
}

impl Default for lua_CompileOptions {
    fn default() -> Self {
        Self {
            optimizationLevel: 1,
            debugLevel: 1,
            typeInfoLevel: 0,
            coverageLevel: 0,
            vectorLib: ptr::null(),
            vectorCtor: ptr::null(),
            vectorType: ptr::null(),
            mutableGlobals: ptr::null(),
            userdataTypes: ptr::null(),
            librariesWithKnownMembers: ptr::null(),
            libraryMemberTypeCallback: None,
            libraryMemberConstantCallback: None,
            disabledBuiltins: ptr::null(),
        }
    }
}
impl Display for lua_CompileOptions {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Debug::fmt(&self, f)
    }
}

unsafe extern "C-unwind" {
    #[link_name = "luau_compile"]
    pub unsafe fn luau_compile_internal(
        source: *const c_char,
        size: usize,
        options: *mut lua_CompileOptions,
        outsize: *mut usize,
    ) -> *mut c_char;
}

#[expect(clippy::missing_safety_doc)]
pub unsafe fn luau_compile(source: &[u8], mut options: lua_CompileOptions) -> Vec<u8> {
    let mut outsize = 0;
    let data_ptr = unsafe { luau_compile_internal(
        source.as_ptr() as *const c_char,
        source.len(),
        &mut options,
        &mut outsize,
    ) };
    assert!(!data_ptr.is_null(), "luau_compile failed");
    let data = unsafe { slice::from_raw_parts(data_ptr as *const u8, outsize).to_vec() };
    unsafe { libc::free(data_ptr as *mut c_void) };
    data
}