// Suck in the autogen bindings as `libscap` module
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(dead_code)]
#![allow(unnecessary_transmutes)]
#![allow(unused_imports)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::missing_safety_doc)]

#[cfg(feature = "full_bindings")]
pub mod bindings {
    use strum_macros::{Display, EnumIter, FromRepr};
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub mod types {
    use strum_macros::{Display, EnumIter, FromRepr};
    include!(concat!("enums.rs"));
}

pub mod consts {
    include!(concat!("consts.rs"));
}
