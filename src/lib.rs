#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::{
    ffi::{CStr, CString},
    fmt::{Display, Formatter},
};

use windows::Win32::{Foundation::HANDLE, System::Diagnostics::Debug::ReadProcessMemory};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub struct Process {
    process_handle: HANDLE,
    handle: *mut DotNetProcess,
}
pub struct Class<'a> {
    handle: *mut DotNetClass,
    process: &'a Process,
}

pub struct Field<'a> {
    handle: *mut DotNetField,
    class: &'a Class<'a>,
}

#[derive(Debug)]
pub enum ReadError {
    FailedToRead(windows::core::Error),
    ReadTooSmall { expected: usize, actual: usize },
    FieldNotStatic,
    FieldIsStatic,
}
impl Display for ReadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FailedToRead(error) => {
                write!(f, "failed to read process memory: {error}")
            }

            Self::ReadTooSmall { expected, actual } => {
                write!(f, "read too small: expected {expected} bytes, got {actual}")
            }

            Self::FieldNotStatic => {
                write!(f, "field is not static")
            }

            Self::FieldIsStatic => {
                write!(f, "field is static")
            }
        }
    }
}

pub trait ReadMemory: Sized {
    const SIZE: usize;

    fn from_bytes(bytes: &[u8]) -> Result<Self, ReadError>;

    fn from_u64(value: u64) -> Result<Self, ReadError>;
}

macro_rules! impl_read_memory_int {
    ($($ty:ty),*) => {
        $(
            impl ReadMemory for $ty {
                const SIZE: usize = std::mem::size_of::<$ty>();

                fn from_bytes(bytes: &[u8]) -> Result<Self, ReadError> {
                    let bytes: [u8; std::mem::size_of::<$ty>()] =
                        bytes.try_into().map_err(|_| {
                            ReadError::ReadTooSmall {
                                expected: Self::SIZE,
                                actual: bytes.len(),
                            }
                        })?;

                    Ok(<$ty>::from_le_bytes(bytes))
                }

                fn from_u64(value: u64) -> Result<Self, ReadError> {
                    Ok(value as $ty)
                }
            }
        )*
    };
}

impl_read_memory_int!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);
impl ReadMemory for f32 {
    const SIZE: usize = 4;

    fn from_bytes(bytes: &[u8]) -> Result<Self, ReadError> {
        let bytes: [u8; 4] = bytes.try_into().map_err(|_| ReadError::ReadTooSmall {
            expected: 4,
            actual: bytes.len(),
        })?;

        Ok(f32::from_le_bytes(bytes))
    }

    fn from_u64(value: u64) -> Result<Self, ReadError> {
        Ok(f32::from_bits(value as u32))
    }
}

impl ReadMemory for f64 {
    const SIZE: usize = 8;

    fn from_bytes(bytes: &[u8]) -> Result<Self, ReadError> {
        let bytes: [u8; 8] = bytes.try_into().map_err(|_| ReadError::ReadTooSmall {
            expected: 8,
            actual: bytes.len(),
        })?;

        Ok(f64::from_le_bytes(bytes))
    }

    fn from_u64(value: u64) -> Result<Self, ReadError> {
        Ok(f64::from_bits(value))
    }
}
impl ReadMemory for bool {
    const SIZE: usize = 1;

    fn from_bytes(bytes: &[u8]) -> Result<Self, ReadError> {
        let value = *bytes.first().ok_or(ReadError::ReadTooSmall {
            expected: 1,
            actual: 0,
        })?;

        Ok(value != 0)
    }

    fn from_u64(value: u64) -> Result<Self, ReadError> {
        Ok(value != 0)
    }
}

impl Process {
    pub fn attach(pid: u32) -> Result<Self, String> {
        let handle = unsafe { openProcess(pid) };
        if handle.is_null() {
            return Err("Failed to attach process".to_string());
        }
        let process_handle = unsafe { getProcessHandle(handle) };
        return Ok(Self {
            process_handle: HANDLE(process_handle),
            handle,
        });
    }

    pub fn find_class(&self, class_name: &str) -> Option<Class<'_>> {
        let c_class_name = CString::new(class_name).expect("CString::new failed");
        let class_handle = unsafe { findClass(self.handle, c_class_name.as_ptr()) };

        if class_handle.is_null() {
            return None;
        }
        return Some(Class {
            handle: class_handle,
            process: self,
        });
    }

    pub fn is_instance_valid(&self, instance_addr: usize) -> bool {
        unsafe { instanceIsValid(self.handle, instance_addr) }
    }

    pub fn read<T: ReadMemory>(&self, address: usize) -> Result<T, ReadError> {
        let mut buffer = vec![0u8; T::SIZE];

        self.read_buffer(address, &mut buffer)?;

        T::from_bytes(&buffer)
    }

    pub fn read_buffer(&self, address: usize, buffer: &mut [u8]) -> Result<(), ReadError> {
        let mut bytes_read = 0usize;

        unsafe {
            ReadProcessMemory(
                self.process_handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                Some(&mut bytes_read),
            )
            .map_err(|e| ReadError::FailedToRead(e))?;
        }

        if bytes_read != buffer.len() {
            return Err(ReadError::ReadTooSmall {
                expected: buffer.len(),
                actual: bytes_read,
            });
        }

        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            closeProcess(self.handle);
        }
    }
}

impl<'a> Class<'a> {
    pub fn get_name(&'a self) -> String {
        let c_name = unsafe { CStr::from_ptr(classGetName(self.handle)) };
        c_name.to_string_lossy().into_owned()
    }
    pub fn get_namespace(&'a self) -> String {
        let c_name = unsafe { CStr::from_ptr(classGetNamespace(self.handle)) };
        c_name.to_string_lossy().into_owned()
    }
    pub fn get_full_name(&'a self) -> String {
        let c_name = unsafe { CStr::from_ptr(classGetFullName(self.handle)) };
        c_name.to_string_lossy().into_owned()
    }
    pub fn get_size(&'a self) -> u32 {
        unsafe { classGetSize(self.handle) }
    }

    pub fn print_fields(&'a self) {
        unsafe {
            classPrintFields(self.handle);
        }
    }

    pub fn is_instance_of(&'a self, instance_addr: usize) -> bool {
        unsafe { instanceIsInstanceOfClass(self.handle, instance_addr) }
    }

    pub fn find_field(&'a self, field_name: &str) -> Option<Field<'a>> {
        let c_field_name = CString::new(field_name).expect("CString::new failed");
        let field_handle = unsafe { classFindField(self.handle, c_field_name.as_ptr()) };

        if field_handle.is_null() {
            return None;
        }
        return Some(Field {
            handle: field_handle,
            class: self,
        });
    }

    pub fn read_to_buffer(&self, instance_address: usize) -> Result<Vec<u8>, ReadError> {
        let size = self.get_size() as usize;
        let mut buffer = vec![0u8; size];

        self.process.read_buffer(instance_address, &mut buffer)?;

        Ok(buffer)
    }
}

impl<'a> Field<'a> {
    pub fn get_name(&'a self) -> String {
        let c_name = unsafe { CStr::from_ptr(fieldGetName(self.handle)) };
        c_name.to_string_lossy().into_owned()
    }
    pub fn get_offset(&'a self) -> u32 {
        unsafe { fieldGetOffset(self.handle) }
    }
    pub fn is_static(&'a self) -> bool {
        unsafe { fieldIsStatic(self.handle) }
    }
    pub fn get_type_name(&'a self) -> String {
        let c_name = unsafe { CStr::from_ptr(fieldGetTypeName(self.handle)) };
        c_name.to_string_lossy().into_owned()
    }

    pub fn read_value<T: ReadMemory>(
        &self,
        instance_address: Option<usize>,
    ) -> Result<T, ReadError> {
        if self.is_static() {
            return self.read_static::<T>();
        }

        let instance_address = instance_address.ok_or(ReadError::FieldNotStatic)?;

        let address = instance_address + self.get_offset() as usize;

        self.class.process.read::<T>(address)
    }

    fn read_static<T: ReadMemory>(&self) -> Result<T, ReadError> {
        let mut value = 0u64;

        let success =
            unsafe { fieldGetStaticValue(self.class.process.handle, self.handle, &mut value) };

        if !success {
            return Err(ReadError::FailedToRead(windows::core::Error::empty()));
        }

        T::from_u64(value)
    }

    pub fn read_value_from_buffer<T: ReadMemory>(&self, buffer: &[u8]) -> Result<T, ReadError> {
        let offset = self.get_offset() as usize;

        let end = offset.checked_add(T::SIZE).ok_or(ReadError::ReadTooSmall {
            expected: usize::MAX,
            actual: buffer.len(),
        })?;

        if end > buffer.len() {
            return Err(ReadError::ReadTooSmall {
                expected: end,
                actual: buffer.len(),
            });
        }

        T::from_bytes(&buffer[offset..end])
    }
}

pub fn find_process(process_name: &str) -> Option<u32> {
    let c_process_name = CString::new(process_name).expect("CString::new failed");
    let pid = unsafe { findProcess(c_process_name.as_ptr()) };
    if pid == 0 { None } else { Some(pid) }
}
