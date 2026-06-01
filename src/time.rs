//! Time support library.
//!
//! Contains wrappers for `strftime`, `strptime`, `libc::localtime_r`.

use std::ffi::{CStr, CString};
use std::fmt;
use std::mem::MaybeUninit;

use anyhow::{Error, bail, format_err};

/// Calender month index to *non-leap-year* day-of-the-year.
pub const CAL_MTOD: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];

/// Shortcut for generating an `&'static CStr`.
#[macro_export]
macro_rules! c_str {
    ($data:expr) => {{
        let bytes = concat!($data, "\0");
        unsafe { ::std::ffi::CStr::from_bytes_with_nul_unchecked(bytes.as_bytes()) }
    }};
}

// Wrapper around `libc::tm` providing `Debug` and some helper methods.
pub struct Tm(libc::tm);

impl std::ops::Deref for Tm {
    type Target = libc::tm;

    fn deref(&self) -> &libc::tm {
        &self.0
    }
}

impl std::ops::DerefMut for Tm {
    fn deref_mut(&mut self) -> &mut libc::tm {
        &mut self.0
    }
}

// (or add libc feature 'extra-traits' but that's the only struct we need it for...)
impl fmt::Debug for Tm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Tm")
            .field("tm_sec", &self.tm_sec)
            .field("tm_min", &self.tm_min)
            .field("tm_hour", &self.tm_hour)
            .field("tm_mday", &self.tm_mday)
            .field("tm_mon", &self.tm_mon)
            .field("tm_year", &self.tm_year)
            .field("tm_wday", &self.tm_wday)
            .field("tm_yday", &self.tm_yday)
            .field("tm_isdst", &self.tm_isdst)
            .field("tm_gmtoff", &self.tm_gmtoff)
            .field("tm_zone", &self.tm_zone)
            .finish()
    }
}

/// These are now exposed via `libc`, but they're part of glibc.
mod imports {
    extern "C" {
        pub fn strptime(
            s: *const libc::c_char,
            format: *const libc::c_char,
            tm: *mut libc::tm,
        ) -> *const libc::c_char;
    }
}

impl Tm {
    /// A zero-initialized time struct.
    #[inline(always)]
    pub fn zero() -> Self {
        unsafe { std::mem::zeroed() }
    }

    /// Get the current time in the local timezone.
    pub fn now_local() -> Result<Self, Error> {
        Self::at_local(unsafe { libc::time(std::ptr::null_mut()) })
    }

    /// Get a local time from a unix time stamp.
    pub fn at_local(time: libc::time_t) -> Result<Self, Error> {
        let mut out = MaybeUninit::<libc::tm>::uninit();
        Ok(Self(unsafe {
            if libc::localtime_r(&time, out.as_mut_ptr()).is_null() {
                bail!("failed to convert timestamp to local time");
            }
            out.assume_init()
        }))
    }

    /// Assume this is an UTC time and convert it to a unix time stamp.
    ///
    /// Equivalent to `timegm(3)`, the gmt equivalent of `mktime(3)`.
    pub fn as_utc_to_epoch(&self) -> libc::time_t {
        let mut year = self.0.tm_year as i64 + 1900;
        let mon = self.0.tm_mon;

        let mut res: libc::time_t = (year - 1970) * 365 + CAL_MTOD[mon as usize];

        if mon <= 1 {
            year -= 1;
        }

        res += (year - 1968) / 4;
        res -= (year - 1900) / 100;
        res += (year - 1600) / 400;

        res += (self.0.tm_mday - 1) as i64;
        res = res * 24 + self.0.tm_hour as i64;
        res = res * 60 + self.0.tm_min as i64;
        res = res * 60 + self.0.tm_sec as i64;

        res
    }
}

/// Wrapper around `strptime(3)` to parse time strings.
pub fn strptime(time: &str, format: &CStr) -> Result<Tm, Error> {
    // zero memory because strptime does not necessarily initialize tm_isdst, tm_gmtoff and tm_zone
    let mut out = MaybeUninit::<libc::tm>::zeroed();

    let time = CString::new(time).map_err(|_| format_err!("time string contains nul bytes"))?;

    let end = unsafe {
        imports::strptime(
            time.as_ptr() as *const libc::c_char,
            format.as_ptr(),
            out.as_mut_ptr(),
        )
    };

    if end.is_null() {
        bail!("failed to parse time string {:?}", time);
    }

    Ok(Tm(unsafe { out.assume_init() }))
}

pub fn date_to_rfc3339(date: &str) -> Result<String, Error> {
    // parse the YYYY-MM-DD HH:MM:SS format for the timezone info
    let ltime = strptime(date, c_str!("%F %T"))?;

    // strptime assume it is in UTC, but we want to interpret it as local time and get the timezone
    // offset (tm_gmtoff) which we can then append to be able to parse it as rfc3339
    let ltime = Tm::at_local(ltime.as_utc_to_epoch())?;

    let mut s = date.replacen(' ', "T", 1);
    if ltime.tm_gmtoff != 0 {
        let sign = if ltime.tm_gmtoff < 0 { '-' } else { '+' };
        let minutes = (ltime.tm_gmtoff / 60) % 60;
        let hours = ltime.tm_gmtoff / (60 * 60);
        s.push_str(&format!("{}{:02}:{:02}", sign, hours, minutes));
    } else {
        s.push('Z');
    }
    Ok(s)
}
