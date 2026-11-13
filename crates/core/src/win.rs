//! Windows 系统调用的小封装：当前用户 SID、是否提权、系统目录、用户配置文件目录、
//! 随父进程退出的作业对象、注册表变更通知、MSIX 应用包环境检测。

use anyhow::{Context, Result, bail};
use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::time::Duration;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE, LocalFree, WAIT_OBJECT_0};
use windows_sys::Win32::Storage::Packaging::Appx::{GetCurrentPackageFamilyName, GetCurrentPackageFullName};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_NOTIFY, KEY_READ, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME, RegCloseKey,
    RegNotifyChangeKeyValue, RegOpenKeyExW,
};
use windows_sys::Win32::System::Threading::{CreateEventW, GetCurrentProcess, OpenProcessToken, WaitForSingleObject};

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// %SystemRoot%\System32 下的程序。用绝对路径启动系统工具，避免 PATH 里同名程序被优先执行。
pub fn system32(file: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    root.join("System32").join(file)
}

struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn process_token() -> Result<Token> {
    let mut h: HANDLE = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h) } == 0 {
        bail!("OpenProcessToken 失败：{}", std::io::Error::last_os_error());
    }
    Ok(Token(h))
}

/// 当前进程用户的 SID 字符串，如 S-1-5-21-…。
pub fn current_user_sid() -> Result<String> {
    let t = process_token()?;
    let mut len = 0u32;
    unsafe { GetTokenInformation(t.0, TokenUser, null_mut(), 0, &mut len) };
    if len == 0 {
        bail!("GetTokenInformation 失败：{}", std::io::Error::last_os_error());
    }
    // 按 u64 对齐分配缓冲区
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    if unsafe { GetTokenInformation(t.0, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) } == 0 {
        bail!("GetTokenInformation 失败：{}", std::io::Error::last_os_error());
    }
    let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let mut s: *mut u16 = null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut s) } == 0 {
        bail!("ConvertSidToStringSidW 失败：{}", std::io::Error::last_os_error());
    }
    let out = unsafe { from_wide_ptr(s) };
    unsafe { LocalFree(s.cast()) };
    Ok(out)
}

unsafe fn from_wide_ptr(p: *const u16) -> String {
    let mut n = 0;
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
}

/// 当前进程是否以管理员身份（已提权）运行。
pub fn is_elevated() -> bool {
    let Ok(t) = process_token() else { return false };
    let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    let ok = unsafe {
        GetTokenInformation(t.0, TokenElevation, (&mut e as *mut TOKEN_ELEVATION).cast(), size_of::<TOKEN_ELEVATION>() as u32, &mut len)
    };
    ok != 0 && e.TokenIsElevated != 0
}

pub fn require_admin() -> Result<()> {
    if !is_elevated() {
        bail!("需要管理员权限：请在“以管理员身份运行”的终端里执行这条命令");
    }
    Ok(())
}

/// 把 %NAME% 换成 vars 里的值（不区分大小写），找不到再查本进程环境变量；都没有则原样保留。
pub fn expand_env(s: &str, vars: &[(&str, &Path)]) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        let Some(len) = rest[start + 1..].find('%') else { break };
        let name = &rest[start + 1..start + 1 + len];
        out.push_str(&rest[..start]);
        let val = vars
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.to_string_lossy().into_owned())
            .or_else(|| (!name.is_empty()).then(|| std::env::var(name).ok()).flatten());
        match val {
            Some(v) => out.push_str(&v),
            None => out.push_str(&rest[start..start + len + 2]),
        }
        rest = &rest[start + len + 2..];
    }
    out.push_str(rest);
    out
}

/// 按 SID 查用户配置文件目录（HKLM ProfileList，只有管理员可写）。
pub fn profile_dir(sid: &str) -> Result<PathBuf> {
    let key = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"))
        .with_context(|| format!("找不到用户 {sid} 的配置文件登记"))?;
    let raw: String = key.get_value("ProfileImagePath").context("读取 ProfileImagePath 失败")?;
    Ok(PathBuf::from(expand_env(&raw, &[])))
}

/// 当前进程所在的 MSIX 应用包。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// 如 Claude_5.11492.0.0_x64__pzs8sxrjxfjjc
    pub full_name: String,
    /// 如 Claude_pzs8sxrjxfjjc
    pub family: String,
}

impl Package {
    /// 应用名，如 Claude
    pub fn app(&self) -> &str {
        self.family.split('_').next().unwrap_or(&self.family)
    }
}

fn package_string(f: impl Fn(&mut u32, *mut u16) -> u32) -> Option<String> {
    let mut len = 0u32;
    // 不在应用包里时返回 APPMODEL_ERROR_NO_PACKAGE；在包里时先返回所需长度
    if f(&mut len, null_mut()) != ERROR_INSUFFICIENT_BUFFER || len == 0 {
        return None;
    }
    let mut buf = vec![0u16; len as usize];
    if f(&mut len, buf.as_mut_ptr()) != 0 {
        return None;
    }
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..n]))
}

/// 当前进程是否运行在某个 MSIX 应用包里（例如从 Claude 桌面版的终端启动）。
///
/// 包里的进程写 %LOCALAPPDATA% / %APPDATA% 时，新文件会被 Windows 重定向到该应用的私有目录，
/// 它启动的子进程也留在包里。后台服务、登录自启和普通终端都看不到这些文件。
pub fn current_package() -> Option<Package> {
    let full_name = package_string(|len, buf| unsafe { GetCurrentPackageFullName(len, buf) })?;
    let family = package_string(|len, buf| unsafe { GetCurrentPackageFamilyName(len, buf) }).unwrap_or_default();
    Some(Package { full_name, family })
}

/// 实测：本进程在 %LOCALAPPDATA% 新建的文件是否被重定向到某个 MSIX 应用的私有目录。
/// 是则返回该应用包的目录名（如 Claude_pzs8sxrjxfjjc）。
///
/// 只看应用包身份不够：实测从 Claude 桌面版启动的 Claude Code 及其终端没有包身份
/// （GetCurrentPackageFullName 返回 15700），写入却照样被重定向。所以直接写一个临时文件看它落在哪里。
pub fn appdata_redirect() -> Option<String> {
    let local = PathBuf::from(std::env::var_os("LOCALAPPDATA")?);
    let name = format!(".anchor-probe-{}.tmp", crate::util::random_hex());
    let probe = local.join(&name);
    std::fs::write(&probe, b"").ok()?;
    let found = std::fs::read_dir(local.join("Packages")).ok().and_then(|rd| {
        rd.flatten()
            .find(|e| e.path().join("LocalCache").join("Local").join(&name).exists())
            .map(|e| e.file_name().to_string_lossy().into_owned())
    });
    let _ = std::fs::remove_file(&probe);
    found
}

/// 当前进程是否处在 MSIX 应用的环境里：有应用包身份，或写入 %LOCALAPPDATA% 会被重定向。
pub fn sandbox() -> Option<Package> {
    current_package().or_else(|| {
        let dir = appdata_redirect()?;
        Some(Package { full_name: dir.clone(), family: dir })
    })
}

/// MSIX 应用替某个目录重定向写入时留下的私有副本：
/// %LOCALAPPDATA%\Packages\<应用>\LocalCache\{Local,Roaming}\<相对路径>。
/// dir 不在 %LOCALAPPDATA% 或 %APPDATA% 下时不会被重定向，返回空。
pub fn private_copies(dir: &Path) -> Vec<PathBuf> {
    let env = |k: &str| std::env::var_os(k).map(PathBuf::from);
    let (Some(local), roaming) = (env("LOCALAPPDATA"), env("APPDATA")) else { return vec![] };
    private_copies_in(dir, &local, roaming.as_deref())
}

fn strip_prefix_ci(path: &Path, base: &Path) -> Option<PathBuf> {
    let p = path.to_string_lossy().replace('/', "\\");
    let b = base.to_string_lossy().replace('/', "\\");
    let b = b.trim_end_matches('\\');
    let rest = p.get(b.len()..)?;
    if !p[..b.len()].eq_ignore_ascii_case(b) || !(rest.is_empty() || rest.starts_with('\\')) {
        return None;
    }
    Some(PathBuf::from(rest.trim_start_matches('\\')))
}

fn private_copies_in(dir: &Path, local: &Path, roaming: Option<&Path>) -> Vec<PathBuf> {
    let (kind, rel) = match (strip_prefix_ci(dir, local), roaming.and_then(|r| strip_prefix_ci(dir, r))) {
        (Some(rel), _) => ("Local", rel),
        (None, Some(rel)) => ("Roaming", rel),
        _ => return vec![],
    };
    // 数据目录本身就在某个应用包的目录里，不是副本
    if rel.as_os_str().is_empty() || rel.starts_with("Packages") {
        return vec![];
    }
    let Ok(rd) = std::fs::read_dir(local.join("Packages")) else { return vec![] };
    let mut out: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path().join("LocalCache").join(kind).join(&rel))
        .filter(|p| p.exists())
        .collect();
    out.sort();
    out
}

/// 作业对象：关闭时结束其中所有进程。把内核放进去，用户代理被强制结束时内核也随之退出，
/// 不会留下占着端口的孤儿进程。
pub struct KillOnClose(HANDLE);
unsafe impl Send for KillOnClose {}
unsafe impl Sync for KillOnClose {}

impl KillOnClose {
    pub fn new() -> Result<Self> {
        let h = unsafe { CreateJobObjectW(null(), null()) };
        if h.is_null() {
            bail!("CreateJobObjectW 失败：{}", std::io::Error::last_os_error());
        }
        let job = Self(h);
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok = unsafe {
            SetInformationJobObject(
                h,
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            bail!("SetInformationJobObject 失败：{}", std::io::Error::last_os_error());
        }
        Ok(job)
    }

    pub fn assign(&self, child: &std::process::Child) -> Result<()> {
        if unsafe { AssignProcessToJobObject(self.0, child.as_raw_handle() as HANDLE) } == 0 {
            bail!("AssignProcessToJobObject 失败：{}", std::io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for KillOnClose {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// 监视 HKLM 下一个键的子键增删和值变化（例如应用包登记表）。
pub struct RegWatch {
    key: HKEY,
    event: HANDLE,
}
unsafe impl Send for RegWatch {}

impl RegWatch {
    pub fn hklm(subkey: &str) -> Result<Self> {
        let mut key: HKEY = null_mut();
        let rc = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, wide(subkey).as_ptr(), 0, KEY_NOTIFY | KEY_READ, &mut key) };
        if rc != 0 {
            bail!("打开注册表键失败（{rc}）：HKLM\\{subkey}");
        }
        let event = unsafe { CreateEventW(null(), 0, 0, null()) };
        if event.is_null() {
            unsafe { RegCloseKey(key) };
            bail!("CreateEventW 失败：{}", std::io::Error::last_os_error());
        }
        let w = Self { key, event };
        w.arm()?;
        Ok(w)
    }

    fn arm(&self) -> Result<()> {
        let rc = unsafe {
            RegNotifyChangeKeyValue(self.key, 0, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, self.event, 1)
        };
        if rc != 0 {
            bail!("RegNotifyChangeKeyValue 失败（{rc}）");
        }
        Ok(())
    }

    /// 等待变化；返回 true 表示有变化（并已重新开始监视）。
    pub fn wait(&self, timeout: Duration) -> bool {
        let ms = timeout.as_millis().min(u32::MAX as u128 - 1) as u32;
        if unsafe { WaitForSingleObject(self.event, ms) } == WAIT_OBJECT_0 {
            let _ = self.arm();
            true
        } else {
            false
        }
    }
}

impl Drop for RegWatch {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.key);
            CloseHandle(self.event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_env_prefers_given_vars() {
        let p = Path::new(r"C:\Users\u");
        assert_eq!(expand_env(r"%USERPROFILE%\.local\bin", &[("UserProfile", p)]), r"C:\Users\u\.local\bin");
        assert_eq!(expand_env("%NO_SUCH_VAR_ANCHOR%;x", &[]), "%NO_SUCH_VAR_ANCHOR%;x");
        assert_eq!(expand_env("100%", &[]), "100%");
    }

    #[test]
    fn private_copies_found_under_package_local_cache() {
        let root = std::env::temp_dir().join(format!("anchor-pkg-{}", crate::util::random_hex()));
        let local = root.join("Local");
        let roaming = root.join("Roaming");
        let copy = local.join(r"Packages\Claude_x\LocalCache\Local\AIAnchor");
        std::fs::create_dir_all(&copy).unwrap();
        std::fs::create_dir_all(local.join(r"Packages\Other_y\LocalCache\Local")).unwrap();
        assert_eq!(private_copies_in(&local.join("AIAnchor"), &local, Some(&roaming)), vec![copy]);
        // 大小写和斜杠不同也能识别
        let mixed = PathBuf::from(local.to_string_lossy().to_uppercase().replace('\\', "/")).join("aianchor");
        assert_eq!(private_copies_in(&mixed, &local, Some(&roaming)).len(), 1);
        // 不在 AppData 下、或只是前缀相同的目录，不会被重定向
        assert!(private_copies_in(Path::new(r"E:\data\AIAnchor"), &local, Some(&roaming)).is_empty());
        assert!(private_copies_in(&root.join("LocalX").join("AIAnchor"), &local, Some(&roaming)).is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn package_app_name() {
        let p = Package { full_name: "Claude_5.1.0.0_x64__pzs8sxrjxfjjc".into(), family: "Claude_pzs8sxrjxfjjc".into() };
        assert_eq!(p.app(), "Claude");
        // 只验证调用不出错：在 Claude 桌面版里跑测试时会返回 Some
        let _ = current_package();
    }

    #[test]
    fn current_user_sid_looks_like_a_sid() {
        assert!(current_user_sid().unwrap().starts_with("S-1-"));
    }
}
