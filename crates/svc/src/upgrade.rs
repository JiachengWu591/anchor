//! anchor-svc upgrade：把已安装的服务程序换成本程序这一份（需要管理员）。
//!
//! 和 install 的区别：不改登记信息、不重设权限、不改服务的设置，只换程序文件；
//! 新的服务没有启动成功，就换回原来的文件并把原来的服务启动起来。
//!
//! - 新文件先复制到服务目录里（anchor-svc.exe.new），复制完才停服务。
//! - 旧文件改名留着（anchor-svc.exe.old），新的服务起来之后才删。
//! - 服务停着的这几秒，防火墙守卫规则原样留着，只是不会自动刷新。

use crate::install;
use anchor_core::ipc;
use anchor_core::util::{same_content, same_path};
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use windows_service::service::{Service, ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const WAIT: Duration = Duration::from_secs(15);

/// 对服务的三个操作。换文件的步骤只依赖它，测试时用假的。
pub trait Control {
    /// 服务现在是不是在运行（不是“已停止”就算）。
    fn running(&self) -> Result<bool>;
    /// 停止，等到确实停了。
    fn stop(&self) -> Result<()>;
    /// 启动，等到它起来并且能应答。
    fn start(&self) -> Result<()>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// 内容相同，什么都没动
    Same,
    /// 换好了。restarted：服务原来在运行，已经用新程序启动；原来没在运行就只换文件
    Replaced { restarted: bool },
}

fn suffixed(exe: &Path, suffix: &str) -> PathBuf {
    let mut s = exe.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// 把 exe 换成 new。出错时 exe 是原来的内容，原来在运行的服务重新启动。
pub fn replace(ctl: &dyn Control, new: &Path, exe: &Path) -> Result<Outcome> {
    if !exe.is_file() {
        bail!("{} 不存在：服务没有安装完整。用 anchor service install 安装", exe.display());
    }
    if same_path(new, exe) {
        bail!("本程序就是已安装的那一份。请运行新编译出来的 anchor-svc.exe upgrade");
    }
    if same_content(new, exe).context("比较新旧服务程序失败")? {
        return Ok(Outcome::Same);
    }
    let (staged, old) = (suffixed(exe, ".new"), suffixed(exe, ".old"));
    let _ = std::fs::remove_file(&staged);
    let _ = std::fs::remove_file(&old);

    // 1. 先把新文件放到旁边。这一步不影响正在运行的服务
    let copied = std::fs::copy(new, &staged).with_context(|| format!("复制到 {} 失败", staged.display())).and_then(|n| {
        let want = std::fs::metadata(new)?.len();
        if n != want { bail!("只复制了 {n} 字节，应为 {want} 字节") } else { Ok(()) }
    });
    if let Err(e) = copied {
        let _ = std::fs::remove_file(&staged);
        return Err(e.context("没有做任何改动"));
    }

    // 2. 停服务
    let was_running = ctl.running()?;
    if was_running {
        println!("停止服务…");
        if let Err(e) = ctl.stop() {
            let _ = std::fs::remove_file(&staged);
            // 没停下来的服务还在运行；过一会儿才停下的，这里把它重新启动
            let _ = ctl.start();
            return Err(e.context(if ctl.running().unwrap_or(false) {
                "没有换文件，服务程序和原来一样，服务还在运行"
            } else {
                "没有换文件，服务程序和原来一样，但服务现在没有运行：运行 anchor service install"
            }));
        }
    }

    // 3. 换文件：旧的改名留着，新的改成正式名字
    let swapped = std::fs::rename(exe, &old).context("给旧的服务程序改名失败（有别的程序占着它？）").and_then(|()| {
        std::fs::rename(&staged, exe).context("换上新的服务程序失败").inspect_err(|_| {
            let _ = std::fs::rename(&old, exe);
        })
    });
    if let Err(e) = swapped {
        let _ = std::fs::remove_file(&staged);
        let back = was_running.then(|| ctl.start());
        return Err(e.context(match back {
            Some(Err(_)) => "换文件失败，服务程序和原来一样，但服务没有重新启动起来：运行 anchor service install",
            Some(Ok(())) => "换文件失败，服务程序和原来一样，已重新启动服务",
            None => "换文件失败，服务程序和原来一样",
        }));
    }

    // 4. 启动新的；起不来就换回去
    if was_running {
        println!("启动新的服务…");
        if let Err(e) = ctl.start() {
            // 新的可能还半开着，或者正被系统按“失败后重启”拉起来：先停掉再换文件
            let _ = ctl.stop();
            let restored = std::fs::rename(exe, &staged).and_then(|()| std::fs::rename(&old, exe));
            let _ = std::fs::remove_file(&staged);
            if let Err(r) = restored {
                return Err(e.context(format!(
                    "新的服务没有启动成功，换回原来的文件也失败了（{r}）。原来的程序在 {}，运行 anchor service install 重新安装",
                    old.display()
                )));
            }
            return Err(e.context(match ctl.start() {
                Ok(()) => "新的服务没有启动成功。已换回原来的服务程序，并重新启动了原来的服务",
                Err(_) => "新的服务没有启动成功。已换回原来的服务程序，但原来的服务也没有启动起来：运行 anchor service install",
            }));
        }
    }

    // 5. 删掉旧文件。刚停下的服务，程序文件要过一小会儿才放开
    let deadline = Instant::now() + Duration::from_secs(3);
    while std::fs::remove_file(&old).is_err() && old.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(Outcome::Replaced { restarted: was_running })
}

/// 真正的服务：经服务控制管理器操作。
struct Scm {
    svc: Service,
}

impl Scm {
    fn state(&self) -> Result<ServiceState> {
        Ok(self.svc.query_status()?.current_state)
    }
}

impl Control for Scm {
    fn running(&self) -> Result<bool> {
        Ok(self.state()? != ServiceState::Stopped)
    }

    fn stop(&self) -> Result<()> {
        if self.state()? == ServiceState::Stopped {
            return Ok(());
        }
        let _ = self.svc.stop();
        let deadline = Instant::now() + WAIT;
        while self.state()? != ServiceState::Stopped {
            if Instant::now() >= deadline {
                bail!("服务 {} 秒内没有停止", WAIT.as_secs());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        // 管道随进程消失。等它消失，之后看到的管道才是新服务的
        let gone = Instant::now() + Duration::from_secs(5);
        while ipc::is_running(ipc::SVC_PIPE) && Instant::now() < gone {
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(())
    }

    fn start(&self) -> Result<()> {
        // 已经在运行（比如系统按“失败后重启”先拉起来了）时这里会报错，以下面看到的状态为准
        let asked = self.svc.start::<&str>(&[]);
        let deadline = Instant::now() + WAIT;
        loop {
            match self.state()? {
                // 服务一进入主函数就报“运行中”，读登记信息、开管道在那之后：管道开了才算起来
                ServiceState::Running if ipc::is_running(ipc::SVC_PIPE) => return Ok(()),
                ServiceState::Stopped => {
                    return Err(match asked {
                        Err(e) => anyhow::anyhow!("服务启动失败：{e}"),
                        Ok(()) => anyhow::anyhow!("服务刚启动就停了，日志在 {}", install::log_file().display()),
                    });
                }
                _ => {}
            }
            if Instant::now() >= deadline {
                bail!("服务 {} 秒内没有就绪，日志在 {}", WAIT.as_secs(), install::log_file().display());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

pub fn run() -> Result<()> {
    anchor_core::win::require_admin()?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::STOP;
    let Ok(svc) = manager.open_service(install::SERVICE_NAME, access) else {
        bail!("服务 {} 没有安装。安装：anchor service install", install::SERVICE_NAME);
    };
    // 登记信息读不出来的话，新的服务也起不来：停服务之前先看
    install::load_state().context("没有做任何改动")?;
    let me = std::env::current_exe()?;
    let exe = install::program_dir().join("anchor-svc.exe");
    println!("更新特权服务 {}", install::SERVICE_NAME);
    println!("  新程序  {}", me.display());
    println!("  安装在  {}", exe.display());
    match replace(&Scm { svc }, &me, &exe)? {
        Outcome::Same => println!("已经是这个版本，没有改动。"),
        Outcome::Replaced { restarted: true } => println!("特权服务已更新并启动。防火墙守卫规则没有动。"),
        Outcome::Replaced { restarted: false } => {
            println!("服务程序已更新。服务原来没有在运行，没有启动它；启动：anchor service install");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::os::windows::fs::OpenOptionsExt;

    /// 假的服务：记下被调用的顺序。程序文件的内容是 broken 时启动不了，和真的一样看的是当时放在那里的文件。
    struct Fake {
        exe: PathBuf,
        running: Cell<bool>,
        stop_fails: bool,
        calls: RefCell<Vec<&'static str>>,
    }

    impl Control for Fake {
        fn running(&self) -> Result<bool> {
            Ok(self.running.get())
        }

        fn stop(&self) -> Result<()> {
            self.calls.borrow_mut().push("stop");
            if self.stop_fails {
                bail!("服务 15 秒内没有停止");
            }
            self.running.set(false);
            Ok(())
        }

        fn start(&self) -> Result<()> {
            self.calls.borrow_mut().push("start");
            if self.running.get() {
                bail!("服务已经在运行");
            }
            if std::fs::read_to_string(&self.exe).unwrap_or_default() == "broken" {
                bail!("服务刚启动就停了");
            }
            self.running.set(true);
            Ok(())
        }
    }

    struct Dir {
        root: PathBuf,
        new: PathBuf,
        exe: PathBuf,
    }

    impl Dir {
        /// 已安装的是 "svc 1"，新编译的是 new_text。
        fn new(new_text: &str) -> Self {
            let root = std::env::temp_dir().join(format!("anchor-svc-upgrade-{}", anchor_core::util::random_hex()));
            let (build, inst) = (root.join("build"), root.join("inst"));
            std::fs::create_dir_all(&build).unwrap();
            std::fs::create_dir_all(&inst).unwrap();
            let (new, exe) = (build.join("anchor-svc.exe"), inst.join("anchor-svc.exe"));
            std::fs::write(&new, new_text).unwrap();
            std::fs::write(&exe, "svc 1").unwrap();
            Self { root, new, exe }
        }

        fn fake(&self, running: bool) -> Fake {
            Fake { exe: self.exe.clone(), running: Cell::new(running), stop_fails: false, calls: RefCell::new(vec![]) }
        }

        fn installed(&self) -> String {
            std::fs::read_to_string(&self.exe).unwrap()
        }

        fn names(&self) -> Vec<String> {
            let mut v: Vec<String> =
                std::fs::read_dir(self.exe.parent().unwrap()).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
            v.sort();
            v
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn replaces_and_restarts_a_running_service() {
        let d = Dir::new("svc 2");
        // 上次没清掉的东西不碍事
        std::fs::write(suffixed(&d.exe, ".old"), "更早的").unwrap();
        std::fs::write(suffixed(&d.exe, ".new"), "没用上的").unwrap();
        let f = d.fake(true);
        assert_eq!(replace(&f, &d.new, &d.exe).unwrap(), Outcome::Replaced { restarted: true });
        assert_eq!(*f.calls.borrow(), ["stop", "start"]);
        assert_eq!(d.installed(), "svc 2");
        assert!(f.running.get());
        assert_eq!(d.names(), ["anchor-svc.exe"], ".new 和 .old 都不留");
    }

    #[test]
    fn same_content_touches_nothing() {
        let d = Dir::new("svc 1");
        let f = d.fake(true);
        assert_eq!(replace(&f, &d.new, &d.exe).unwrap(), Outcome::Same);
        assert!(f.calls.borrow().is_empty(), "不停服务");
        assert!(f.running.get());
    }

    #[test]
    fn a_stopped_service_is_replaced_but_not_started() {
        let d = Dir::new("svc 2");
        let f = d.fake(false);
        assert_eq!(replace(&f, &d.new, &d.exe).unwrap(), Outcome::Replaced { restarted: false });
        assert!(f.calls.borrow().is_empty());
        assert_eq!(d.installed(), "svc 2");
        assert!(!f.running.get());
    }

    #[test]
    fn a_new_service_that_does_not_start_is_rolled_back() {
        let d = Dir::new("broken");
        let f = d.fake(true);
        let err = format!("{:#}", replace(&f, &d.new, &d.exe).unwrap_err());
        assert!(err.contains("已换回原来的服务程序，并重新启动了原来的服务"), "{err}");
        assert!(err.contains("服务刚启动就停了"), "原因也要带上：{err}");
        assert_eq!(*f.calls.borrow(), ["stop", "start", "stop", "start"]);
        assert_eq!(d.installed(), "svc 1");
        assert!(f.running.get(), "原来的服务又在运行");
        assert_eq!(d.names(), ["anchor-svc.exe"]);
    }

    #[test]
    fn a_service_that_does_not_stop_is_left_alone() {
        let d = Dir::new("svc 2");
        let mut f = d.fake(true);
        f.stop_fails = true;
        let err = format!("{:#}", replace(&f, &d.new, &d.exe).unwrap_err());
        assert!(err.contains("没有换文件"), "{err}");
        assert_eq!(d.installed(), "svc 1");
        assert!(f.running.get());
        assert_eq!(d.names(), ["anchor-svc.exe"]);
    }

    #[test]
    fn a_file_that_cannot_be_renamed_keeps_the_old_service() {
        let d = Dir::new("svc 2");
        let f = d.fake(true);
        // 服务程序被别的程序打开着，只许别人读（共享方式 1 = FILE_SHARE_READ）：能比较内容，改不了名
        let held = std::fs::OpenOptions::new().read(true).share_mode(1).open(&d.exe).unwrap();
        let err = format!("{:#}", replace(&f, &d.new, &d.exe).unwrap_err());
        drop(held);
        assert!(err.contains("已重新启动服务"), "{err}");
        assert_eq!(*f.calls.borrow(), ["stop", "start"]);
        assert_eq!(d.installed(), "svc 1");
        assert!(f.running.get());
        assert_eq!(d.names(), ["anchor-svc.exe"]);
    }

    #[test]
    fn refuses_when_there_is_nothing_to_replace() {
        let d = Dir::new("svc 2");
        let f = d.fake(true);
        let err = replace(&f, &d.exe, &d.exe).unwrap_err().to_string();
        assert!(err.contains("就是已安装的那一份"), "{err}");
        std::fs::remove_file(&d.exe).unwrap();
        let err = replace(&f, &d.new, &d.exe).unwrap_err().to_string();
        assert!(err.contains("没有安装完整"), "{err}");
        assert!(f.calls.borrow().is_empty());
    }

    #[test]
    fn a_new_program_that_disappears_changes_nothing() {
        let d = Dir::new("svc 2");
        let f = d.fake(true);
        let gone = d.root.join("build").join("gone.exe");
        assert!(replace(&f, &gone, &d.exe).is_err());
        assert!(f.calls.borrow().is_empty());
        assert_eq!(d.installed(), "svc 1");
        assert_eq!(d.names(), ["anchor-svc.exe"]);
    }
}
