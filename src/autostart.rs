use anyhow::Result;

/// Enable or disable launching the app when the user logs in.
pub fn set_autostart(enable: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux_set(enable)
    }
    #[cfg(target_os = "windows")]
    {
        windows_set(enable)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = enable;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn linux_set(enable: bool) -> Result<()> {
    use directories::BaseDirs;
    use std::fs;

    let base = BaseDirs::new().ok_or_else(|| anyhow::anyhow!("no base dirs"))?;
    let autostart_dir = base.config_dir().join("autostart");
    fs::create_dir_all(&autostart_dir)?;
    let desktop = autostart_dir.join("monotp.desktop");

    if enable {
        let exe = std::env::current_exe()?;
        let contents = format!(
            "[Desktop Entry]\nType=Application\nName=monotp\nComment=Encrypted TOTP authenticator\nExec={}\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
            exe.display()
        );
        fs::write(&desktop, contents)?;
    } else if desktop.exists() {
        fs::remove_file(&desktop)?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_set(enable: bool) -> Result<()> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (run, _) = hkcu.create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Run")?;

    if enable {
        let exe = std::env::current_exe()?;
        run.set_value("monotp", &exe.to_string_lossy().to_string())?;
    } else {
        let _ = run.delete_value("monotp");
    }
    Ok(())
}
