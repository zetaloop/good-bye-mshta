#![cfg_attr(windows, windows_subsystem = "windows")]

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Globalization::GetUserDefaultUILanguage;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NIM_SETVERSION, NOTIFYICON_VERSION_4, NOTIFYICONDATAW, Shell_NotifyIconW, ShellExecuteW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, HWND_MESSAGE, IDI_INFORMATION, LoadIconW, SHOW_WINDOW_CMD,
    SW_SHOWNORMAL, WM_USER,
};

#[derive(Copy, Clone, Eq, PartialEq)]
enum Language {
    Chinese,
    English,
}

struct LocalizedStrings {
    tray_tooltip: &'static str,
    privileged_title: &'static str,
    legacy_title: &'static str,
    no_arguments_body: &'static str,
}

const LOCALIZED_STRINGS_CHINESE: LocalizedStrings = LocalizedStrings {
    tray_tooltip: "mshta.exe 已被替换",
    privileged_title: "mshta 提权已过时，请改用",
    legacy_title: "mshta 指令已过时，不再支持执行",
    no_arguments_body: "未传入参数",
};

const LOCALIZED_STRINGS_ENGLISH: LocalizedStrings = LocalizedStrings {
    tray_tooltip: "mshta.exe has been replaced",
    privileged_title: "mshta elevation is deprecated. Use:",
    legacy_title: "mshta command is deprecated and no longer supported",
    no_arguments_body: "No arguments were provided",
};

fn localized_strings(language: Language) -> &'static LocalizedStrings {
    match language {
        Language::Chinese => &LOCALIZED_STRINGS_CHINESE,
        Language::English => &LOCALIZED_STRINGS_ENGLISH,
    }
}

fn detect_language() -> Language {
    const PRIMARY_LANGUAGE_MASK: u16 = 0x03ff;
    const PRIMARY_LANGUAGE_CHINESE: u16 = 0x0004;
    unsafe {
        let langid = GetUserDefaultUILanguage();
        if langid != 0 {
            let primary = langid & PRIMARY_LANGUAGE_MASK;
            if primary == PRIMARY_LANGUAGE_CHINESE {
                return Language::Chinese;
            }
        }
    }
    Language::English
}

fn main() {
    let language = detect_language();
    let args: Vec<OsString> = std::env::args_os().collect();

    let Some(script_os) = args.get(1) else {
        show_retirement_notice(language, &NoticeMessage::no_arguments(language));
        return;
    };

    let script = script_os.to_string_lossy();

    match parse_shell_execute(&script) {
        Some(request) => {
            show_retirement_notice(language, &NoticeMessage::privileged(language, &request));
            if let Err(err) = execute_shell_request(&request) {
                eprintln!("Failed to ShellExecute: {err}");
            }
        }
        None => {
            let command_line = render_command_line(&args);
            show_retirement_notice(
                language,
                &NoticeMessage::legacy_command(language, &command_line),
            );
        }
    }
}

fn show_retirement_notice(language: Language, message: &NoticeMessage) {
    let strings = localized_strings(language);
    unsafe {
        let Some(hwnd) = create_message_window() else {
            return;
        };

        let mut base: NOTIFYICONDATAW = std::mem::zeroed();
        base.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        base.hWnd = hwnd;
        base.uID = 1;
        base.uFlags = NIF_MESSAGE | NIF_TIP;
        base.uCallbackMessage = WM_USER + 1;
        write_fixed(&mut base.szTip, strings.tray_tooltip);

        let icon = LoadIconW(0, IDI_INFORMATION as usize as *const u16);
        if icon != 0 {
            base.uFlags |= NIF_ICON;
            base.hIcon = icon;
        }

        if Shell_NotifyIconW(NIM_ADD, &base) == 0 {
            DestroyWindow(hwnd);
            return;
        }

        let mut version = base;
        version.Anonymous.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &version);

        let mut info = base;
        info.uFlags = NIF_INFO;
        info.Anonymous.uTimeout = 1000;
        info.dwInfoFlags = NIIF_INFO;
        write_fixed(&mut info.szInfoTitle, message.title);
        write_fixed(&mut info.szInfo, message.body.as_ref());

        Shell_NotifyIconW(NIM_MODIFY, &info);

        Shell_NotifyIconW(NIM_DELETE, &base);
        DestroyWindow(hwnd);
    }
}

struct NoticeMessage {
    title: &'static str,
    body: Cow<'static, str>,
}

impl NoticeMessage {
    fn privileged(language: Language, request: &ShellExecuteRequest) -> Self {
        let strings = localized_strings(language);
        let body = build_privileged_body(request);
        Self {
            title: strings.privileged_title,
            body: Cow::Owned(body),
        }
    }

    fn legacy_command(language: Language, command_line: &str) -> Self {
        let strings = localized_strings(language);
        Self {
            title: strings.legacy_title,
            body: Cow::Owned(command_line.to_string()),
        }
    }

    fn no_arguments(language: Language) -> Self {
        let strings = localized_strings(language);
        Self {
            title: strings.legacy_title,
            body: Cow::Borrowed(strings.no_arguments_body),
        }
    }
}

fn build_privileged_body(req: &ShellExecuteRequest) -> String {
    let mut ps_cmd = String::from(
        "powershell -NoProfile -NonInteractive -WindowStyle Hidden -Command \"$ws = New-Object -ComObject WScript.Shell; $null = $ws.ShellExecute('",
    );
    ps_cmd.push_str(&ps_single_quote(&req.file));
    ps_cmd.push_str("', '");
    ps_cmd.push_str(&ps_single_quote(req.parameters.as_deref().unwrap_or("")));
    ps_cmd.push_str("', '");
    ps_cmd.push_str(&ps_single_quote(req.directory.as_deref().unwrap_or("")));
    ps_cmd.push_str("', '");
    ps_cmd.push_str(&ps_single_quote(req.operation.as_deref().unwrap_or("")));
    ps_cmd.push_str("', ");
    ps_cmd.push_str(&req.show.to_string());
    ps_cmd.push_str(")\"");

    let mut py_cmd =
        String::from("pythonw -c \"import sys,ctypes; f,p,d,o,s=sys.argv[1:6]; s=int(s); ");
    py_cmd.push_str(
        "r=ctypes.windll.shell32.ShellExecuteW(None, (o if o else None), f, (p if p else None), (d if d else None), s); "
    );
    py_cmd.push_str("sys.exit(0 if r>32 else 1)\"");

    py_cmd.push(' ');
    py_cmd.push_str(&quote_arg_str_always(&req.file));
    py_cmd.push(' ');
    py_cmd.push_str(&quote_arg_str_always(
        req.parameters.as_deref().unwrap_or(""),
    ));
    py_cmd.push(' ');
    py_cmd.push_str(&quote_arg_str_always(
        req.directory.as_deref().unwrap_or(""),
    ));
    py_cmd.push(' ');
    py_cmd.push_str(&quote_arg_str_always(
        req.operation.as_deref().unwrap_or(""),
    ));
    py_cmd.push(' ');
    py_cmd.push_str(&req.show.to_string());

    let mut body = String::new();
    body.push_str(&ps_cmd);
    body.push('\n');
    body.push_str(&py_cmd);
    body
}

fn ps_single_quote(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch == '\'' {
            out.push('\'');
            out.push('\'');
        } else {
            out.push(ch);
        }
    }
    out
}

fn quote_arg_str_always(input: &str) -> String {
    quote_argument_impl(input, true)
}
unsafe fn create_message_window() -> Option<HWND> {
    let instance = unsafe { GetModuleHandleW(ptr::null()) };
    if instance == 0 {
        return None;
    }

    let class_name = wide("STATIC");
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class_name.as_ptr(),
            ptr::null(),
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            0,
            instance,
            ptr::null_mut(),
        )
    };

    if hwnd == 0 { None } else { Some(hwnd) }
}

fn write_fixed<const N: usize>(buffer: &mut [u16; N], text: &str) {
    buffer.fill(0);
    if N == 0 {
        return;
    }

    let max_units = N - 1;
    if max_units == 0 {
        return;
    }

    let mut units: Vec<u16> = OsStr::new(text).encode_wide().collect();
    if units.len() > max_units {
        units.truncate(max_units);

        if units
            .last()
            .is_some_and(|last| (0xD800..=0xDBFF).contains(last))
        {
            units.pop();
        }

        const DOT: u16 = '.' as u16;
        if units.len() >= 3 {
            let len = units.len();
            units[len - 3] = DOT;
            units[len - 2] = DOT;
            units[len - 1] = DOT;
        } else {
            for unit in units.iter_mut() {
                *unit = DOT;
            }
            while units.len() < max_units && units.len() < 3 {
                units.push(DOT);
            }
        }
    }

    let copy_len = units.len().min(max_units);
    buffer[..copy_len].copy_from_slice(&units[..copy_len]);
}

struct ShellExecuteRequest {
    file: String,
    parameters: Option<String>,
    directory: Option<String>,
    operation: Option<String>,
    show: SHOW_WINDOW_CMD,
}

fn parse_shell_execute(script: &str) -> Option<ShellExecuteRequest> {
    let script = script.trim();
    let lower = script.to_ascii_lowercase();
    if !lower.starts_with("vbscript:") {
        return None;
    }

    let name_pos = lower.find("shellexecute")?;
    let after_name = &script[name_pos + "shellexecute".len()..];
    let after_exec = after_name.trim_start();
    if !after_exec.starts_with('(') {
        return None;
    }

    let raw_arguments = split_parentheses(after_exec)?;
    let arguments = split_arguments(&raw_arguments);

    if arguments.is_empty() {
        return None;
    }

    let file = required_string(&arguments, 0)?;
    let parameters = optional_string(&arguments, 1);
    let directory = optional_string(&arguments, 2);
    let operation = optional_string(&arguments, 3).filter(|s| !s.is_empty());
    let show = optional_string(&arguments, 4)
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(SW_SHOWNORMAL);

    Some(ShellExecuteRequest {
        file,
        parameters,
        directory,
        operation,
        show,
    })
}

fn render_command_line(args: &[OsString]) -> String {
    let mut rendered = String::new();
    let mut first = true;
    for arg in args {
        let piece = quote_argument(arg);
        if first {
            rendered.push_str(&piece);
            first = false;
        } else {
            rendered.push(' ');
            rendered.push_str(&piece);
        }
    }
    rendered
}

fn execute_shell_request(request: &ShellExecuteRequest) -> Result<(), String> {
    let file = wide(&request.file);
    let parameters = request.parameters.as_deref().map(wide);
    let directory = request.directory.as_deref().map(wide);
    let operation = request.operation.as_deref().map(wide);

    let result = unsafe {
        ShellExecuteW(
            0,
            option_to_pcwstr(operation.as_deref()),
            file.as_ptr(),
            option_to_pcwstr(parameters.as_deref()),
            option_to_pcwstr(directory.as_deref()),
            request.show,
        )
    };

    let code = result as isize;
    if code <= 32 {
        Err(format!("ShellExecuteW 返回错误码 {code}"))
    } else {
        Ok(())
    }
}

fn split_parentheses(segment: &str) -> Option<String> {
    let mut chars = segment.chars().peekable();
    let first = chars.next()?;
    if first != '(' {
        return None;
    }

    let mut in_string = false;
    let mut buffer = String::new();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                buffer.push(ch);
                if in_string {
                    if let Some('"') = chars.peek().copied() {
                        // Escaped quote
                        buffer.push('"');
                        chars.next();
                    } else {
                        in_string = false;
                    }
                } else {
                    in_string = true;
                }
            }
            ')' if !in_string => return Some(buffer),
            _ => buffer.push(ch),
        }
    }

    None
}

fn split_arguments(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                current.push(ch);
                if in_string {
                    if let Some('"') = chars.peek() {
                        current.push('"');
                        chars.next();
                    } else {
                        in_string = false;
                    }
                } else {
                    in_string = true;
                }
            }
            ',' if !in_string => {
                args.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() {
        args.push(current.trim().to_string());
    }

    args
}

fn required_string(arguments: &[String], index: usize) -> Option<String> {
    let value = arguments.get(index)?;
    let unquoted = unquote(value)?;
    if unquoted.is_empty() {
        None
    } else {
        Some(unquoted)
    }
}

fn optional_string(arguments: &[String], index: usize) -> Option<String> {
    arguments
        .get(index)
        .and_then(|value| unquote(value))
        .filter(|value| !value.is_empty())
}

fn unquote(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Some(String::new());
    }

    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        let inner = &trimmed[1..trimmed.len() - 1];
        let mut result = String::new();
        let mut chars = inner.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '"' {
                if let Some('"') = chars.peek() {
                    result.push('"');
                    chars.next();
                } else {
                    return None;
                }
            } else {
                result.push(ch);
            }
        }

        Some(result)
    } else {
        Some(trimmed.to_string())
    }
}

fn quote_argument(arg: &OsStr) -> String {
    quote_argument_impl(arg.to_string_lossy(), false)
}

fn quote_argument_impl<S: AsRef<str>>(value: S, always_quote: bool) -> String {
    let value = value.as_ref();
    if value.is_empty() {
        return "\"\"".to_string();
    }

    let needs_quotes = always_quote || value.chars().any(|ch| ch.is_whitespace() || ch == '"');
    if !needs_quotes {
        return value.to_string();
    }

    let mut result = String::with_capacity(value.len() + 2);
    result.push('"');
    let mut backslashes = 0usize;
    for ch in value.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                for _ in 0..(backslashes * 2 + 1) {
                    result.push('\\');
                }
                result.push('"');
                backslashes = 0;
            }
            _ => {
                if backslashes > 0 {
                    for _ in 0..backslashes {
                        result.push('\\');
                    }
                    backslashes = 0;
                }
                result.push(ch);
            }
        }
    }
    if backslashes > 0 {
        for _ in 0..(backslashes * 2) {
            result.push('\\');
        }
    }
    result.push('"');
    result
}

fn option_to_pcwstr(value: Option<&[u16]>) -> *const u16 {
    value.map_or(ptr::null(), |buf| buf.as_ptr())
}

fn wide(input: &str) -> Vec<u16> {
    OsStr::new(input).encode_wide().chain(Some(0)).collect()
}
