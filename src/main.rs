use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use winrt_notification::{Duration, Toast};

use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{SHOW_WINDOW_CMD, SW_SHOWNORMAL};
use windows::core::PCWSTR;

fn main() {
    show_retirement_notice();

    let mut raw_args = std::env::args_os().skip(1);
    let Some(script_os) = raw_args.next() else {
        return;
    };

    let forwarded: Vec<OsString> = raw_args.collect();
    let script = script_os.to_string_lossy();

    if let Some(mut request) = parse_shell_execute(&script) {
        request.parameters = expand_parameters(request.parameters.as_ref(), &forwarded);
        if let Err(err) = execute_shell_request(&request) {
            eprintln!("无法执行 ShellExecute 请求: {err}");
        }
    }
}

fn show_retirement_notice() {
    let _ = Toast::new(Toast::POWERSHELL_APP_ID)
        .title("mshta.exe 已被替换")
        .text1("mshta 已退役，请使用 PowerShell 或 Python 提权")
        .duration(Duration::Short) // 由系统控制显示时长
        .show();
}

#[derive(Debug)]
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
    if !lower.contains("createobject(\"shell.application\")") {
        return None;
    }

    let exec_pos = lower.find(".shellexecute")?;
    let after_exec = script[exec_pos + ".ShellExecute".len()..].trim_start();
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
        .map(SHOW_WINDOW_CMD)
        .unwrap_or(SW_SHOWNORMAL);

    Some(ShellExecuteRequest {
        file,
        parameters,
        directory,
        operation,
        show,
    })
}

fn expand_parameters(parameters: Option<&String>, forwarded: &[OsString]) -> Option<String> {
    let mut result = parameters.cloned().unwrap_or_default();
    let joined = if forwarded.is_empty() {
        String::new()
    } else {
        join_forwarded_args(forwarded)
    };

    if result.contains("%*") {
        result = result.replace("%*", joined.as_str());
    } else if !joined.is_empty() {
        if result.is_empty() {
            result = joined;
        } else {
            result.push(' ');
            result.push_str(&joined);
        }
    }

    if result.trim().is_empty() {
        None
    } else {
        Some(result.trim().to_string())
    }
}

fn execute_shell_request(request: &ShellExecuteRequest) -> Result<(), String> {
    let file = wide(&request.file);
    let parameters = request.parameters.as_ref().map(|value| wide(value));
    let directory = request.directory.as_ref().map(|value| wide(value));
    let operation = request.operation.as_ref().map(|value| wide(value));

    let result = unsafe {
        ShellExecuteW(
            HWND::default(),
            option_to_pcwstr(operation.as_ref()),
            PCWSTR(file.as_ptr()),
            option_to_pcwstr(parameters.as_ref()),
            option_to_pcwstr(directory.as_ref()),
            request.show,
        )
    };

    let code = result.0 as isize;
    if code <= 32 {
        Err(format!("ShellExecuteW 返回错误码 {code}"))
    } else {
        Ok(())
    }
}

fn split_parentheses(segment: &str) -> Option<String> {
    let mut chars = segment.chars().enumerate();
    let mut in_string = false;
    let mut buffer = String::new();

    while let Some((idx, ch)) = chars.next() {
        if idx == 0 {
            if ch != '(' {
                return None;
            }
            continue;
        }

        match ch {
            '"' => {
                buffer.push(ch);
                if in_string {
                    if let Some((_, next)) = chars.clone().next() {
                        if next == '"' {
                            // Escaped quote
                            chars.next();
                            buffer.push('"');
                        } else {
                            in_string = false;
                        }
                    } else {
                        in_string = false;
                    }
                } else {
                    in_string = true;
                }
            }
            ')' if !in_string => {
                return Some(buffer);
            }
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

fn join_forwarded_args(args: &[OsString]) -> String {
    let mut rendered = Vec::new();
    for arg in args {
        rendered.push(quote_argument(arg));
    }
    rendered.join(" ")
}

fn quote_argument(arg: &OsStr) -> String {
    let value = arg.to_string_lossy();
    if value.is_empty() {
        return "\"\"".to_string();
    }

    let needs_quotes = value.chars().any(|ch| ch.is_whitespace() || ch == '"');
    if !needs_quotes {
        return value.into_owned();
    }

    let mut result = String::from('"');
    let mut backslashes = 0;
    for ch in value.chars() {
        match ch {
            '\\' => {
                backslashes += 1;
            }
            '"' => {
                result.push_str(&"\\".repeat(backslashes * 2 + 1));
                result.push('"');
                backslashes = 0;
            }
            _ => {
                if backslashes > 0 {
                    result.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                }
                result.push(ch);
            }
        }
    }

    if backslashes > 0 {
        result.push_str(&"\\".repeat(backslashes * 2));
    }

    result.push('"');
    result
}

fn option_to_pcwstr(value: Option<&Vec<u16>>) -> PCWSTR {
    if let Some(buffer) = value {
        PCWSTR(buffer.as_ptr())
    } else {
        PCWSTR::null()
    }
}

fn wide(input: &str) -> Vec<u16> {
    OsStr::new(input).encode_wide().chain(Some(0)).collect()
}
