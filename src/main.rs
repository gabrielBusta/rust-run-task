use std::fs::{self, remove_dir_all, remove_file};
use std::io::{self, Write};
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;
#[cfg(unix)]

const SECRET_BASEURL_TPL: &str = "http://taskcluster/secrets/v1/secret/{}";

const GITHUB_SSH_FINGERPRINT: &[u8] = b"github.com ssh-rsa \
AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY\
4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDP\
gVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyR\
kQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWO\
WRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZ\
yaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+\
2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=\n";

const CACHE_UID_GID_MISMATCH: &str = r#"
There is a UID/GID mismatch on the cache. This likely means:

a) different tasks are running as a different user/group
b) different Docker images have different UID/GID for the same user/group

Our cache policy is that the UID/GID for ALL tasks must be consistent
for the lifetime of the cache. This eliminates permissions problems due
to file/directory user/group ownership.

To make this error go away, ensure that all Docker images are use
a consistent UID/GID and that all tasks using this cache are running as
the same user/group.
"#;

const NON_EMPTY_VOLUME: &str = r#"
error: volume %s is not empty

Our Docker image policy requires volumes to be empty.

The volume was likely populated as part of building the Docker image.
Change the Dockerfile and anything run from it to not create files in
any VOLUME.

A lesser possibility is that you stumbled upon a TaskCluster platform bug
where it fails to use new volumes for tasks.
"#;

const FETCH_CONTENT_NOT_FOUND: &str = r#"
error: fetch-content script not found

The script at `taskcluster/scripts/misc/fetch-content` could not be
detected in the current environment.
"#;

const EXIT_PURGE_CACHE: i32 = 72;

const IS_MACOSX: bool = cfg!(target_os = "macos");
const IS_POSIX: bool = cfg!(unix);
const IS_WINDOWS: bool = cfg!(target_os = "windows");

const NULL_REVISION: &str = "0000000000000000000000000000000000000000";

fn print_line(prefix: &str, m: &str) -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Time went backwards")?;
    let in_ms = now.as_secs() * 1000 + now.subsec_millis() as u64;
    let now = format!("{:?}", in_ms);
    let now = &now[0..now.len() - 3]; // slice milliseconds to 3 decimals

    print!("[{} {}Z] {}\n", prefix, now, m);
    io::stdout().flush()?;
    Ok(())
}

fn call_windows_retry<F, P: AsRef<Path>>(
    func_name: &str,
    func: F,
    path: P,
    retry_max: u32,
    retry_delay: u64,
) -> io::Result<()>
where
    F: Fn(&P) -> io::Result<()>,
{
    let mut retry_count = 0;
    loop {
        match func(&path) {
            Err(e) => match e.kind() {
                io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound => {
                    if retry_count == retry_max {
                        return Err(io::Error::new(
                            e.kind(),
                            "Maximum number of retries reached",
                        ));
                    }
                    retry_count += 1;
                    println!(
                        "{}() failed for \"{:?}\". Reason: {} ({:?}). Retrying...",
                        func_name,
                        path.as_ref(),
                        e,
                        e.kind()
                    );
                    sleep(Duration::from_secs(retry_count as u64 * retry_delay));
                }
                _ => return Err(e),
            },
            Ok(_) => break,
        }
    }
    Ok(())
}

fn update_permissions<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref();
    let metadata = fs::metadata(&path)?;
    let mut permissions = metadata.permissions();

    if permissions.readonly() {
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions)?;
    }

    Ok(())
}

#[cfg(target_family = "windows")]
fn long_path_name<P: AsRef<Path>>(path: P) -> io::Result<String> {
    use std::ptr;
    use widestring::U16CString;
    use winapi::um::fileapi::GetFullPathNameW;

    let path_str = path.as_ref().to_string_lossy().to_string();

    // Convert path to wide string
    let wide_path = U16CString::from_str(&path_str)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Failed to create wide string"))?;

    // Query for the required buffer size
    let size_needed =
        unsafe { GetFullPathNameW(wide_path.as_ptr(), 0, ptr::null_mut(), ptr::null_mut()) };
    if size_needed == 0 {
        return Err(io::Error::last_os_error());
    }

    // Create a wide string buffer
    let mut wide_buffer: Vec<u16> = vec![0; size_needed as usize];

    // Call again with a buffer to store the result
    let result = unsafe {
        GetFullPathNameW(
            wide_path.as_ptr(),
            wide_buffer.len() as u32,
            wide_buffer.as_mut_ptr(),
            ptr::null_mut(),
        )
    };

    if result == 0 {
        return Err(io::Error::last_os_error());
    }

    // Convert wide buffer to string
    let result_path = U16CString::from_vec_with_nul(wide_buffer)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to read wide string"))?
        .to_string_lossy()
        .to_string();

    Ok(result_path)
}

#[cfg(not(target_family = "windows"))]
fn long_path_name<P: AsRef<Path>>(path: P) -> io::Result<String> {
    Ok(path.as_ref().to_string_lossy().to_string())
}

pub fn remove<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = long_path_name(path)?;
    let path = Path::new(&path);

    // specify the maximum number of retries and the delay between retries
    let retry_max = 5;
    let retry_delay = 500; // This is in milliseconds

    if !path.exists() {
        println!("WARNING: {} does not exists!", path.display());
        return Ok(());
    }

    if path.is_file() || path.symlink_metadata()?.file_type().is_symlink() {
        update_permissions(&path)?;
        call_windows_retry("remove_file", remove_file, path, retry_max, retry_delay)?;
    } else if path.is_dir() {
        update_permissions(&path)?;

        for entry in WalkDir::new(&path).into_iter().filter_map(|e| e.ok()) {
            update_permissions(entry.path())?;
        }

        call_windows_retry(
            "remove_dir_all",
            remove_dir_all,
            path,
            retry_max,
            retry_delay,
        )?;
    }
    Ok(())
}

fn main() {
    match print_line("prefix", "message") {
        Ok(()) => (),
        Err(e) => eprintln!("Error: {}", e),
    }
}
