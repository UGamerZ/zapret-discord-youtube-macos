#pragma once
// Launch without a controlling console. Returns only after exec succeeds or
// reports a concrete error; pid_path is optional and written before exec.
int mac_launch_detached(const char *executable, char *const arguments[], const char *log_path, const char *pid_path);
