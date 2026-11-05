// A test-only worker image that installs NO seccomp filter and reports
// whether PR_SET_NO_NEW_PRIVS was already set when it started. It is how
// cpp/tests/worker_image_tests.cpp observes what the supervisor did to the
// process before exec (R2-K-21). Never a production worker.
#include <cstdint>
#include <sys/prctl.h>
#include "../include/stack_supervised_exec.hpp"

int main() {
    const int nnp = ::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    const uint8_t body = static_cast<uint8_t>(nnp == 1 ? '1' : '0');
    if (!stack::supervised::SupervisedExecutor::WriteResultFrame(stack::supervised::kWorkerResultFd, &body, 1)) return 127;
    return 0;
}
