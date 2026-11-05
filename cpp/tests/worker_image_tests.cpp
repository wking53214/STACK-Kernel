// Worker image trust (R2-K-21). The supervisor executes a worker image on
// behalf of a caller that does not trust the worker, so it has to be sure
// which program it is about to run:
//
//   - a symlink is refused (a final component by O_NOFOLLOW, any component by
//     openat2 RESOLVE_NO_SYMLINKS);
//   - an image that is setuid, setgid, group-writable or world-writable is
//     refused;
//   - the child sets PR_SET_NO_NEW_PRIVS before it execs, so even an unpinned
//     image cannot gain privilege through exec;
//   - a configuration may pin the image's SHA-256. The supervisor then reads
//     the open descriptor, hashes what it read, and executes a sealed copy of
//     exactly those bytes, so a swap of the file after the check changes
//     nothing and a program that is not the pinned one never runs.
//
// The cases that need only the previous API are first; the digest cases need
// WorkerSpec::expected_sha256 and are compiled out with
// -DSTACK_IMAGE_TESTS_POLICY_ONLY (used to show the policy cases failing on
// the code before the fix).
#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../include/stack_supervised_exec.hpp"

using namespace stack::supervised;

#ifndef STACK_WORKER_PATH
#error "STACK_WORKER_PATH must name the shipped worker program"
#endif
#ifndef STACK_WORKER_TEST_PATH
#error "STACK_WORKER_TEST_PATH must name the test worker program"
#endif
#ifndef STACK_PROBE_NNP_PATH
#error "STACK_PROBE_NNP_PATH must name the NO_NEW_PRIVS probe"
#endif

namespace {

constexpr uint64_t kMs = 1'000'000ULL;
constexpr const char* kShippedBytes = "stack-ffi-payload-v1";

struct TempDir {
    char path[64];
    TempDir() {
        std::snprintf(path, sizeof path, "/tmp/stack_img_XXXXXX");
        REQUIRE(::mkdtemp(path) != nullptr);
    }
    ~TempDir() {
        const std::string cmd = std::string("rm -rf ") + path;
        (void)std::system(cmd.c_str());
    }
    std::string In(const char* name) const { return std::string(path) + "/" + name; }
};

bool ReadAll(const char* path, std::vector<uint8_t>& out) {
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    uint8_t buf[65536];
    ssize_t n;
    out.clear();
    while ((n = ::read(fd, buf, sizeof buf)) > 0) out.insert(out.end(), buf, buf + n);
    ::close(fd);
    return n == 0;
}

// Writes `bytes` to `path` in place (same inode), creating it with `mode`.
bool WriteInPlace(const char* path, const std::vector<uint8_t>& bytes, mode_t mode) {
    const int fd = ::open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) return false;
    std::size_t off = 0;
    while (off < bytes.size()) {
        const ssize_t w = ::write(fd, bytes.data() + off, bytes.size() - off);
        if (w <= 0) { ::close(fd); return false; }
        off += static_cast<std::size_t>(w);
    }
    ::close(fd);
    return ::chmod(path, mode) == 0;
}

std::string CopyOf(const char* src, const std::string& dst, mode_t mode) {
    std::vector<uint8_t> bytes;
    REQUIRE(ReadAll(src, bytes));
    REQUIRE(WriteInPlace(dst.c_str(), bytes, mode));
    return dst;
}

struct Outcome1 {
    ExecutionReport report;
    uint8_t out[64]{};
    std::string Text() const {
        return std::string(reinterpret_cast<const char*>(out), report.outcome == Outcome::Completed ? report.result_length : 0);
    }
};

Outcome1 Run(const char* path, const uint8_t* digest = nullptr) {
    Outcome1 r;
    Limits l;
    l.wall_clock_deadline_ns = 2'000 * kMs;
    l.max_output_bytes = sizeof r.out;
    WorkerSpec spec;
    spec.executable = path;
    spec.kind = 0;
#ifndef STACK_IMAGE_TESTS_POLICY_ONLY
    spec.expected_sha256 = digest;
#else
    (void)digest;
#endif
    r.report = SupervisedExecutor::RunWorker(l, spec, r.out, sizeof r.out);
    return r;
}

void RequireRefused(const Outcome1& r, int err) {
    REQUIRE(r.report.outcome == Outcome::SpawnFailed);
    REQUIRE(r.report.error_number == err);
    REQUIRE(r.report.child_pid == 0);
}

}  // namespace

TEST_CASE("Image: a plain copy of the worker still runs (control)", "[image]") {
    TempDir d;
    const std::string p = CopyOf(STACK_WORKER_PATH, d.In("worker"), 0755);
    const Outcome1 r = Run(p.c_str());
    REQUIRE(r.report.outcome == Outcome::Completed);
    REQUIRE(r.Text() == kShippedBytes);
}

TEST_CASE("Image: a symlink is refused, as the final component and as a directory component", "[image][symlink]") {
    TempDir d;
    const std::string real = CopyOf(STACK_WORKER_PATH, d.In("worker"), 0755);
    const std::string link = d.In("link");
    REQUIRE(::symlink(real.c_str(), link.c_str()) == 0);
    RequireRefused(Run(link.c_str()), ELOOP);

    const std::string dir = d.In("realdir");
    REQUIRE(::mkdir(dir.c_str(), 0755) == 0);
    CopyOf(STACK_WORKER_PATH, dir + "/worker", 0755);
    const std::string dirlink = d.In("dirlink");
    REQUIRE(::symlink(dir.c_str(), dirlink.c_str()) == 0);
    const std::string via = dirlink + "/worker";
    RequireRefused(Run(via.c_str()), ELOOP);
    // The same image by its real path runs.
    const std::string direct = dir + "/worker";
    REQUIRE(Run(direct.c_str()).report.outcome == Outcome::Completed);
}

TEST_CASE("Image: group-writable, world-writable, setuid and setgid images are refused", "[image][mode]") {
    TempDir d;
    for (const mode_t mode : {mode_t{0775}, mode_t{0757}, mode_t{0777}, mode_t{04755}, mode_t{02755}, mode_t{06755}}) {
        const std::string p = CopyOf(STACK_WORKER_PATH, d.In("worker"), mode);
        INFO("mode " << std::oct << mode);
        struct stat st{};
        REQUIRE(::stat(p.c_str(), &st) == 0);
        REQUIRE((st.st_mode & 07777) == mode);  // the mode really was applied
        RequireRefused(Run(p.c_str()), EACCES);
        ::unlink(p.c_str());
    }
}

TEST_CASE("Image: the worker is exec'd with NO_NEW_PRIVS already set", "[image][nnp]") {
    // The probe installs no filter and reports PR_GET_NO_NEW_PRIVS as it
    // starts. Before the fix the supervisor did not set it (only the worker
    // did, inside its own main), so an unpinned image could exec setuid
    // helpers' privilege rules.
    const Outcome1 r = Run(STACK_PROBE_NNP_PATH);
    REQUIRE(r.report.outcome == Outcome::Completed);
    REQUIRE(r.Text() == "1");
}

#ifndef STACK_IMAGE_TESTS_POLICY_ONLY

namespace {

void DigestOf(const char* path, uint8_t (&out)[32]) { REQUIRE(SupervisedExecutor::Sha256OfFile(path, out) == 0); }

std::string Hex(const uint8_t (&d)[32]) {
    char buf[65];
    for (int i = 0; i < 32; ++i) std::snprintf(buf + 2 * i, 3, "%02x", d[i]);
    return std::string(buf, 64);
}

std::string Sha256sumTool(const char* path) {
    const std::string cmd = std::string("sha256sum ") + path;
    FILE* f = ::popen(cmd.c_str(), "r");
    REQUIRE(f != nullptr);
    char line[256] = {};
    REQUIRE(std::fgets(line, sizeof line, f) != nullptr);
    ::pclose(f);
    return std::string(line, 64);
}

#ifdef STACK_SUPERVISED_TESTING
// The swap seam: runs after the image was opened and verified, before the
// fork. It replaces the file's content IN PLACE (same inode, so a descriptor
// that merely holds the file would execute the new bytes) with the probe.
const char* g_swap_target = nullptr;
bool g_swap_by_rename = false;
std::vector<uint8_t> g_swap_bytes;
void SwapImage(const char*) {
    if (g_swap_by_rename) {
        const std::string tmp = std::string(g_swap_target) + ".new";
        REQUIRE(WriteInPlace(tmp.c_str(), g_swap_bytes, 0755));
        REQUIRE(::rename(tmp.c_str(), g_swap_target) == 0);
    } else {
        REQUIRE(WriteInPlace(g_swap_target, g_swap_bytes, 0755));
    }
}
#endif

}  // namespace

TEST_CASE("Image: SHA-256 matches the known vectors and sha256sum", "[image][sha256]") {
    uint8_t d[32];
    SupervisedExecutor::Sha256(reinterpret_cast<const uint8_t*>(""), 0, d);
    REQUIRE(Hex(d) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    SupervisedExecutor::Sha256(reinterpret_cast<const uint8_t*>("abc"), 3, d);
    REQUIRE(Hex(d) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const char* two_block = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    SupervisedExecutor::Sha256(reinterpret_cast<const uint8_t*>(two_block), std::strlen(two_block), d);
    REQUIRE(Hex(d) == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    // A file longer than one read buffer, against the system tool.
    DigestOf(STACK_WORKER_PATH, d);
    REQUIRE(Hex(d) == Sha256sumTool(STACK_WORKER_PATH));
    DigestOf(STACK_WORKER_TEST_PATH, d);
    REQUIRE(Hex(d) == Sha256sumTool(STACK_WORKER_TEST_PATH));
}

TEST_CASE("Image: a pinned image with the right digest runs; a wrong digest is refused with nothing spawned", "[image][digest]") {
    uint8_t good[32];
    DigestOf(STACK_WORKER_PATH, good);
    const Outcome1 ok = Run(STACK_WORKER_PATH, good);
    REQUIRE(ok.report.outcome == Outcome::Completed);
    REQUIRE(ok.Text() == kShippedBytes);

    uint8_t bad[32];
    std::memcpy(bad, good, 32);
    bad[31] ^= 1;
    RequireRefused(Run(STACK_WORKER_PATH, bad), EKEYREJECTED);
    // The other worker build has another digest.
    uint8_t other[32];
    DigestOf(STACK_WORKER_TEST_PATH, other);
    RequireRefused(Run(STACK_WORKER_PATH, other), EKEYREJECTED);
    // CheckWorkerImage agrees.
    REQUIRE(SupervisedExecutor::CheckWorkerImage(STACK_WORKER_PATH, good) == 0);
    REQUIRE(SupervisedExecutor::CheckWorkerImage(STACK_WORKER_PATH, bad) == EKEYREJECTED);
}

TEST_CASE("Image: a non-worker binary (touch) is not run when the worker's digest is pinned", "[image][digest]") {
    TempDir d;
    // Copy touch into a directory we own so the owner/mode checks pass; only
    // the digest stands between it and execution.
    const std::string touch = CopyOf("/usr/bin/touch", d.In("touch"), 0755);
    uint8_t worker_digest[32];
    DigestOf(STACK_WORKER_PATH, worker_digest);
    const std::string marker = d.In("marker");
    Limits l;
    l.wall_clock_deadline_ns = 2'000 * kMs;
    l.max_output_bytes = 16;
    uint8_t out[16];
    WorkerSpec spec;
    spec.executable = touch.c_str();
    spec.kind = 0;
    spec.argument = marker.c_str();
    spec.expected_sha256 = worker_digest;
    const ExecutionReport r = SupervisedExecutor::RunWorker(l, spec, out, sizeof out);
    REQUIRE(r.outcome == Outcome::SpawnFailed);
    REQUIRE(r.error_number == EKEYREJECTED);
    REQUIRE(r.child_pid == 0);
    REQUIRE(::access(marker.c_str(), F_OK) != 0);
}

#ifdef STACK_SUPERVISED_TESTING
TEST_CASE("Image: a pinned image swapped after the check still runs the verified bytes", "[image][digest][swap]") {
    TempDir d;
    const std::string p = CopyOf(STACK_WORKER_PATH, d.In("worker"), 0755);
    uint8_t digest[32];
    DigestOf(p.c_str(), digest);
    REQUIRE(ReadAll(STACK_PROBE_NNP_PATH, g_swap_bytes));
    g_swap_target = p.c_str();

    for (const bool by_rename : {false, true}) {
        INFO(std::string(by_rename ? "swap by rename" : "swap in place (same inode)"));
        g_swap_by_rename = by_rename;
        // The swap really happens: the path now holds the probe.
        SupervisedExecutor::SetImageCheckedHookForTesting(&SwapImage);
        const Outcome1 r = Run(p.c_str(), digest);
        SupervisedExecutor::SetImageCheckedHookForTesting(nullptr);
        REQUIRE(r.report.outcome == Outcome::Completed);
        // The verified worker ran ("stack-ffi-payload-v1"), not the probe ("1").
        REQUIRE(r.Text() == kShippedBytes);
        uint8_t now[32];
        DigestOf(p.c_str(), now);
        REQUIRE(std::memcmp(now, digest, 32) != 0);  // the path did change
        CopyOf(STACK_WORKER_PATH, p, 0755);          // restore for the next round
    }
}

TEST_CASE("Image: the same swap with no digest pinned runs the swapped bytes (documents the unpinned mode)", "[image][swap]") {
    // Unpinned, the descriptor opened before the fork is what executes, so a
    // rename after the open changes nothing, but a write into the same inode
    // does. That is why a deployment pins the digest.
    TempDir d;
    const std::string p = CopyOf(STACK_WORKER_PATH, d.In("worker"), 0755);
    REQUIRE(ReadAll(STACK_PROBE_NNP_PATH, g_swap_bytes));
    g_swap_target = p.c_str();
    g_swap_by_rename = true;
    SupervisedExecutor::SetImageCheckedHookForTesting(&SwapImage);
    const Outcome1 renamed = Run(p.c_str());
    SupervisedExecutor::SetImageCheckedHookForTesting(nullptr);
    REQUIRE(renamed.report.outcome == Outcome::Completed);
    REQUIRE(renamed.Text() == kShippedBytes);  // the opened inode ran
}
#endif

#endif  // STACK_IMAGE_TESTS_POLICY_ONLY
