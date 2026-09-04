#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace stellar::service {

// These are observations, not assertions supplied by the caller.  The real
// Windows adapter must obtain them from handles opened with reparse traversal
// disabled.  Keeping the observation seam explicit makes the hostile cases
// hermetic and prevents an unavailable observer from becoming a fallback.
struct ProtectedInstalledArtifactFacts {
  bool opened{};
  bool regularFile{};
  bool fileReparsePoint{};
  bool ancestorReparsePoint{};
  bool stableFileIdentity{};
  bool writeSharingDenied{};
  std::uint64_t byteCount{};
  std::string owner;
  std::vector<std::string> mutationPrincipals;
};

class ProtectedInstalledArtifactFilesystem {
public:
  virtual ~ProtectedInstalledArtifactFilesystem() = default;
  virtual bool ReadExact(const std::wstring &absolutePath,
                         std::size_t maximumBytes,
                         std::vector<unsigned char> &bytes,
                         ProtectedInstalledArtifactFacts &facts) const = 0;
};

class ProtectedInstalledArtifactIdentity {
public:
  virtual ~ProtectedInstalledArtifactIdentity() = default;
  virtual bool IsExpectedOwner(const std::string &owner) const = 0;
  virtual bool IsAllowedMutationPrincipal(const std::string &principal) const = 0;
};

struct ProtectedInstalledArtifactPath {
  std::wstring policyEnvelopePath;
  std::wstring requestSignerRegistryPath;
};

enum class ProtectedInstalledArtifactStatus {
  accepted,
  invalid_path,
  unavailable,
  too_large,
  hostile_file_state,
  owner_refused,
  acl_refused,
  noncanonical,
};

// Reads only an explicitly configured absolute file.  Every filesystem and
// identity observation must be affirmative, the content is size-bounded, and
// parser acceptance is mandatory.  There is intentionally no path default,
// memory substitute, or partial-read success state.
ProtectedInstalledArtifactStatus ReadProtectedInstalledArtifact(
    const std::wstring &absolutePath, std::size_t maximumBytes,
    const ProtectedInstalledArtifactFilesystem &filesystem,
    const ProtectedInstalledArtifactIdentity &identity,
    bool (*canonicalValidator)(const std::vector<unsigned char> &),
    std::vector<unsigned char> &canonicalBytes);

ProtectedInstalledArtifactStatus ReadProtectedCustodianPolicyEnvelope(
    const ProtectedInstalledArtifactPath &paths,
    const ProtectedInstalledArtifactFilesystem &filesystem,
    const ProtectedInstalledArtifactIdentity &identity,
    std::vector<unsigned char> &canonicalEnvelope);

ProtectedInstalledArtifactStatus ReadProtectedRequestSignerRegistry(
    const ProtectedInstalledArtifactPath &paths,
    const ProtectedInstalledArtifactFilesystem &filesystem,
    const ProtectedInstalledArtifactIdentity &identity,
    std::vector<unsigned char> &canonicalRegistry);

} // namespace stellar::service
