#include "protected_installed_artifact.h"

#include "canonical_json.h"
#include <algorithm>
#include <string_view>

namespace stellar::service {
namespace {
constexpr std::size_t kMaximumPolicyEnvelopeBytes = 64U * 1024U;
constexpr std::size_t kMaximumRequestSignerRegistryBytes = 1024U * 1024U;

bool AbsoluteFilePath(const std::wstring &path) {
  // A device/UNC namespace can bypass an installer root policy.  The future
  // Windows adapter is responsible for additionally checking every ancestor.
  return path.size() >= 4 && path[1] == L':' &&
         (path[2] == L'\\' || path[2] == L'/') &&
         path.find(L"..") == std::wstring::npos &&
         path.rfind(L"\\\\?\\", 0) != 0 && path.rfind(L"\\\\.\\", 0) != 0;
}

bool PolicyEnvelopeCanonical(const std::vector<unsigned char> &bytes) {
  if (bytes.empty()) return false;
  const std::string text(bytes.begin(), bytes.end());
  return json::ParseCanonicalCustodianGatewayPolicy(text).accepted;
}

bool RegistryCanonical(const std::vector<unsigned char> &bytes) {
  if (bytes.empty()) return false;
  const std::string text(bytes.begin(), bytes.end());
  return json::ParseCanonicalRequestSignerRegistry(text).accepted;
}
} // namespace

ProtectedInstalledArtifactStatus ReadProtectedInstalledArtifact(
    const std::wstring &absolutePath, std::size_t maximumBytes,
    const ProtectedInstalledArtifactFilesystem &filesystem,
    const ProtectedInstalledArtifactIdentity &identity,
    bool (*canonicalValidator)(const std::vector<unsigned char> &),
    std::vector<unsigned char> &canonicalBytes) {
  canonicalBytes.clear();
  if (!AbsoluteFilePath(absolutePath) || maximumBytes == 0 || !canonicalValidator)
    return ProtectedInstalledArtifactStatus::invalid_path;
  ProtectedInstalledArtifactFacts facts;
  std::vector<unsigned char> candidate;
  if (!filesystem.ReadExact(absolutePath, maximumBytes, candidate, facts) || !facts.opened)
    return ProtectedInstalledArtifactStatus::unavailable;
  if (candidate.size() > maximumBytes || facts.byteCount != candidate.size())
    return ProtectedInstalledArtifactStatus::too_large;
  if (!facts.regularFile || facts.fileReparsePoint || facts.ancestorReparsePoint ||
      !facts.stableFileIdentity || !facts.writeSharingDenied)
    return ProtectedInstalledArtifactStatus::hostile_file_state;
  if (!identity.IsExpectedOwner(facts.owner))
    return ProtectedInstalledArtifactStatus::owner_refused;
  if (facts.mutationPrincipals.empty() ||
      std::any_of(facts.mutationPrincipals.begin(), facts.mutationPrincipals.end(),
                  [&identity](const std::string &principal) {
                    return principal.empty() ||
                           !identity.IsAllowedMutationPrincipal(principal);
                  }))
    return ProtectedInstalledArtifactStatus::acl_refused;
  if (!canonicalValidator(candidate))
    return ProtectedInstalledArtifactStatus::noncanonical;
  canonicalBytes = std::move(candidate);
  return ProtectedInstalledArtifactStatus::accepted;
}

ProtectedInstalledArtifactStatus ReadProtectedCustodianPolicyEnvelope(
    const ProtectedInstalledArtifactPath &paths,
    const ProtectedInstalledArtifactFilesystem &filesystem,
    const ProtectedInstalledArtifactIdentity &identity,
    std::vector<unsigned char> &canonicalEnvelope) {
  return ReadProtectedInstalledArtifact(paths.policyEnvelopePath,
                                        kMaximumPolicyEnvelopeBytes, filesystem,
                                        identity, PolicyEnvelopeCanonical,
                                        canonicalEnvelope);
}

ProtectedInstalledArtifactStatus ReadProtectedRequestSignerRegistry(
    const ProtectedInstalledArtifactPath &paths,
    const ProtectedInstalledArtifactFilesystem &filesystem,
    const ProtectedInstalledArtifactIdentity &identity,
    std::vector<unsigned char> &canonicalRegistry) {
  return ReadProtectedInstalledArtifact(paths.requestSignerRegistryPath,
                                        kMaximumRequestSignerRegistryBytes,
                                        filesystem, identity, RegistryCanonical,
                                        canonicalRegistry);
}

} // namespace stellar::service
