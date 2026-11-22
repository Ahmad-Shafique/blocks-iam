using Blocks.Genesis.Entities.Iam;

namespace Authentication.DomainService.Shared.Services
{
    /// <summary>
    /// The <c>TrustEmail</c> flag of an identity provider: may a sign-in from this provider be matched to an existing
    /// Blocks account by email alone, when its external identity (issuer + subject) is not linked to any account yet?
    /// </summary>
    /// <remarks>
    /// <para>
    /// The flag has three states, and the third one is what keeps this change migration-free:
    /// <list type="bullet">
    /// <item><c>true</c>: the email is trusted for linking.</item>
    /// <item><c>false</c>: it is not; only a linked external identity signs an existing account in.</item>
    /// <item>never set: every provider saved before the flag existed. It keeps today's behaviour, which is
    /// <see cref="LegacyDefault"/> (the email match). The owner decides whether that changes (I06-WP1 owner item).</item>
    /// </list>
    /// A provider created from now on is stamped <c>false</c> unless its creator says otherwise
    /// (<see cref="StampNewProviderDefault"/>), so only new providers get the stricter default.
    /// </para>
    /// <para>
    /// Where it is kept: <see cref="IdentityProvider"/> is a Genesis package class, so a typed property needs a Genesis
    /// release first. Until then the flag is one marker in the provider's <c>Tags</c>, which every read and the
    /// whole-document replace on update already carry, so an admin edit can never drop it. When Genesis gains a typed
    /// <c>bool? TrustEmail</c>, only this class changes.
    /// </para>
    /// </remarks>
    public static class IdentityProviderEmailTrust
    {
        public const string TrustedTag = "trust-email:true";
        public const string UntrustedTag = "trust-email:false";

        /// <summary>
        /// The answer for a provider whose flag was never set: today's behaviour, the email match. OWNER ITEM (I06-WP1):
        /// changing this to <c>false</c> switches every existing provider to identity-only linking at once.
        /// </summary>
        public const bool LegacyDefault = true;

        /// <summary>The stored flag, or null when it was never set.</summary>
        public static bool? Read(IdentityProvider? provider)
        {
            var tags = provider?.Tags;
            if (tags == null || tags.Count == 0)
            {
                return null;
            }

            // Both present can only come from a hand edit; the stricter one wins.
            if (tags.Contains(UntrustedTag, StringComparer.OrdinalIgnoreCase))
            {
                return false;
            }

            return tags.Contains(TrustedTag, StringComparer.OrdinalIgnoreCase) ? true : null;
        }

        /// <summary>
        /// Whether the email may be used to find an existing account. A provider that could not be looked up is
        /// treated like one whose flag was never set, so no sign-in path changes behaviour by accident.
        /// </summary>
        public static bool IsEmailTrusted(IdentityProvider? provider) => Read(provider) ?? LegacyDefault;

        /// <summary>Sets the flag, replacing any earlier marker.</summary>
        public static void Set(IdentityProvider provider, bool trustEmail)
        {
            ArgumentNullException.ThrowIfNull(provider);
            provider.Tags ??= [];
            provider.Tags.RemoveAll(IsTrustTag);
            provider.Tags.Add(trustEmail ? TrustedTag : UntrustedTag);
        }

        /// <summary>A new provider without an explicit flag gets <c>false</c>. One with a flag keeps it.</summary>
        public static void StampNewProviderDefault(IdentityProvider provider)
        {
            ArgumentNullException.ThrowIfNull(provider);
            if (Read(provider) == null)
            {
                Set(provider, false);
            }
        }

        private static bool IsTrustTag(string tag) =>
            string.Equals(tag, TrustedTag, StringComparison.OrdinalIgnoreCase)
            || string.Equals(tag, UntrustedTag, StringComparison.OrdinalIgnoreCase);
    }
}
