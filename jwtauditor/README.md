# JWT Auditor - Burp Suite Extension

## Overview

**JWT Auditor** is a comprehensive JWT (JSON Web Token) security testing extension for Burp Suite. This extension provides penetration testers with professional-grade JWT vulnerability detection, exploitation tools, and attack simulation capabilities directly within Burp Suite.

## Key Features

### 🔓 Tab 1: Decoder
- Parse and display JWT tokens in 4 resizable sections
- Shows header (algorithm, type, key ID, JWKS URL)
- Shows payload (user data, claims, permissions)
- Shows signature (Base64URL encoded)
- Shows token info (expiration, issued time, age)
- **Resizable components**: Drag dividers to adjust section sizes

### 🔍 Tab 2: Analyzer (15+ Vulnerability Checks)
- **🔴 CRITICAL**: none algorithm, missing expiration, JKU/X5U SSRF, KID injection
- **🟠 HIGH**: Weak HMAC, sensitive data, long expiration, weak secrets
- **🟡 MEDIUM**: Missing claims, timestamp issues, replay attacks, algorithm confusion
- **🟢 LOW**: Missing JWT ID, non-standard algorithms, header validation
- Resizable findings table - drag column headers to resize
- Color-coded severity levels with explanations

### ⚡ Tab 3: Bruteforcer
- Tests 1000+ common JWT secrets
- Works with HMAC algorithms (HS256, HS384, HS512)
- Real-time progress tracking
- Stop/pause functionality
- Finds secret in seconds for weak passwords

### ⚔️ Tab 4: Attacks (7 Modules, 68+ Payloads)

#### Attack 1: None Algorithm Bypass
- Changes algorithm to 'none' (complete signature bypass)
- Allows modifying any JWT claim without valid signature
- Works if server doesn't validate algorithm type

#### Attack 2: Algorithm Confusion (14+ variants)
- Confuses server about signing algorithm
- RS256 → HS256 confusion attacks
- Tries HS256, HS384, HS512, lowercase variants
- If server uses public key as HMAC secret = token forgery

#### Attack 3: KID Injection (47+ payloads)
- SQL injection in key ID parameter
- Path traversal attacks
- Command injection payloads
- LDAP injection patterns
## Installation & Usage

### Step 1: Download JAR File
```
JWTAuditor.jar (47.4 KB)
Location: c:\Users\navee\OneDrive\Documents\New-projects\jwtauditor\
```

### Step 2: Load in Burp Suite
1. Open Burp Suite
2. Go to **Extender → Extensions**
3. Click **Add**
4. Select **JWTAuditor.jar**
5. Extension loads automatically

### Step 3: Start Testing
1. **Decoder Tab**: Paste JWT and click "Decode JWT"
2. **Analyzer Tab**: Click "Analyze Current Token"
3. **Bruteforcer Tab**: If HMAC found, click "Start Bruteforce"
4. **Attacks Tab**: Generate exploitation payloads
5. **Help Tab**: Read detailed explanations

## Tab-by-Tab Guide

### Decoder Tab
- Paste JWT token in input field
- Click "🔓 Decode JWT"
- View 4 resizable sections:
  - Header: Algorithm, type, key ID, JWKS URL
  - Payload: User data, claims, permissions
  - Signature: Base64URL encoded
  - Info: Expiration, token age, claim count
- **Drag dividers to resize sections**

### Analyzer Tab
- Click "🔎 Analyze Current Token"
- Finds 15+ security vulnerabilities
- Results in resizable findings table
- **Drag column headers to resize columns**
- Color-coded by severity:
  - 🔴 CRITICAL: Immediate exploitation
  - 🟠 HIGH: Likely exploitable
  - 🟡 MEDIUM: Potentially exploitable
  - 🟢 LOW: Minor issues

### Bruteforcer Tab
- Works with HS256, HS384, HS512 only
- Click "▶️ Start Bruteforce"
- Tests 1000+ common secrets
- Shows real-time progress
- If secret found: "🎉 SECRET FOUND!"
- Click "⏸️ Stop" to pause

### Attacks Tab
- 7 specialized attack modules
- Each button explains the attack
- Shows:
  - WHAT IT DOES (purpose)
  - HOW IT WORKS (mechanics)
  - WHEN IT WORKS (conditions)
  - IMPACT (severity level)
  - HOW TO TEST (step-by-step)
- Copy generated tokens to test

### Editor Tab
- Manually create JWT tokens
- Edit header JSON
- Edit payload claims
- Enter HMAC secret
- Click "Generate JWT"
- Copy token to clipboard

### Help & Info Tab (Last Tab)
- Complete user guide
- All vulnerabilities explained
- Real-world examples
- Penetration testing workflow
- Security best practices

## Vulnerability Categories

### 🔴 CRITICAL (Immediate Exploitation)
```
✓ None Algorithm ('alg': 'none')
✓ Missing Expiration (no 'exp' claim)
✓ Dynamic JKU/X5U URLs (SSRF)
✓ KID Parameter Injection (SQL, path traversal)
```

### 🟠 HIGH (Likely Exploitable)
```
✓ Weak HMAC Algorithm (HS256/384/512)
✓ Sensitive Data Exposure (PII, email, API keys)
✓ Long Expiration (> 30 days)
✓ Weak Secret Vulnerability (common passwords)
```

### 🟡 MEDIUM (Potentially Exploitable)
```
✓ Missing Recommended Claims (iss, aud, jti)
✓ Timestamp Validation Issues
✓ Replay Attack Risk (no unique ID)
✓ Algorithm Confusion Risk
```

### 🟢 LOW (Minor Issues)
```
✓ Missing JWT ID (jti claim)
✓ Non-standard Algorithms
✓ Header Type Validation
```

## Real-World Testing Workflow

### Phase 1: Token Capture
- Intercept JWT in Burp Repeater
- Copy token to clipboard

### Phase 2: Decode & Analyze
```
1. Go to JWT Auditor
2. Paste token in Decoder tab
3. Click "Decode JWT"
4. Review all 4 sections
5. Go to Analyzer tab
6. Click "Analyze Current Token"
7. Note CRITICAL & HIGH issues
```

### Phase 3: Vulnerability Testing
```
For each CRITICAL finding:
  → Go to Attacks tab
  → Click matching attack button
  → Copy generated token
  → Test in application
  → Document result

Example workflow:
  Found: 'none' algorithm detected
  → Click "None Algorithm Bypass"
  → Copy modified token
  → Send in Burp Repeater
  → Check if application accepts it
```

### Phase 4: Secret Cracking (if applicable)
```
If HMAC algorithm detected:
  1. Go to Bruteforcer tab
  2. Click "Start Bruteforce"
  3. Wait for secret or completion
  4. If found → Use in privilege escalation
```

### Phase 5: Exploitation
```
Once secret found or bypass works:
  1. Go to Attacks tab
  2. Click "Privilege Escalation"
  3. Generate admin token
  4. Test against application
  5. Document successful exploitation
```

### Phase 6: Reporting
```
Document all findings:
  • Vulnerability: [name]
  • Severity: [CRITICAL/HIGH/MEDIUM/LOW]
  • Impact: [what attacker can do]
  • Proof: [generated token accepted]
  • Recommendation: [how to fix]
```

## Attack Examples

### Example 1: None Algorithm Bypass
```
Original Token: eyJhbGciOiJSUzI1NiJ9.{payload}.{signature}
Attack: None Algorithm Bypass
Result: eyJhbGciOiJub25lIn0.{payload}.
Effect: No signature validation, can modify claims
```

### Example 2: Privilege Escalation
```
Original Payload: {"sub":"user123", "role":"user"}
Modified: {"sub":"user123", "role":"admin"}
If accepted: User becomes admin
```

### Example 3: Algorithm Confusion
```
Original: {"alg":"RS256"} signed with private key
Modified: {"alg":"HS256"} signed with public key
If accepted: Attacker can forge tokens
```

### Example 4: User Impersonation
```
Original: {"sub":"user123", ...}
Modified: {"sub":"admin", ...}
If accepted: Attacker is now admin
```

## Features Summary

| Feature | Details | Tab |
|---------|---------|-----|
| **Decode JWT** | Parse 4 components (header, payload, signature, info) | 1 - Decoder |
| **Analyze** | 15+ vulnerability checks with color-coded severity | 2 - Analyzer |
| **Brute Force** | Test 1000+ secrets against HMAC tokens | 3 - Bruteforcer |
| **None Algorithm** | Bypass signature verification | 4 - Attacks |
| **Algorithm Confusion** | Test 14+ algorithm variations | 4 - Attacks |
| **KID Injection** | 47+ injection payloads | 4 - Attacks |
| **JKU Manipulation** | SSRF/key injection attacks | 4 - Attacks |
| **JWK Injection** | Header public key injection | 4 - Attacks |
| **Privilege Escalation** | Role/permission modification | 4 - Attacks |
| **Claim Spoofing** | 5 impersonation scenarios | 4 - Attacks |
| **Manual Editor** | Create custom JWT tokens | 5 - Editor |
| **Help & Guide** | Complete documentation & examples | 6 - Help & Info |

## Technical Details

### Algorithms Supported
- **Symmetric (HMAC)**: HS256, HS384, HS512 (brute forceable)
- **Asymmetric (RSA)**: RS256, RS384, RS512 (needs private key)
- **Elliptic Curve**: ES256, ES384, ES512 (needs private key)
- **None**: Signature bypass (exploitable)

### Token Size
- Typical JWT: 300-500 bytes
- With nested claims: Up to 2 KB

### Performance
- Token parsing: < 1ms
- Security analysis: < 100ms
- Brute force: ~100 secrets/second
- Attack generation: < 10ms

## Legal Disclaimer

**For authorized security testing only.**

This tool is designed for:
- ✅ Authorized penetration testing
- ✅ Security research on your own applications
- ✅ Educational purposes in controlled environments

**NOT for:**
- ❌ Unauthorized access to systems
- ❌ Accessing others' data without permission
- ❌ Illegal activities
- ❌ Bypassing security on systems you don't own

**Always get written authorization before testing.**

## Support & Documentation

### Quick Reference
- **Resizable Components**: Drag dividers in Decoder tab
- **Resizable Columns**: Drag headers in Analyzer tab
- **Copy Tokens**: Auto-copy in attack dialogs
- **Custom Wordlists**: Bruteforcer uses 1000+ secrets

### Common Issues

**Q: Bruteforcer doesn't work**
A: Token must use HMAC (HS256/384/512). RS256/ES256 need private key.

**Q: Attack generates same token**
A: Use Editor tab to manually modify and test specific claims.

**Q: Help tab content not showing**
A: Scroll down in Help & Info tab to see all content.

**Q: Tables not resizable**
A: In Analyzer, drag column headers. In Decoder, drag split pane dividers.

## Version History

- **v2.0** (Latest): Resizable components, detailed attack explanations, Help tab at end
- **v1.0**: Initial release with all 6 tabs and 15+ vulnerability checks
3. **Extended Permissions**: Full read/write/delete access
4. **Time Manipulation**: Sets expiration to year 2286
5. **Service Account**: Impersonates internal service account

### 5. ✏️ JWT Editor & Generator

#### Token Editing
- Decode and edit JWT components
- Modify individual claims
- Update algorithm
- Change header parameters

#### Token Generation
- Create JWT from scratch
- Support for HS256, HS384, HS512, RS256, ES256
- RSA key pair generation
- Custom claim specification

## Usage Guide

### Quick Start

1. **Open JWT Auditor Tab**
   - Burp Suite → Extensions → JWT Auditor tab

2. **Decode a Token**
   - Paste JWT in Decoder tab
   - Click "Decode"
   - View header, payload, signature

3. **Analyze Security**
   - Click "Analyze Current Token" in Analyzer tab
   - Review security findings
   - Findings sorted by severity

4. **Attempt Exploitation**
   - Go to Attacks tab
   - Choose attack type (1-7)
   - Review generated tokens
   - Copy to clipboard for testing

5. **Brute Force Secrets**
   - Select HMAC-based token
   - Go to Bruteforcer tab
   - Click "Start Bruteforce"
   - Monitor progress

### Integration with Burp Proxy

1. **Automatic Detection**: Any JWT in proxied requests appears in JWT tab
2. **Right-Click Context**: Select requests with JWTs → "Send to JWT Auditor"
3. **Message Editor Tab**: JWT tab appears in message editor for all requests with tokens

## Security Findings Explained

### CRITICAL Severity 🔴

| Finding | Description | Fix |
|---------|-------------|-----|
| None Algorithm | Signature verification disabled | Always validate algorithm, reject "none" |
| No Expiration | Token valid indefinitely | Add `exp` claim with reasonable time (15-60 min) |
| Dynamic JKU/X5U | SSRF/key injection risk | Disable dynamic URL loading or whitelist |
| KID Injection | Path traversal/command injection | Validate KID, use whitelist, sanitize input |

### HIGH Severity 🟠

| Finding | Description | Fix |
|---------|-------------|-----|
| HMAC Algorithm | Weak symmetric signing | Use RS256/ES256, implement strong secrets |
| Sensitive Data | PII/secrets in token | Move to server-side storage, use references |
| Long Expiration | Extended risk window | Limit to 15-30 minutes for access tokens |
| Weak Secret Risk | Vulnerable to brute force | Use 256-bit+ secrets, avoid dictionaries |

### MEDIUM Severity 🟡

| Finding | Description | Fix |
|---------|-------------|-----|
| Missing Claims | No iss/aud/jti | Include all recommended claims |
| No JWT ID | Can't track/revoke | Add unique `jti` claim |
| Timestamp Issues | Invalid time values | Validate iat, nbf, exp properly |
| Replay Risk | Can replay old tokens | Implement token tracking, short expiry |

## Installation

### Prerequisites
- Burp Suite Pro (with extension capability)
- Java 8+ (Burp's embedded JVM)

### Installation Steps

1. **Compile Extension**
   ```bash
   javac src/burp/jwt/*.java
   javac src/burp/jwt/*/*.java
   jar cf JWTAuditor.jar src/
   ```

2. **Load into Burp**
   - Burp Suite → Extender → Extensions → Add
   - Select `JWTAuditor.jar`
   - Click "Next" to load

3. **Verify Installation**
   - New "JWT Auditor" tab appears in Burp
   - Output shows "JWT Auditor Extension loaded successfully"

## File Structure

```
jwtauditor/
├── JWTAuditorExtender.java          # Main extension entry point
├── JWTAuditorUI.java                # Main UI with tabs
├── JWTEditorTab.java                # Message editor integration
├── JWTEditorTabFactory.java         # Tab factory
├── JWTContextMenuFactory.java       # Context menu items
├── JWTUtils.java                    # Core JWT utilities
├── JWTHeader.java                   # JWT header representation
├── JWTToken.java                    # JWT token representation
├── SecurityAnalyzer.java            # 15+ security checks
├── SecretBruteforcer.java          # HMAC secret brute forcing
└── AdvancedAttackPlatform.java     # 7 attack modules
```

## Attack Scenarios & Real-World Examples

### Scenario 1: Signature Bypass via None Algorithm
```
Original: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...signature
Modified: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0...
Result: No signature validation, authentication bypassed
```

### Scenario 2: Algorithm Confusion (RS256 → HS256)
```
Original Header: {"alg":"RS256","typ":"JWT"}
Modified Header: {"alg":"HS256","typ":"JWT"}
Attack: Sign with public key (now treated as HMAC secret)
Result: Signature validation passes if server has algorithm confusion
```

### Scenario 3: KID Injection for Database Access
```
Original: {"alg":"RS256","kid":"key1","typ":"JWT"}
Modified: {"alg":"RS256","kid":"1' OR '1'='1","typ":"JWT"}
Attack: Injected into: SELECT * FROM keys WHERE id='1' OR '1'='1'
Result: Returns all keys, enabling signature forgery
```

### Scenario 4: Privilege Escalation
```
Original Claims: {"sub":"user123","role":"user","permissions":["read"]}
Modified Claims: {"sub":"user123","role":"admin","permissions":["read","write","delete","admin"]}
Result: User gains admin access if server trusts JWT claims
```

## Best Practices for JWT Security

### For Developers

1. **Always Validate Algorithm**
   - Whitelist specific algorithms
   - Reject `alg: "none"`
   - Reject unexpected algorithms

2. **Use Strong Secrets/Keys**
   - HMAC: 256+ bit random secrets
   - RSA: 2048+ bit keys
   - Store securely (environment variables, key vaults)

3. **Include Required Claims**
   - `exp`: 15-60 minute expiration
   - `iss`: Issuer identification
   - `aud`: Audience/service identification
   - `jti`: Unique token ID for revocation

4. **Implement Token Revocation**
   - Maintain JWT ID blacklist
   - Implement logout with token invalidation
   - Use Redis/cache for fast lookups

5. **Validate All Claims**
   - Check signature first
   - Validate exp, iat, nbf
   - Validate iss and aud match expected values
   - Check for required custom claims

### For Security Testers

1. **Always Test All Algorithms**
   - Try "none" algorithm
   - Try algorithm confusion attacks
   - Try different HMAC variants

2. **Brute Force HMAC Secrets**
   - Use provided wordlists
   - Add domain-specific terms
   - Check for weak patterns in application

3. **Test Header Parameters**
   - Try KID injection (path traversal, SQL injection, command injection)
   - Try JKU/X5U manipulation
   - Look for SSRF opportunities

4. **Test Claims**
   - Remove exp claim
   - Extend expiration to far future
   - Modify role/permission claims
   - Add new admin claims

5. **Test Signature Verification**
   - Modify payload without changing signature
   - Remove signature entirely
   - Use empty signature with "none" algorithm

## Advanced Configuration

### Custom Wordlist for Bruteforcing
```java
SecretBruteforcer bruteforcer = new SecretBruteforcer(token);
List<String> customSecrets = Arrays.asList(
    "MyCompanySecret123",
    "application-name",
    "project-specific-key"
);
bruteforcer.addCustomSecrets(customSecrets);
```

### Custom Attack Payloads
```java
Map<String, Object> customClaims = new LinkedHashMap<>();
customClaims.put("sub", "admin");
customClaims.put("custom_role", "superuser");
customClaims.put("exp", 9999999999L);

AdvancedAttackPlatform platform = new AdvancedAttackPlatform(token);
JWTToken attacked = platform.generateClaimSpoofing(customClaims);
```

## Troubleshooting

### Extension Won't Load
- Verify Java version compatibility
- Check Burp console for error messages
- Ensure JAR is properly compiled

### Token Not Recognized
- Verify JWT format (header.payload.signature)
- Check for URL encoding issues
- Ensure token is valid Base64URL encoding

### Bruteforcer Not Finding Secret
- Verify token uses HMAC algorithm
- Add secret to custom wordlist
- Check for key encoding issues (UTF-8 vs bytes)

## Limitations

1. **HMAC Brute Forcing Only**: RSA/ECDSA require key/public key, not practical
2. **No JWE Support**: Only JWT (signed), not encrypted
3. **No Automatic Signature Generation**: Manual token modification only
4. **Basic JSON Parsing**: Not full JSON spec compliance
5. **No Algorithm Key Fetching**: JKU/X5U URLs must be manually specified

## Future Enhancements

1. JWE (JSON Web Encryption) support
2. Automatic RSA key pair generation
3. Advanced algorithm-specific attacks
4. Token lifetime calculation and recommendations
5. Integration with custom wordlists from Burp
6. Automated attack generation and testing
7. Token comparison and diff tools
8. Batch JWT analysis

## References

- [JWT Specification (RFC 7519)](https://tools.ietf.org/html/rfc7519)
- [JWT Best Practices (RFC 8725)](https://tools.ietf.org/html/rfc8725)
- [JWT Security Issues (CVE List)](https://cve.mitre.org/)
- [PortSwigger JWT Attacks](https://portswigger.net/web-security/jwt)
- [Wallarm JWT Vulnerabilities](https://wallarm.com/what/jwt)

## Support & Feedback

For issues, feature requests, or feedback:
- Original JWTAuditor: https://github.com/dr34mhacks/jwtauditor
- Burp Extension Documentation: https://portswigger.net/burp/extender

## Legal Disclaimer

This extension is designed for authorized security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. Unauthorized access to computer systems is illegal. Always obtain written permission before conducting security assessments.

---

**Built with ❤️ by security professionals, for security professionals**

Version: 1.0  
Last Updated: January 2026
