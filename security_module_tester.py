#!/usr/bin/env python3
"""
Simple Security Module Test - For debugging DAC issues
Run this standalone without any other processes
"""

from security_module import SecurityModule, PermissionLevel

def test_step(step_num, description):
    """Print test step"""
    print(f"\n{'='*60}")
    print(f"STEP {step_num}: {description}")
    print(f"{'='*60}")

def main():
    print("\n" + "="*60)
    print("SIMPLE SECURITY MODULE TEST")
    print("="*60)
    print("\nThis test runs COMPLETELY STANDALONE")
    print("No other terminals or processes needed!\n")
    
    input("Press Enter to start...")
    
    # Initialize security module
    test_step(1, "Initialize Security Module")
    security = SecurityModule("TestNode")
    print("✓ Security module initialized")
    print(f"  Default users: alice, bob, admin")
    
    # Test authentication
    test_step(2, "Test User Authentication")
    result = security.authenticate_user("alice", "password123")
    print(f"  Authenticate alice: {result.success}")
    if result.success:
        print(f"  ✓ Alice authenticated successfully")
    else:
        print(f"  ✗ Authentication failed: {result.message}")
        return
    
    # Test creating a resource (Alice becomes owner)
    test_step(3, "Create Resource with Alice as Owner")
    print("  Checking permission for /files/alice_document.txt...")
    result = security.check_permission("/files/alice_document.txt", "alice", PermissionLevel.READ)
    print(f"  Result: success={result.success}, authorized={result.authorized}")
    print(f"  Message: {result.message}")
    
    if result.authorized:
        print("  ✓ Alice can access her own file (she's the owner)")
    else:
        print("  ✗ Alice should be able to access (owner)")
        return
    
    # Test Bob cannot access Alice's file
    test_step(4, "Bob Tries to Access Alice's File")
    print("  Bob tries to read /files/alice_document.txt...")
    result = security.check_permission("/files/alice_document.txt", "bob", PermissionLevel.READ)
    print(f"  Result: success={result.success}, authorized={result.authorized}")
    print(f"  Message: {result.message}")
    
    if not result.authorized:
        print("  ✓ Bob correctly denied access (no permission)")
    else:
        print("  ✗ Bob should NOT have access yet")
        return
    
    # Alice grants permission to Bob
    test_step(5, "Alice Grants READ Permission to Bob")
    print("  Alice grants READ permission...")
    result = security.grant_permission(
        "/files/alice_document.txt",
        "bob",
        PermissionLevel.READ.value,
        "alice"
    )
    print(f"  Result: success={result.success}")
    print(f"  Message: {result.message}")
    
    if result.success:
        print("  ✓ Permission granted successfully")
    else:
        print("  ✗ Failed to grant permission")
        return
    
    # Bob tries again
    test_step(6, "Bob Tries Again After Permission Grant")
    print("  Bob tries to read /files/alice_document.txt...")
    result = security.check_permission("/files/alice_document.txt", "bob", PermissionLevel.READ)
    print(f"  Result: success={result.success}, authorized={result.authorized}")
    print(f"  Message: {result.message}")
    
    if result.authorized:
        print("  ✓ Bob can now read the file")
    else:
        print("  ✗ Bob should have READ permission now")
        return
    
    # Bob tries to WRITE (should fail)
    test_step(7, "Bob Tries to WRITE (Should Fail)")
    print("  Bob tries to write to /files/alice_document.txt...")
    result = security.check_permission("/files/alice_document.txt", "bob", PermissionLevel.WRITE)
    print(f"  Result: success={result.success}, authorized={result.authorized}")
    print(f"  Message: {result.message}")
    
    if not result.authorized:
        print("  ✓ Bob correctly denied WRITE access")
    else:
        print("  ✗ Bob should only have READ, not WRITE")
        return
    
    # Test encryption
    test_step(8, "Test XOR Encryption")
    original = b"This is a secret message!"
    print(f"  Original data: {original}")
    
    enc_result = security.encrypt_data(original)
    print(f"  Encryption success: {enc_result.success}")
    print(f"  Encrypted data (first 40 chars): {enc_result.encrypted_data[:40]}")
    
    dec_result = security.decrypt_data(enc_result.encrypted_data)
    print(f"  Decryption success: {dec_result.success}")
    print(f"  Decrypted data: {dec_result.decrypted_data}")
    
    if dec_result.decrypted_data == original:
        print("  ✓ Encryption/Decryption working correctly")
    else:
        print("  ✗ Decryption failed")
        return
    
    # Test authentication token
    test_step(9, "Test Authentication Token")
    token_result = security.issue_auth_token("alice", "/files/secure.txt", "READ")
    print(f"  Token issued: {token_result.success}")
    print(f"  Token (first 20 chars): {token_result.auth_token[:20]}...")
    
    validate_result = security.validate_auth_token(
        token_result.auth_token,
        "/files/secure.txt",
        "READ"
    )
    print(f"  Token validation: {validate_result.success}, authorized={validate_result.authorized}")
    
    if validate_result.authorized:
        print("  ✓ Token authentication working")
    else:
        print("  ✗ Token validation failed")
        return
    
    # Show statistics
    test_step(10, "Security Statistics")
    security.show_stats()
    
    # Final summary
    print("\n" + "="*60)
    print("✅ ALL TESTS PASSED!")
    print("="*60)
    print("\nSecurity Module Features Verified:")
    print("  ✓ User Authentication")
    print("  ✓ Discretionary Access Control (DAC)")
    print("  ✓ Resource Ownership")
    print("  ✓ Permission Granting/Checking")
    print("  ✓ XOR Encryption/Decryption")
    print("  ✓ Authentication Tokens")
    print("\nThe security module is working correctly!")
    print("="*60 + "\n")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        print("\nIf you see an ImportError, make sure security_module.py is in the same directory")