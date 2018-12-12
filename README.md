# HSM Signer

This is a web service that reveals an API for signing messages with
a key stored securely in an HSM module.  For testing, SoftHSM may be used.

## Testing with SoftHSM

Initialize a token in a test SoftHSM environment.  This command
will prompt you to set a Security Officer (SO) PIN and a user PIN.
The User PIN will be needed by the application at runtime to log in
to the PKCS11 sessions and carry out operations.  The Application
should *not* need the SO password, but it will be needed to make
changes / updates to the token.

```
softhsm2-util --init-token --slot 0 --label "Test Token 1"
```

## Building and Running

```
# If you need stack: brew install stack on OS X
stack build
stack exec haskell-pkcs-exe
```