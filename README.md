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
softhsm2-util --init-token --slot 0 --label Test1
# Note the new Slot ID # and also the corresponding
# hex (0xAAAAA) number from the below command
softhsm2-util --show-slots
# Import the test privat key
softhsm2-util --import test/keys/testprivkey.pem --slot [SLOTID] --label Test1 --id [AAAAA]
```

## Building and Running

```
# If you need stack: brew install stack on OS X
stack build
# Run the web server
stack exec server
```

## Resources
* http://www.ocamlpro.com/2018/11/21/an-introduction-to-tezos-rpcs-signing-operations/
 * https://www.ibm.com/developerworks/community/blogs/79c1eec4-00c4-48ef-ae2b-01bd8448dd6c/entry/Rexx_Sample_Generate_Different_Types_of_PKCS_11_Keys?lang=en