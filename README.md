Simple CLI tool for merging Java KeyStore

With java 17+ just run `java Main.java` - to have interactive CLI, for immediate execution you can appends comma separated list of steps eg. `ak,ass,assrc,jhc,output,jtop`

Can read:
- macos keychain via KeychainStore
- macos keychain from files (`/Library/Keychains/System.keychain` and `/System/Library/Keychains/SystemRootCertificates.keychain`) 
- .cer/.crt file
- java_home cacerts file

Can write:
- macos launchctl .plist file for replacement of trustStore via JAVA_TOOL_OPTIONS
- java_home cacerts file
