Simple CLI tool for merging Java KeyStore

With java 17+ just run `java Main.java`

Can read:
- macos keychain
- .cer file
- java_home cacerts file

Can write:
- macos launchctl .plist file for replacement of trustStore via JAVA_TOOL_OPTIONS
- java_home cacerts file
