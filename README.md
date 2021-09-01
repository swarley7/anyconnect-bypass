# anyconnect-bypass

Dumps the session token from a successful AnyConnect auth attempt, so that you can use OpenConnect (useful when there's really bad Auth requirements, such as MS MFA).

# Basic Usage

On your Windows host open the AnyConnect Client Mobility application, and hit the Gear Icon to get preferences.

Make sure "Block connections to untrusted servers" is *unticked*

Open cmd.exe as Admin and run the following command:

`PATH\TO\anyconnect-bypass.exe -l 127.0.0.1 -p 1234 -s -r vpn.example.com:443`

Then in your AnyConnect Client, attempt to connect to `127.0.0.1:1234`

A security warning should pop up; hit connect anyway (security, amirite?).

Respond to any required authentication requests (including MFA) - Note: for Microsoft MFA this should spawn a popover browser window.

Once auth is complete, the app should exit and return the following:

~~~
Paste the following Session token into OpenConnect: <REDACTED>
E.g.: sudo openconnect --cookie="<REDACTED>" vpn.example.com:443
~~~

On your linux / mac host (or Windows, if you're so inclined), launch OpenConnect with the supplied Cookie value as instructed:

`sudo openconnect --cookie="<REDACTED>" vpn.example.com:443`

# Help

~~~
  -c string
    	Use a config file (set TLS ect) - Commandline params overwrite config file
  -cert string
    	Use a specific certificate file
  -client-cert string
    	Read client certificate from file.
  -client-key string
    	Read client key from file. If only client-cert is given, the key and cert will be read from the same file.
  -d	Debug messages displayed
  -l string
    	Local address to listen on
  -o string
    	Output name for AnyConnect Session token
  -p int
    	Local Port to listen on
  -r string
    	Remote Server address host:port
  -s	Create a TLS Proxy
~~~