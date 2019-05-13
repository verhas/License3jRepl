# License3jRepl

Read Eval Print Loop application for License3j library to manage
licenses and keys.

This application can be used to create key pairs, create licenses and to
sign licenses. The typical workflow is to create a key pair that will be
used to sign and verify licenses. The private key should be stored in
some secure place, like a `.key` directory in your home directory on
your machine, or on a USB drive stored in a bank vault. It all depends
on your security needs.

The public key, as it is public can be advertised, but most likely you
will embed it into the the code of your application.

# Start the application

To start the application you should issue the command:

```
java -jar License3jrepl-3.1.0-jar-with-dependencies.jar
```

The list of the JAR files following the command line parameter `-cp`
should include the core License3j library, the License3j Repl
application and the Repl framework. The versions in the sample line
above are one of the first versions. It is recommended to use the latest
released versions. The License3j and License3Repl libraries are released
with matching version numbers.

The jar file can be downloaded from github from the URL

https://github.com/verhas/License3jRepl/releases/download/3.1.0/License3jrepl-3.1.0-jar-with-dependencies.jar

The names of the files should include the path to the file using the
operating system native notation. The path can be relative to the
current working directory or can be absolute. In the example above the
JAR files are all in the current working directory.

The list of libraries is separated using `;` on Windows and `:` on Linux
and on other Unix operating system. The last argument
`javax0.license3jrepl.App` is the name of the class that contains the
`public static main()` method that initializes the REPL application and
starts it up.

It is recommended to use the latest released versions. The License3j and
License3Repl libraries are released with matching version numbers.

If the command line is correct and the libraries can be found by the
Java environment then you will see the

```
L3j> $
```

prompt. The first thing you can try is to ask for help.

```
L3j> $ help
Available commands:
alias myalias command
exit
help
feature name:TYPE=value
licenseLoad [format=TEXT*|BINARY|BASE64] fileName
saveLicense [format=TEXT*|BINARY|BASE64] fileName
loadPrivateKey [format=BINARY*|BASE64] keyFile
loadPublicKey [format=BINARY*|BASE64] keyFile
sign [digest=SHA-512]
generateKeys [algorithm=RSA] [size=2048] [format=BINARY*|BASE64] public=xxx private=xxx
verify
newLicense
dumpLicense
dumpPublicKey
! cmd to execute shell commands
. filename to execute the content of the file
Aliases:
ll -> licenseload
lpuk -> loadpublickey
dl -> dumplicense
dpk -> dumppublickey
lprk -> loadprivatekey
No license in memory
No keys in memory.
```

# How to issue commands in the application

You can issue commands in the application interactively typing commands
after the prompt. The format of the different commands are described in
the help text. You can also use the TAB key to auto complete the
commands and the parameters.

## Exiting the program

Just type `exit`. If you get the warning that

```
[WARNING] There is unsaved state in the application. Use 'exit confirm=yes'
```

then there is a license in the memory that was loaded, modified and not
saved yet. If you are sure you want to lose the modifications that you
made you should follow the suggestion of the warning text and use `exit
confirm=yes`. That will force the exit to the operating system.

You can also press Control-C or terminate the Java process. The
application does not keep any file open and thus there is no danger to
render anything unstable. You may, however, loose some modification from
the license you manipulated in the memory just like if you typed `exit
confirm=yes`.

## Operating System Commands

You can execute OS commands if you type `!` at the start of the line.
That way you can see what is in a directory, you can type/cat the
content of a file to the screen wthout leawing the REPL application.