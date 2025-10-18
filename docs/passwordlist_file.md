contributors: gurnec
## The Passwordlist ##

If you already have a simple list of whole passwords you'd like to test, and you don't need any of the features described above, you can use the `--passwordlist` command-line option (instead of the `--tokenlist` option as described later in the [Running *btcrecover*](TUTORIAL.md#running-btcrecover) section). The passwordlist is just a standard text file, with one password per line. (It can be either raw text or also compressed with gzip)If your password contains any non-[ASCII](https://en.wikipedia.org/wiki/ASCII) (non-English) characters, you should read the section on [Unicode Support](TUTORIAL.md#unicode-support) before continuing.

If you specify `--passwordlist` without a file, *btcrecover* will prompt you to type in a list of passwords, one per line, in the Command Prompt window. If you already have a text file with the passwords in it, you can use `--passwordlist FILE` instead (replacing `FILE` with the file name).

Be sure not to add any extra spaces, unless those spaces are actually a part of a password.

Each line is used verbatim as a single password when using the `--passwordlist` option (and none of the features from above are applied). You can however use any of the Typos features described below to try different variations of the passwords in the passwordlist.

If you would like to store your command line options alongside the passwordlist file itself, you can add the `--passwordlist-arguments` option when launching *btcrecover*. When this flag is present, *btcrecover* will look at the first line of the passwordlist file; if it begins with `#--`, everything after that sequence is treated as additional command line arguments. The values provided inside the file behave exactly like command line arguments, but the normal command line still takes precedence if you specify the same option in both places. For safety reasons `--passwordlist`, `--tokenlist`, `--performance`, and `--utf8` are not permitted inside the file.
