# Resource Usage and Security Notes

## Beta Software ##

Although this software is unlikely to harm any wallet files, **you are strongly encouraged to only run it with copies of your wallets**. In particular, this software is distributed **WITHOUT ANY WARRANTY**; please see the accompanying GPLv2 licensing terms for more details.

Because this software is beta software, and also because it interacts with other beta software, it’s entirely possible that it may fail to find a password which it’s been correctly configure by you to find.

## Resource Usage ##

### Memory ###

When *btcrecover* starts, it's first task is to count all the passwords it's about to try, looking for and recording duplicates for future reference (so that no password is tried twice) and also so it can display an ETA. This duplicate checking can take **a lot** of memory, depending on how many passwords need to be counted, but in some circumstances it can also save a lot of time. If *btcrecover* appears to hang after displaying the `Counting passwords ...` message, or if it outright crashes, try running it again with the `--no-dupchecks` option. After this initial counting phase, it doesn't use up much RAM as it searches through passwords.

Although this initial counting phase can be skipped by using the `--no-eta` option, it's not recommended. If you do use `--no-eta`, it's highly recommended that you also use `--no-dupchecks` at the same time.

Before the main search begins *btcrecover* also runs a short benchmark to estimate how quickly passwords or seeds can be checked. This can take a noticeable amount of time for some wallet types, so a message is displayed while it runs. By default the benchmark stops after about 30 seconds, but if you want to shorten or skip this step you can supply `--pre-start-seconds <seconds>` to limit how long the benchmark runs (use `0` to skip it entirely) or `--skip-pre-start`. Skipping the benchmark may reduce the accuracy of the reported ETA.

You may want to always use a single `--no-dupchecks` option when working with MultiBit Classic or Electrum wallets because the duplicate checking can actually decrease CPU efficiency (and always decreases memory efficiency) with these wallets in many cases.

If you specify `--no-dupchecks` more than once, it will disable even more of the duplicate checking logic:

 * 1 time - disables the most comprehensive and also the most memory intensive duplicate checking
 * 2 times - disables duplicate checking that rarely consumes much memory relative to the time it saves, although it may if the tokenlist file has a large number of tokens on relatively few lines with at least one but relatively few identical tokens
 * 3 times - disables duplicate checking which consumes very little memory relative to the duplicates it can potentially find; it's almost never useful to use this level
 * 4 times - disables duplicate checking which consumes no additional memory; it's never useful to use this level (and it's only available for debugging purposes)

### CPU ###

By default, *btcrecover* tries to use as much CPU time as is available and spare. You can use the `--threads` option to decrease the number of worker threads (which defaults to the number of logical processors in your system) if you'd like to decrease CPU usage (but also the guess rate).

With MultiBit or Electrum wallets, *btcrecover* may not be able to efficiently use more than four or five CPU cores, sometimes even less depending on the contents of the tokenlist and the chosen typos. Specifying the `--no-dupchecks` option may help improve CPU usage and therefore the password guess rate in many cases with these two wallet types, and using slightly fewer or slightly greater `--threads` might also help. The only way to find out is to experiment.

*btcrecover* places itself in the lowest CPU priority class to minimize disruption to your PC while searching.

## Security Issues ##

Most Bitcoin wallet software goes to great lengths to protect your wallet password while it's stored unencrypted. *btcrecover* does not. This includes, but is not limited to:

 * you must create the tokenlist file which will probably have lots of sensitive password information in it, and save it to an unencrypted file;
 * no attempt is made to overwrite sensitive password information in RAM during or after running;
 * unless you use the `--no-dupchecks` option, a large amount of sensitive password information is stored in RAM temporarily, is not securely overwritten, and is very likely swapped out to the paging file where it could remain for a long time even after *btcrecover* has exited.

None of these issues are intentionally malicious, they should be considered security bugs. There are no workarounds for them, short of only running *btcrecover* inside a VM on a hard disk drive (not a solid-state drive) and securely deleting the VM once finished, all of which is far beyond the scope of this tutorial...
