
#Custom Wildcard Lists
BTCRecover allows you to pass an argument to a standard text file containing a list of items that can be used as an expanding wildcard.

_If you attempt to use a custom wildcard without first having passed an argument to a list file, that wildcard will simply return a single blank string. (So will be ignored)_

If you make use of this feature, it is wise to check that your custom wildcards are being correctly loaded and behave as you expect through use of the --listpass argument.

##Repeating String Wildcards
###Repetition Behaviour
The `%e` and `%f` wildcards are special in that when they appear multiple times in a given candidate password, they will have the same value.

What this means is that they are useful for situations where you may have used some character (or string) which is repeated multiple times throughout a password. 

**Example 1:**

You can see an example of this behaviour with the following command which loads a demo file for the `%e` wildcard

    python btcrecover.py --listpass --passwordlist ./docs/custom-wildcard-lists/demo_passwordlist.txt --wildcard-custom-list-e ./docs/custom-wildcard-lists/strings.txt --has-wildcards
    
**Example 2**

Likewise this works file for full strings, as you can see with a command like this:

    python btcrecover.py --listpass --passwordlist ./docs/custom-wildcard-lists/demo_passwordlist.txt --wildcard-custom-list-e ./docs/custom-wildcard-lists/string.txt --has-wildcards

###Wildcards within Wildcards
These two types of wildcards are also **extra** special in that the strings used for them can also include _other_ expanding wildcards. 

**Example 3**

You can see an example of this behaviour with the following command which loads a demo file for the `%f` wildcard
    
    python btcrecover.py --listpass --passwordlist ./docs/custom-wildcard-lists/demo_passwordlist.txt --wildcard-custom-list-f ./docs/custom-wildcard-lists/wildcard.txt --has-wildcards
    
##Standard String Wildcards
The `%j` and `%k` wildcards behave in a simmilar manner to normal expanding wildcards. 

**Example 4**

You can see an example of this behaviour with the following command which loads a demo file for the `%j` wildcard
    
    python btcrecover.py --listpass --passwordlist ./docs/custom-wildcard-lists/demo_passwordlist.txt --wildcard-custom-list-j ./docs/custom-wildcard-lists/strings.txt --has-wildcards

If you compare the output of example 4 to that of example 2, you can see how these two different types of wildcards are handled.
