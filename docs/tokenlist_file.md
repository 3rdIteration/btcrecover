contributors: gurnec
# The Token File #

*btcrecover* can accept as input a text file which has a list of what are called password “tokens”. A token is simply a portion of a password which you do remember, even if you don't remember where that portion appears in the actual password. It will combine these tokens in different ways to create different whole password guesses to try.

This file, typically named `tokens.txt`, can be created in any basic text editor, such as Notepad on Windows or TextEdit on OS X, and should probably be saved into the same folder as the `btcrecover.py` script (just to keep things simple). Note that if your password contains any non-[ASCII](https://en.wikipedia.org/wiki/ASCII) (non-English) characters, you should read the section on [Unicode Support](#unicode-support) before continuing.

## Basics ##

Let’s say that you remember your password contains 3 parts, you just can’t remember in what order you used them. Here are the contents of a simple `tokens.txt` file:
``` linenums="1"
Cairo
Beetlejuice
Hotel_california
```
When used with these contents, *btcrecover* will try all possible combinations using one or more of these three tokens, e.g. `Hotel_california` (just one token), `BettlejuiceCairo` (two tokens pasted together), etc.

Note that lines which start with a `#` are ignored as comments, but only if the `#` is at the *very beginning* of the line:
``` linenums="1"
# This line is a comment, it's ignored.
# The line at the bottom is not a comment because the
# first character on the line is a space, and not a #
 #a_single_token_starting_with_the_#_symbol
```
## Mutual Exclusion ##

Maybe you’re not sure about how you spelled or capitalized one of those words. Take this token file:
``` linenums="1"
Cairo
Beetlejuice beetlejuice Betelgeuse betelgeuse
Hotel_california
```
Tokens listed on the same line, separated by spaces, are mutually exclusive and will never be tried together in a password guess. *btcrecover* will try `Cairo` and `bettlejuiceCairoHotel_california`, but it will skip over `Betelgeusebetelgeuse`. Had all four Beetlejuice versions been listed out on separate lines, this would have resulted in trying thousands of additional passwords which we know to be incorrect. As is, this token file only needs to try 48 passwords to account for all possible combinations. Had they all been on separate lines, it would have had to try 1,956 different combinations.

In short, when you’re sure that certain tokens or variations of a token have no chance of appearing together in a password, placing them all on the same line can save a lot of time.

## Required Tokens ##

What if you’re certain that `Cairo` appears in the password, but you’re not so sure about the other tokens?
``` linenums="1"
+ Cairo
Beetlejuice beetlejuice Betelgeuse betelgeuse
Hotel_california
```
Placing a `+` (and some space after it) at the beginning of a line tells *btcrecover* to only try passwords that include `Cairo` in them. You can also combine these two last features. Here’s a longer example:
``` linenums="1"
Cairo cairo Katmai katmai
+ Beetlejuice beetlejuice Betelgeuse betelgeuse
Hotel_california hotel_california
```
In this example above, passwords will be constructed by taking at most one token from the first line, exactly one token from the second line (it’s required), and at most one token from the third line. So `Hotel_californiaBetelgeuse` would be tried, but `cairoKatmaiBetelgeuse` would be skipped (`cairo` and `Katmai` are on the same line, so they’re never tried together) and `katmaiHotel_california` is also skipped (because one token from the second line is required in every try).

This file will create a total of just 244 different combinations. Had all ten of those tokens been listed on separate lines, it would have produced 9,864,100 guesses, which could take days longer to test!

## Anchors ##

### Beginning and Ending Anchors ###

Another way to save time is to use “anchors”. You can tell *btcrecover* that certain tokens, if they are present at all, are definitely at the beginning or end of the password:
``` linenums="1"
^Cairo
Beetlejuice beetlejuice Betelgeuse betelgeuse
Hotel_california$
```
In this example above, the `^` symbol is considered special if it appears at the beginning of any token (it’s not actually a part of the password), and the `$` symbol is special if it appears at the end of any token. `Cairo`, if it is tried, is only tried at the beginning of a password, and `Hotel_california`, if it is tried, is only tried at the end. Note that neither is required to be tried in password guesses with the example above. As before, all of these options can be combined:
``` linenums="1"
Cairo
Beetlejuice beetlejuice Betelgeuse betelgeuse
+ ^Hotel_california ^hotel_california
```
In this example above, either `Hotel_california` or `hotel_california` is *required* at the beginning of every password that is tried (and the other tokens are tried normally after that).

### Positional Anchors ###

Tokens with positional anchors may only appear at one specific position in the password -- there are always a specific number of other tokens which precede the anchored one. In the example below you'll notice a number in between the two `^` symbols added to the very beginning to create positionally anchored tokens (with no spaces):
``` linenums="1"
^2^Second_or_bust
^3^Third_or_bust
Cairo
Beetlejuice
Hotel_california
```
As you can guess, `Second_or_bust`, if it is tried, is only tried as the second token in a password, and `Third_or_bust`, if it is tried, is only tried as the third. (Neither token is required because there is no `+` at the beginning these of these lines.)

### Middle Anchors ###

Middle anchors are a bit like positional anchors, only more flexible: the anchored tokens may appear once throughout a specific *range* of positions in the password.

**Note** that placing a middle anchor on a token introduces a special restriction: it *forces* the token into the *middle* of a password. A token with a middle anchor (unlike any of the other anchors described above) will *never* be tried as the first or last token of a password.

You specify a middle anchor by adding a comma and two numbers (between the `^` symbols) at the very beginning of a token (all with no spaces):
``` linenums="1"
^2,3^Second_or_third_(but_never_last)
^2,4^Second_to_fourth_(but_never_last)
Cairo
Beetlejuice
Hotel_california
```
 As mentioned above, neither of those middle-anchored tokens will ever be tried as the last token in a password, so something (one or more of the non-anchored tokens) will appear after the middle-anchored ones in every guess in which they appear. Since tokens with middle anchors never appear at the beginning either, the smallest value you can use for that first number is 2. Finally, when you specify the range, you can leave out one (or even both) of the numbers, like this:
``` linenums="1"
^3,^Third_or_after_(but_never_last)
^,3^Third_or_earlier(but_never_first_or_last)
^,^Anywhere_in_the_middle
Cairo
Beetlejuice
Hotel_california
```
You can't leave out the comma (that's what makes it a middle anchor instead of a positional anchor). Leaving out a number doesn't change the “never at the beginning or the end” rule which always applies to middle anchors. If you do need a token with a middle anchor to also possibly appear at the beginning or end of a password, you can add second copy to the same line with a beginning or end anchor (because at most one token on a line can appear in any guess):
``` linenums="1"
^,^Anywhere_in_the_middle_or_end        Anywhere_in_the_middle_or_end$
^,^Anywhere_in_the_middle_or_beginning ^Anywhere_in_the_middle_or_beginning
```

### Relative Anchors ###

Relative anchors restrict the position of tokens relative to one another. They are only affected by other tokens which also have relative anchors. They look like positional anchors, except they have a single `r` preceding the relative number value:
``` linenums="1"
^r1^Earlier
^r2^Middlish_A
^r2^Middlish_B
^r3^Later
Anywhere
```
In this example above, if two or more relative-anchored tokens appear together in a single password guess, they appear in their specified order. `Earlier Anywhere Later` and `Anywhere Middlish_A Later` would be tried, however `Later Earlier` would not. Note that `Middlish_A` and `Middlish_B` can appear in the same guess, and they can appear with either being first since they have a matching relative value, e.g. `Middlish_B Middlish_A Later` would be tried.

You cannot specify a single token with both a positional and relative anchor at the same time.

## Token Counts ##

There are a number of command-line options that affect the combinations tried. The `--max-tokens` option limits the number of tokens that are added together and tried. With `--max-tokens` set to 2, `Hotel_californiaCairo`, made from two tokens, would be tried from the earlier example, but `Hotel_californiaCairoBeetlejuice` would be skipped because it’s made from three tokens. You can still use *btcrecover* even if you have a large number of tokens, as long as `--max-tokens` is set to something reasonable. If you’d like to re-run *btcrecover* with a larger number of `--max-tokens` if at first it didn’t succeed, you can also specify `--min-tokens` to avoid trying combinations you’ve already tried.

## Expanding Wildcards ##

What if you think one of the tokens has a number in it, but you’re not sure what that number is? For example, if you think that Cairo is definitely followed by a single digit, you could do this:
``` linenums="1"
Cairo0 Cairo1 Cairo2 Cairo3 Cairo4 Cairo5 Cairo6 Cairo7 Cairo8 Cairo9
Beetlejuice
Hotel_california
```
While this definitely works, it’s not very convenient. This next token file has the same effect, but it’s easier to write:
``` linenums="1"
Cairo%d
Beetlejuice
Hotel_california
```
The `%d` is a wildcard which is replaced by all combinations of a single digit. Here are some examples of the different types of wildcards you can use:

 * `%d`    - a single digit
 * `%2d`   - exactly 2 digits
 * `%1,3d` - between 1 and 3 digits (all possible permutations thereof)
 * `%0,2d` - between 0 and 2 digits (in other words, the case where there are no digits is also tried)
 * `%a`    - a single ASCII lowercase letter
 * `%1,3a` - between 1 and 3 lowercase letters
 * `%A`    - a single ASCII uppercase letter
 * `%n`    - a single digit or lowercase letter
 * `%N`    - a single digit or uppercase letter
 * `%ia`   - a “case-insensitive” version of %a: a single lower or uppercase letter
 * `%in`   - a single digit, lower or uppercase letter
 * `%1,2in`- between 1 and 2 characters long of digits, lower or uppercase letters
 * `%[chars]` - exactly 1 of the characters between `[` and `]` (e.g. either a `c`, `h`, `a`, `r`, or `s`) _**Note**: All characters in this wildcard are used as-is, even if that character would normally have its own wildcard if used as a token, like space, $, % or ^_
 * `%1,3[chars]` - between 1 and 3 of the characters between `[` and `]`
 * `%[0-9a-f]` - exactly 1 of these characters: `0123456789abcdef`
 * `%2i[0-9a-f]` - exactly 2 of these characters: `0123456789abcdefABCDEF`
 * `%s`    - a single space
 * `%l`    - a single line feed character
 * `%r`    - a single carriage return character
 * `%R`    - a single line feed or carriage return character
 * `%t`    - a single tab character
 * `%T`    - a single space or tab character
 * `%w`    - a single space, line feed, or carriage return character
 * `%W`    - a single space, line feed, carriage return, or tab character
 * `%y`    - any single ASCII symbol
 * `%Y`    - any single ASCII digit or symbol
 * `%p`    - any single ASCII letter, digit, or symbol
 * `%P`    - any single character from either `%p` or `%W` (pretty much everything)
 * `%q`    - any single ASCII letter, digit, symbol or space. (The characters typically used for BIP39 passphrase for most vendors) 
 * `%c`    - a single character from a custom set specified at the command line with `--custom-wild characters`
 * `%C`    - an uppercased version of `%c` (the same as `%c` if `%c` has no lowercase letters)
 * `%ic`   - a case-insensitive version of `%c`
 * `%%`    - a single `%` (so that `%`’s in your password aren’t confused as wildcards)
 * `%^`    - a single `^` (so it’s not confused with an anchor if it’s at the beginning of a token)
 * `%S`    - a single `$` (yes, that’s `%` and a capital `S` that gets replaced by a dollar sign, sorry if that’s confusing)
 * `%h`    - a single hexidcimal character (0-9, A-F) 
 * `%*`    - a single Base58 character (Bitcoin Base58 Character Set)
 * `%U`    - a single Unicode character (All Unicode characters up to 65,535)
 * `%e`    - Custom String Repeating wildcard, [Read about behaviour and usage](custom_wildcards.md)
 * `%f`    - Custom String Repeating wildcard, [Read about behaviour and usage](custom_wildcards.md)
 * `%j`    - Custom String Standard wildcard, [Read about behaviour and usage](custom_wildcards.md)
 * `%k`    - Custom String Standard wildcard, [Read about behaviour and usage](custom_wildcards.md)

Up until now, most of the features help by reducing the number of passwords that need to be tried by exploiting your knowledge of what’s probably in the password. Wildcards significantly expand the number of passwords that need to be tried, so they’re best used in moderation.

## Backreference Wildcards ##

Backreference wildcards copy one or more characters which appear somewhere earlier in the password. In the simplest case, they're not very useful. For example, in the token `Z%b`, the `%b` simply copies the character which immediately precedes it, resulting in `ZZ`.

Consider the case where the password contains patterns such as `AA`, `BB`, up through `ZZ`, but would never contain `AZ`. You could use `%2A` to generate these patterns, but then you'd end up with `AZ` being tried. `%2A` generates 676 different combinations, but in this example we only want to try 26. Instead you can use two wildcards together: `%A%b`. The `%A` will expand into a single letter (from `A` to `Z`), and *after* this expansion happens, the `%b` will copy that letter, resulting in only the 26 patterns we want.

As with normal wildcards, backreference wildcards may contain a copy length, for example:

 * `Test%d%b`    - `Test00` through `Test99`, but never `Test12`
 * `Test%d%2b`   - `Test000` through `Test999`, but never `Test123`
 * `Test%d%0,3b` - `Test0` to `Test9` (the backreference length is 0), `Test00` to `Test99`, etc., `Test0000` to `Test9999`

In the examples so far, the copying starts with the character immediately to the left of the `%b`, but this can be changed by adding a `;#` just before the `b`, for example:

 * `Test%b`       - `Testt`
 * `Test%;1b`     - starts 1 back, same as above, `Testt`
 * `Test%;2b`     - starts 2 back, `Tests`
 * `Test%;4b`     - starts 4 back, `TestT`
 * `Test%2;4b`    - starts 4 back, with a copy length of 2: `TestTe`
 * `Test%8;4b`    - starts 4 back, with a copy length of 8: `TestTestTest`
 * `Test%0,2;4b`  - starts 4 back, with a copy length from 0 to 2: `Test`, `TestT`, and `TestTe`
 * `%2Atest%2;6b` - patterns such as `ABtestAB` and `XKtestXK` where the two capital letters before and after `test` match each other, but never `ABtestXK` where they don't match

To summarize, wildcards to the left of a `%b` are expanded first, and then the `%b` is replaced by copying one or more characters from the left, and then wildcards towards the right (if any) are examined.

## Contracting Wildcards ##

Instead of adding new characters to a password guess, contracting wildcards remove one or more characters. Here's an example:

    Start%0,2-End

The `%0,2-` contracting wildcard will remove between 0 and 2 adjacent characters from either side, so that each of `StartEnd` (removes 0), `StarEnd` (removes 1 from left), `StaEnd` (removes 2 from left), `Starnd` (removes 1 from left and 1 from right), `Startnd` (removes 1 from right), and `Startd` (removes 2 from right) will be tried. This can be useful when considering copy-paste errors, for example:

    %0,20-A/Long/Password/with/symbols/that/maybe/was/partially/copy/pasted%0,20-

Different versions of this password will be tried removing up to 20 characters from either end.

Here are the three types of contracting wildcards:

 * `%0,5-` - removes between 0 and 5 adjacent characters (total) taken from either side of the wildcard
 * `%0,5<` - removes between 0 and 5 adjacent characters only from the wildcard's left
 * `%0,5>` - removes between 0 and 5 adjacent characters only from the wildcard's right

You may want to note that a contracting wildcard in one token can potentially remove characters from other tokens, but it will never remove or cross over another wildcard. Here's an example to fully illustrate this (feel free to skip to the next section if you're not interested in these specific details):
``` linenums="1"
AAAA%0,10>BBBB
xxxx%dyyyy
```
These two tokens each have eight normal letters. The first token has a contracting wildcard which removes up to 10 characters from its right, and the second token has an expanding wildcard which expands to a single digit.

One of the passwords generated from these tokens is `AAAABBxxxx5yyyy`, which comes from selecting the first token followed by the second token, and then applying the wildcards with the contracting wildcard removing two characters. Another is `AAAAxx5yyyy` which comes from the same tokens, but the contracting wildcard now is removing six characters, two of which are from the second token.

The digit and the `yyyy` will never be removed by the contracting wildcard because other wildcards are never removed or crossed over. Even though the contracting wildcard is set to remove up to 10 characters, `AAAAyyy` will never be produced because the `%d` blocks it.

## Keyboard Walking — Backreference Wildcards, revisited ##

This feature combines traits of both backreference wildcards and typos maps into a single function. If you haven't read about typos maps below (or about backreference wildcards above), you should probably skip this section for now and come back later.

Consider a complex password pattern such as this: `00test11`, `11test22`, etc. up through `88test99`. In other words, the pattern is generated by combining these 5 strings: `#` `#` `test` `#+1` `#+1`. Using simple backreference wildcards, we can almost produce such a pattern with this token: `%d%btest%d%b`. This produces everything from our list, but it also produced a lot more that we don't want, for example `33test55` is produced even though it doesn't match the pattern because 3+1 is not 5.

Instead a way is needed for a backreference wildcard to do more than simply copy a previous character, it must be able to create a *modified copy* of a previous character. It can do this the same way that a typos map replaces characters by using a separate map file to determine the replacement. So to continue this example, a new map file is needed, `nextdigit.txt`:
``` linenums="1"
0 1
1 2
2 3
3 4
4 5
5 6
6 7
7 8
8 9
```
Finally, here's a token that makes use of this map file to generate the pattern we're looking for: `%d%btest%2;nextdigit.txt;6b`. That's pretty complicated, so let's break it down:

 * `%d`   - expands to `0` through `9`
 * `%b`   - copies the previous character, so no we have `00` through `99`
 * `test` - now we have `00test` through `99test`
 * `%2;nextdigit.txt;6b` - a single backreference wildcard which is made up of:
     * `2` - the copy length (the length of the result after expansion)
     * `nextdigit.txt` - the map file used determine how to modify characters
     * `6` - how far to the left of the wildcard to start copying; 6 characters counting leftwards from the end of `00test` is the first `0`

    The result of expanding this wildcard when the token starts off with `00test` is `00test11`. It expands into *two* `1`'s because the copy length is 2, and it expands into modified `1`'s instead of just copying the `0`'s because the file maps a `0` (in its first column) to a `1` (in the second column). Likewise, a `77test` is expanded into `77test88`. `99test` is expanded into `99test99` because the the lookup character, a `9`, isn't present in (the first column of) the map file, and so it's copied unmodified.

Note that when you use a map file inside a backreference wildcard, the file name always has a semicolon (`;`) on either side. These are all valid backreference wildcards (but they're all different because the have different copy lengths and starting positions): `%;file.txt;b`, `%2;file.txt;b`, `%;file.txt;6b`, `%2;file.txt;6b`.

The final example involves something called keyboard walking. Consider a password pattern where a typist starts with any letter, and then chooses the next character by moving their finger using a particular pattern, for example by always going either diagonal up and right, or diagonal down and right, and then repeating until the result is a certain length. A single backreference wildcard that uses a map file can create this pattern.

Here's what the beginning of a map file for this pattern, `pattern.txt`, would look like:
``` linenums="1"
q 2a
a wz
z s
2 w
w 3s
...
```
So if the last letter is a `q`, the next letter in the pattern is either a `2` or an `a` (for going upper-right or lower-right). If the last letter is a `z`, there's only one direction available for the next letter, upper-right to `s`. With this map file, and the following token, all combinations which follow this pattern between 4 and 6 characters long would be tried: `%a%3,5;pattern.txt;b`

## Delimiters, Spaces, and Special Symbols in Passwords ##

By default, *btcrecover* uses one or more whitespaces to separate tokens in the tokenlist file, and to separated to-be-replaced characters from their replacements in the typos-map file. It also ignores any extra whitespace in these files. This makes it difficult to test passwords which include spaces and certain other symbols.

One way around this that only works for the tokenlist file is to use the `%s` wildcard which will be replaced by a single space. Another option that works both for the tokenlist file and a typos-map file is using the `--delimiter` option which allows you to change this behavior. If used, whitespace is no longer ignored, nor is extra whitespace stripped. Instead, the new `--delimiter` string must be used *exactly as specified* to separate tokens or typos-map columns. Any whitespace becomes a part of a token, so you must take care not to add any inadvertent whitespace to these files.

Additionally, *btcrecover* considers the following symbols special under certain specific circumstances in the tokenlist file (and for the `#` symbol, also in the typos-map file). A special symbol is part of the syntax, and not part of a password.

 * `%` - always considered special (except when *inside* a `%[...]`-style wildcard, see the [Wildcards](TUTORIAL.md#expanding-wildcards) section); `%%` in a token will be replaced by `%` during searches
 * `^` - only special if it's the first character of a token; `%^` will be replaced by `^` during searches
 * `$` - only special if it's the last character of a token; `%S` (note the capital `S`) will be replaced by `$` during searches
 * `#` - only special if it's the *very first* character on a line, see the [note about comments here](TUTORIAL.md#basics)
 * `+` - only special if it's the first (not including any spaces) character on a line, immediately followed by a space (or delimiter) and then some tokens (see the [Mutual Exclusion](TUTORIAL.md#mutual-exclusion) section); if you need  a single `+` character as a token, make sure it's not the first token on the line, or it's on a line all by itself
 * `]` - only special when it follows `%[` in a token to mark the end of a `%[...]`-style wildcard. If it appears *immediately after* the `%[`, it is part of the replacement set and the *next* `]` actually ends the wildcard, e.g. the wildcard `%[]x]` contains two replacement characters, `]` and `x`. 

None of this applies to passwordlist files, which always treat spaces and symbols (except for carriage-returns and line-feeds) verbatim, treating them as parts of a password.
